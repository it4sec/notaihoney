package response

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrResponseLimit = errors.New("response byte limit reached")

type Chunk struct {
	Delay time.Duration
	Body  []byte
}

type Plan struct {
	Status  int
	Headers map[string]string
	Mode    string
	Delay   time.Duration
	Body    []byte
	Chunks  []Chunk
	Close   bool
}

type Result struct {
	Bytes    int64
	SHA256   string
	Complete bool
	Error    error
}

type hashWriter struct {
	w io.Writer
	h hash.Hash
	n int64
}

func (w *hashWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	if n > 0 {
		_, _ = w.h.Write(p[:n])
		w.n += int64(n)
	}
	return n, err
}

func (w *hashWriter) sum() string {
	return hex.EncodeToString(w.h.Sum(nil))
}

func Write(ctx context.Context, dst io.Writer, protoMajor, protoMinor int, method string, plan Plan, maxBytes int64) Result {
	if plan.Mode == "" {
		plan.Mode = "immediate"
	}
	wireSize, err := intendedWireSize(protoMajor, protoMinor, method, plan)
	if err != nil {
		return Result{Error: err}
	}
	if wireSize > maxBytes {
		return Result{Error: fmt.Errorf("%w: %d > %d", ErrResponseLimit, wireSize, maxBytes)}
	}
	if err := wait(ctx, plan.Delay); err != nil {
		return Result{Error: err}
	}

	hw := &hashWriter{w: dst, h: sha256.New()}
	headers, err := responseHeaders(protoMajor, protoMinor, method, plan)
	if err != nil {
		return Result{Error: err}
	}
	if err := writeAll(hw, []byte(statusLine(protoMajor, protoMinor, plan.Status))); err != nil {
		return resultFrom(hw, false, err)
	}
	for _, line := range headers {
		if err := writeAll(hw, []byte(line)); err != nil {
			return resultFrom(hw, false, err)
		}
	}
	if err := writeAll(hw, []byte("\r\n")); err != nil {
		return resultFrom(hw, false, err)
	}
	if strings.EqualFold(method, "HEAD") || plan.Status == http.StatusNoContent || plan.Status == http.StatusNotModified {
		return resultFrom(hw, true, nil)
	}

	switch plan.Mode {
	case "immediate":
		if err := writeAll(hw, plan.Body); err != nil {
			return resultFrom(hw, false, err)
		}
	case "ndjson":
		if protoMajor == 1 && protoMinor == 1 {
			for _, chunk := range plan.Chunks {
				if err := wait(ctx, chunk.Delay); err != nil {
					return resultFrom(hw, false, err)
				}
				prefix := []byte(strconv.FormatInt(int64(len(chunk.Body)), 16) + "\r\n")
				if err := writeAll(hw, prefix); err != nil {
					return resultFrom(hw, false, err)
				}
				if err := writeAll(hw, chunk.Body); err != nil {
					return resultFrom(hw, false, err)
				}
				if err := writeAll(hw, []byte("\r\n")); err != nil {
					return resultFrom(hw, false, err)
				}
			}
			if err := writeAll(hw, []byte("0\r\n\r\n")); err != nil {
				return resultFrom(hw, false, err)
			}
		} else if protoMajor == 1 && protoMinor == 0 {
			for _, chunk := range plan.Chunks {
				if err := wait(ctx, chunk.Delay); err != nil {
					return resultFrom(hw, false, err)
				}
				if err := writeAll(hw, chunk.Body); err != nil {
					return resultFrom(hw, false, err)
				}
			}
		} else {
			return resultFrom(hw, false, fmt.Errorf("unsupported HTTP protocol %d.%d", protoMajor, protoMinor))
		}
	default:
		return resultFrom(hw, false, fmt.Errorf("unsupported response mode %q", plan.Mode))
	}
	return resultFrom(hw, true, nil)
}

func resultFrom(w *hashWriter, complete bool, err error) Result {
	return Result{Bytes: w.n, SHA256: w.sum(), Complete: complete && err == nil, Error: err}
}

func responseHeaders(protoMajor, protoMinor int, method string, plan Plan) ([]string, error) {
	headers := make(map[string]string, len(plan.Headers)+2)
	for key, value := range plan.Headers {
		headers[http.CanonicalHeaderKey(key)] = value
	}
	switch plan.Mode {
	case "", "immediate":
		headers["Content-Length"] = strconv.Itoa(len(plan.Body))
	case "ndjson":
		if protoMajor == 1 && protoMinor == 1 {
			headers["Transfer-Encoding"] = "chunked"
		} else if protoMajor == 1 && protoMinor == 0 {
			total := 0
			for _, chunk := range plan.Chunks {
				total += len(chunk.Body)
			}
			headers["Content-Length"] = strconv.Itoa(total)
		} else {
			return nil, fmt.Errorf("unsupported HTTP protocol %d.%d", protoMajor, protoMinor)
		}
	default:
		return nil, fmt.Errorf("unsupported response mode %q", plan.Mode)
	}
	if plan.Close {
		headers["Connection"] = "close"
	} else if protoMajor == 1 && protoMinor == 0 {
		headers["Connection"] = "keep-alive"
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		lines = append(lines, key+": "+headers[key]+"\r\n")
	}
	return lines, nil
}

func statusLine(protoMajor, protoMinor, status int) string {
	text := http.StatusText(status)
	if text == "" {
		text = "Status"
	}
	return fmt.Sprintf("HTTP/%d.%d %d %s\r\n", protoMajor, protoMinor, status, text)
}

func intendedWireSize(protoMajor, protoMinor int, method string, plan Plan) (int64, error) {
	headers, err := responseHeaders(protoMajor, protoMinor, method, plan)
	if err != nil {
		return 0, err
	}
	total := int64(len(statusLine(protoMajor, protoMinor, plan.Status)) + 2)
	for _, line := range headers {
		total += int64(len(line))
	}
	if strings.EqualFold(method, "HEAD") || plan.Status == http.StatusNoContent || plan.Status == http.StatusNotModified {
		return total, nil
	}
	if plan.Mode == "" || plan.Mode == "immediate" {
		return total + int64(len(plan.Body)), nil
	}
	if plan.Mode != "ndjson" {
		return 0, fmt.Errorf("unsupported response mode %q", plan.Mode)
	}
	if protoMajor == 1 && protoMinor == 0 {
		for _, chunk := range plan.Chunks {
			total += int64(len(chunk.Body))
		}
		return total, nil
	}
	if protoMajor == 1 && protoMinor == 1 {
		for _, chunk := range plan.Chunks {
			total += int64(len(strconv.FormatInt(int64(len(chunk.Body)), 16)) + 2 + len(chunk.Body) + 2)
		}
		return total + 5, nil
	}
	return 0, fmt.Errorf("unsupported HTTP protocol %d.%d", protoMajor, protoMinor)
}

func writeAll(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
