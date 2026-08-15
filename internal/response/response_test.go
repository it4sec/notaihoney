package response

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestImmediateAndHEAD(t *testing.T) {
	plan := Plan{Status: 200, Mode: "immediate", Body: []byte("hello")}
	var buf bytes.Buffer
	result := Write(context.Background(), &buf, 1, 1, "GET", plan, 4096)
	if result.Error != nil || !result.Complete {
		t.Fatal(result.Error)
	}
	if !strings.Contains(buf.String(), "Content-Length: 5\r\n") || !strings.HasSuffix(buf.String(), "\r\n\r\nhello") {
		t.Fatalf("unexpected response: %q", buf.String())
	}
	buf.Reset()
	result = Write(context.Background(), &buf, 1, 1, "HEAD", plan, 4096)
	if result.Error != nil || strings.HasSuffix(buf.String(), "hello") {
		t.Fatalf("HEAD emitted body: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "Content-Length: 5\r\n") {
		t.Fatal("HEAD lost representation length")
	}
}

func TestNDJSONFramingNoImplicitNewline(t *testing.T) {
	plan := Plan{Status: 200, Mode: "ndjson", Chunks: []Chunk{{Body: []byte("one")}, {Body: []byte("two\n")}}}
	var h11 bytes.Buffer
	result := Write(context.Background(), &h11, 1, 1, "GET", plan, 4096)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if !strings.Contains(h11.String(), "Transfer-Encoding: chunked\r\n") || !strings.Contains(h11.String(), "3\r\none\r\n") {
		t.Fatalf("bad chunking: %q", h11.String())
	}
	if strings.Contains(h11.String(), "one\n") {
		t.Fatal("serializer appended an implicit newline")
	}
	var h10 bytes.Buffer
	result = Write(context.Background(), &h10, 1, 0, "GET", plan, 4096)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if !strings.Contains(h10.String(), "Content-Length: 7\r\n") || strings.Contains(h10.String(), "Transfer-Encoding") {
		t.Fatalf("bad HTTP/1.0 framing: %q", h10.String())
	}
}

func TestHTTP10ImmediateAndResponseLimit(t *testing.T) {
	plan := Plan{Status: 200, Mode: "immediate", Body: []byte("abc")}
	var buf bytes.Buffer
	result := Write(context.Background(), &buf, 1, 0, "GET", plan, 4096)
	if result.Error != nil || !result.Complete {
		t.Fatal(result.Error)
	}
	if !strings.HasPrefix(buf.String(), "HTTP/1.0 200 OK\r\n") || !strings.Contains(buf.String(), "Content-Length: 3\r\n") {
		t.Fatalf("unexpected HTTP/1.0 response: %q", buf.String())
	}
	buf.Reset()
	result = Write(context.Background(), &buf, 1, 1, "GET", plan, 1)
	if !errors.Is(result.Error, ErrResponseLimit) || buf.Len() != 0 {
		t.Fatalf("response limit must fail before transmission: result=%#v bytes=%d", result, buf.Len())
	}
}

func TestHashCoversSuccessfullyWrittenPlaintext(t *testing.T) {
	plan := Plan{Status: 200, Mode: "immediate", Body: []byte("body")}
	var buf bytes.Buffer
	result := Write(context.Background(), &buf, 1, 1, "GET", plan, 4096)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	sum := sha256.Sum256(buf.Bytes())
	if result.SHA256 != hex.EncodeToString(sum[:]) || result.Bytes != int64(buf.Len()) {
		t.Fatalf("hash/length mismatch: %#v", result)
	}
}
