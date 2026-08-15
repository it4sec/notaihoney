package engine

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"notaihoney/internal/evidence"
	"notaihoney/internal/response"
)

var (
	errHeaderLimit     = errors.New("header byte limit reached")
	errConnectionLimit = errors.New("connection byte limit reached")
)

type connectionCounters struct {
	mu       sync.Mutex
	bytesIn  int64
	bytesOut int64
	requests int
}

func (c *connectionCounters) snapshot() (int64, int64, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesIn, c.bytesOut, c.requests
}

func (c *connectionCounters) remaining(max int64) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return max - c.bytesIn - c.bytesOut
}

func (c *connectionCounters) addIn(n int64) {
	c.mu.Lock()
	c.bytesIn += n
	c.mu.Unlock()
}

func (c *connectionCounters) addOut(n int64) {
	c.mu.Lock()
	c.bytesOut += n
	c.mu.Unlock()
}

func (c *connectionCounters) addRequest() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests++
	return c.requests
}

type recordingReader struct {
	conn           net.Conn
	bwj            *evidence.BWJWriter
	connectionID   evidence.ID
	counters       *connectionCounters
	maxConnBytes   int64
	lifetimeEnd    time.Time
	fatal          func(error)
	parserFailed   bool
	headerPhase    bool
	headerStarted  bool
	headerBytesRead int64
	headerReadCap  int64
	headerTimeout  time.Duration
}

func (r *recordingReader) beginHeaderPhase(idleTimeout, headerTimeout time.Duration, alreadyBuffered bool) error {
	r.headerPhase = true
	r.headerStarted = alreadyBuffered
	r.headerBytesRead = 0
	r.headerTimeout = headerTimeout
	if alreadyBuffered {
		return r.conn.SetReadDeadline(limitDeadline(time.Now().Add(headerTimeout), r.lifetimeEnd))
	}
	return r.conn.SetReadDeadline(limitDeadline(time.Now().Add(idleTimeout), r.lifetimeEnd))
}

func (r *recordingReader) beginBodyPhase(timeout time.Duration) error {
	r.headerPhase = false
	return r.conn.SetReadDeadline(limitDeadline(time.Now().Add(timeout), r.lifetimeEnd))
}

func (r *recordingReader) beginPostFailure(timeout time.Duration) error {
	r.headerPhase = false
	r.parserFailed = true
	return r.conn.SetReadDeadline(limitDeadline(time.Now().Add(timeout), r.lifetimeEnd))
}

func (r *recordingReader) clearReadDeadline() {
	_ = r.conn.SetReadDeadline(time.Time{})
}

func (r *recordingReader) Read(p []byte) (int, error) {
	remaining := r.counters.remaining(r.maxConnBytes)
	if remaining <= 0 {
		return 0, errConnectionLimit
	}
	limit := int64(len(p))
	if limit > remaining {
		limit = remaining
	}
	if r.headerPhase {
		remainingHeader := r.headerReadCap - r.headerBytesRead
		if remainingHeader <= 0 {
			return 0, errHeaderLimit
		}
		if limit > remainingHeader {
			limit = remainingHeader
		}
	}
	if limit <= 0 {
		return 0, errConnectionLimit
	}
	n, readErr := r.conn.Read(p[:int(limit)])
	if n > 0 {
		if r.headerPhase && !r.headerStarted {
			r.headerStarted = true
			_ = r.conn.SetReadDeadline(limitDeadline(time.Now().Add(r.headerTimeout), r.lifetimeEnd))
		}
		flags := uint8(0)
		if r.parserFailed {
			flags |= evidence.FlagParserFailed
		}
		if err := r.bwj.WriteData(r.connectionID, evidence.ID{}, evidence.DirectionInbound, flags, p[:n]); err != nil {
			r.fatal(err)
			return 0, err
		}
		r.counters.addIn(int64(n))
		if r.headerPhase {
			r.headerBytesRead += int64(n)
		}
	}
	return n, readErr
}

type exchangeWriter struct {
	conn          net.Conn
	bwj           *evidence.BWJWriter
	connectionID  evidence.ID
	requestID     evidence.ID
	counters      *connectionCounters
	maxConnBytes  int64
	writeTimeout  time.Duration
	lifetimeEnd   time.Time
	fatal         func(error)
	streaming     bool
	hasher        hash.Hash
}

func newExchangeWriter(conn net.Conn, bwj *evidence.BWJWriter, connectionID, requestID evidence.ID, counters *connectionCounters, maxConnBytes int64, writeTimeout time.Duration, lifetimeEnd time.Time, fatal func(error)) *exchangeWriter {
	return &exchangeWriter{
		conn: conn,
		bwj: bwj,
		connectionID: connectionID,
		requestID: requestID,
		counters: counters,
		maxConnBytes: maxConnBytes,
		writeTimeout: writeTimeout,
		lifetimeEnd: lifetimeEnd,
		fatal: fatal,
		hasher: sha256.New(),
	}
}

func (w *exchangeWriter) Write(p []byte) (int, error) {
	remaining := w.counters.remaining(w.maxConnBytes)
	if remaining <= 0 {
		return 0, errConnectionLimit
	}
	limited := false
	if int64(len(p)) > remaining {
		p = p[:int(remaining)]
		limited = true
	}
	deadline := limitDeadline(time.Now().Add(w.writeTimeout), w.lifetimeEnd)
	if err := w.conn.SetWriteDeadline(deadline); err != nil {
		return 0, err
	}
	n, writeErr := w.conn.Write(p)
	if n > 0 {
		flags := uint8(0)
		if w.streaming {
			flags |= evidence.FlagStreaming
		}
		if err := w.bwj.WriteData(w.connectionID, w.requestID, evidence.DirectionOutbound, flags, p[:n]); err != nil {
			w.fatal(err)
			w.counters.addOut(int64(n))
			_, _ = w.hasher.Write(p[:n])
			return n, err
		}
		w.counters.addOut(int64(n))
		_, _ = w.hasher.Write(p[:n])
	}
	if writeErr != nil {
		return n, writeErr
	}
	if limited && n == len(p) {
		return n, errConnectionLimit
	}
	if n == 0 && len(p) > 0 {
		return 0, io.ErrShortWrite
	}
	return n, nil
}

func (w *exchangeWriter) Sum() string {
	return hex.EncodeToString(w.hasher.Sum(nil))
}

func (w *exchangeWriter) clearDeadline() { _ = w.conn.SetWriteDeadline(time.Time{}) }

func handleConnection(ctx context.Context, rt *serverRuntime, service *serviceRuntime, raw net.Conn) {
	connectionID, err := evidence.NewID()
	if err != nil {
		rt.fail(fmt.Errorf("INTERNAL_FATAL generate connection id: %w", err))
		_ = raw.Close()
		return
	}
	connectionIDText := evidence.FormatID(connectionID)
	started := time.Now()
	lifetimeEnd := started.Add(time.Duration(rt.cfg.Limits.MaxConnectionLifetimeSeconds) * time.Second)
	counters := &connectionCounters{}
	closeReason := evidence.CloseUnspecified
	closeReasonText := "unspecified"
	transport := raw

	rt.registerConnection(raw)
	defer rt.unregisterConnection(raw)
	defer raw.Close()
	defer func() {
		if err := rt.bwj.WriteConnectionClose(connectionID, closeReason); err != nil {
			rt.fail(err)
		}
		bytesIn, bytesOut, requests := counters.snapshot()
		rt.emit(evidence.Event{
			EventType: "connection_close",
			ServiceID: service.id,
			ConnectionID: connectionIDText,
			CloseReason: closeReasonText,
			BytesIn: bytesIn,
			BytesOut: bytesOut,
			RequestCount: requests,
		})
	}()

	if err := rt.bwj.WriteConnectionOpen(connectionID); err != nil {
		rt.fail(err)
		closeReason = evidence.CloseEvidenceFailure
		closeReasonText = "evidence_failure"
		return
	}
	srcIP, srcPort := splitAddress(raw.RemoteAddr())
	dstIP, dstPort := splitAddress(raw.LocalAddr())
	rt.emit(evidence.Event{
		EventType: "connection_open",
		ServiceID: service.id,
		ConnectionID: connectionIDText,
		SourceIP: srcIP,
		SourcePort: srcPort,
		DestinationIP: dstIP,
		DestinationPort: dstPort,
		ListenerProtocol: service.cfg.Listener.Protocol,
	})

	if service.cfg.Listener.Protocol == "https" {
		handshakeTimeout := time.Duration(rt.cfg.Limits.TLSHandshakeTimeoutSeconds) * time.Second
		if remaining := time.Until(lifetimeEnd); remaining < handshakeTimeout {
			handshakeTimeout = remaining
		}
		if handshakeTimeout <= 0 {
			emitLimit(rt, service.id, connectionID, connectionIDText, evidence.LimitConnectionLifetime, uint64(time.Since(started).Seconds()))
			closeReason = evidence.CloseLimitReached
			closeReasonText = "connection_lifetime"
			return
		}
		tlsConn, elapsed, err := handshakeTLS(ctx, raw, rt.tlsConfig, handshakeTimeout)
		if err != nil {
			code := boundedTLSErrorCode(err)
			rt.emit(evidence.Event{
				EventType: "tls_error",
				ServiceID: service.id,
				ConnectionID: connectionIDText,
				SourceIP: srcIP,
				SourcePort: srcPort,
				DestinationIP: dstIP,
				DestinationPort: dstPort,
				TLSErrorCode: code,
				HandshakeElapsedMS: elapsed.Milliseconds(),
			})
			if !time.Now().Before(lifetimeEnd) {
				emitLimit(rt, service.id, connectionID, connectionIDText, evidence.LimitConnectionLifetime, uint64(time.Since(started).Seconds()))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "connection_lifetime"
			} else {
				closeReason = evidence.CloseTLSError
				closeReasonText = "tls_error"
			}
			return
		}
		transport = tlsConn
	}

	rr := &recordingReader{
		conn: transport,
		bwj: rt.bwj,
		connectionID: connectionID,
		counters: counters,
		maxConnBytes: rt.cfg.Limits.MaxConnectionBytes,
		lifetimeEnd: lifetimeEnd,
		fatal: rt.fail,
		headerReadCap: rt.cfg.Limits.MaxHeaderBytes + 4096,
	}
	br := bufio.NewReaderSize(rr, 4096)
	routeState := NewRouteState()

	for {
		select {
		case <-ctx.Done():
			closeReason = evidence.CloseShutdown
			closeReasonText = "shutdown"
			return
		default:
		}
		if time.Now().After(lifetimeEnd) {
			emitLimit(rt, service.id, connectionID, connectionIDText, evidence.LimitConnectionLifetime, uint64(time.Since(started).Seconds()))
			closeReason = evidence.CloseLimitReached
			closeReasonText = "connection_lifetime"
			return
		}
		requestStartedAt := time.Now()
		requestStart := logicalConsumed(rr, br)
		alreadyBuffered := br.Buffered() > 0
		if err := rr.beginHeaderPhase(time.Duration(rt.cfg.Limits.IdleTimeoutSeconds)*time.Second, time.Duration(rt.cfg.Limits.HeaderTimeoutSeconds)*time.Second, alreadyBuffered); err != nil {
			closeReason = evidence.CloseInternalError
			closeReasonText = "internal_error"
			return
		}
		req, readErr := readRequest(br)
		headerEnd := logicalConsumed(rr, br)
		if readErr != nil {
			if errors.Is(readErr, io.EOF) && !rr.headerStarted && !alreadyBuffered {
				closeReason = evidence.CloseRemote
				closeReasonText = "remote_close"
				return
			}
			if isTimeout(readErr) {
				if !time.Now().Before(lifetimeEnd) {
					emitLimit(rt, service.id, connectionID, connectionIDText, evidence.LimitConnectionLifetime, uint64(time.Since(started).Seconds()))
					closeReason = evidence.CloseLimitReached
					closeReasonText = "connection_lifetime"
				} else if rr.headerStarted || alreadyBuffered {
					emitLimit(rt, service.id, connectionID, connectionIDText, evidence.LimitHeaderTimeout, uint64(headerEnd-requestStart))
					closeReason = evidence.CloseHeaderTimeout
					closeReasonText = "header_timeout"
				} else {
					emitLimit(rt, service.id, connectionID, connectionIDText, evidence.LimitIdleTimeout, 0)
					closeReason = evidence.CloseIdleTimeout
					closeReasonText = "idle_timeout"
				}
				postFailureCapture(rr, rt)
				return
			}
			if errors.Is(readErr, errHeaderLimit) {
				emitLimit(rt, service.id, connectionID, connectionIDText, evidence.LimitHeaderBytes, uint64(headerEnd-requestStart))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "header_bytes"
				postFailureCapture(rr, rt)
				return
			}
			if errors.Is(readErr, errConnectionLimit) {
				emitLimit(rt, service.id, connectionID, connectionIDText, evidence.LimitConnectionBytes, uint64(rt.cfg.Limits.MaxConnectionBytes))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "connection_bytes"
				return
			}
			writeParserError(rt, connectionID, evidence.ParserInvalidHTTP, uint64(headerEnd))
			rt.emit(evidence.Event{EventType: "parser_error", ServiceID: service.id, ConnectionID: connectionIDText, OperationalCode: "invalid_http"})
			closeReason = evidence.CloseParserFailure
			closeReasonText = "parser_failure"
			postFailureCapture(rr, rt)
			return
		}
		if headerEnd-requestStart > rt.cfg.Limits.MaxHeaderBytes {
			emitLimit(rt, service.id, connectionID, connectionIDText, evidence.LimitHeaderBytes, uint64(headerEnd-requestStart))
			closeReason = evidence.CloseLimitReached
			closeReasonText = "header_bytes"
			postFailureCapture(rr, rt)
			return
		}
		if service.cfg.Listener.Protocol == "https" && !supportedHTTPSHTTP(req) {
			writeParserError(rt, connectionID, evidence.ParserUnsupportedHTTPVersion, uint64(headerEnd))
			rt.emit(evidence.Event{EventType: "parser_error", ServiceID: service.id, ConnectionID: connectionIDText, OperationalCode: "https_requires_http_1_1"})
			closeReason = evidence.CloseParserFailure
			closeReasonText = "unsupported_http_version"
			postFailureCapture(rr, rt)
			return
		}
		if service.cfg.Listener.Protocol == "http" && !supportedPlainHTTP(req) {
			writeParserError(rt, connectionID, evidence.ParserUnsupportedHTTPVersion, uint64(headerEnd))
			rt.emit(evidence.Event{EventType: "parser_error", ServiceID: service.id, ConnectionID: connectionIDText, OperationalCode: "unsupported_http_version"})
			closeReason = evidence.CloseParserFailure
			closeReasonText = "unsupported_http_version"
			postFailureCapture(rr, rt)
			return
		}

		continueExpected, unsupportedExpectation := expectMode(req)
		if unsupportedExpectation {
			writeParserError(rt, connectionID, evidence.ParserUnsupportedExpectation, uint64(headerEnd))
			rt.emit(evidence.Event{EventType: "parser_error", ServiceID: service.id, ConnectionID: connectionIDText, OperationalCode: "unsupported_expectation"})
			closeReason = evidence.CloseParserFailure
			closeReasonText = "unsupported_expectation"
			postFailureCapture(rr, rt)
			return
		}

		requestID, err := evidence.NewID()
		if err != nil {
			rt.fail(fmt.Errorf("INTERNAL_FATAL generate request id: %w", err))
			closeReason = evidence.CloseInternalError
			closeReasonText = "internal_error"
			return
		}
		requestIDText := evidence.FormatID(requestID)
		responseStart := currentBytesOut(counters)
		xw := newExchangeWriter(transport, rt.bwj, connectionID, requestID, counters, rt.cfg.Limits.MaxConnectionBytes, time.Duration(rt.cfg.Limits.WriteTimeoutSeconds)*time.Second, lifetimeEnd, rt.fail)

		if req.ContentLength > rt.cfg.Limits.MaxBodyBytes {
			emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitBodyBytes, uint64(req.ContentLength))
			closeReason = evidence.CloseLimitReached
			closeReasonText = "body_bytes"
			postFailureCapture(rr, rt)
			return
		}
		if continueExpected && requestMayHaveBody(req) {
			interim := interimContinueBytes()
			if int64(len(interim)) > rt.cfg.Limits.MaxResponseBytes {
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitResponseBytes, uint64(len(interim)))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "response_bytes"
				postFailureCapture(rr, rt)
				return
			}
			if _, err := xw.Write(interim); err != nil {
				xw.clearDeadline()
				closeReason = reasonForWriteError(err)
				closeReasonText = writeErrorCode(err)
				return
			}
		}
		if err := rr.beginBodyPhase(time.Duration(rt.cfg.Limits.BodyTimeoutSeconds) * time.Second); err != nil {
			closeReason = evidence.CloseInternalError
			closeReasonText = "internal_error"
			return
		}
		bodyRead, bodyErr := consumeBody(req, rt.cfg.Limits.MaxBodyBytes)
		requestEnd := logicalConsumed(rr, br)
		rr.clearReadDeadline()
		if bodyErr != nil {
			if isTimeout(bodyErr) && !time.Now().Before(lifetimeEnd) {
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitConnectionLifetime, uint64(time.Since(started).Seconds()))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "connection_lifetime"
			} else if isTimeout(bodyErr) {
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitBodyTimeout, uint64(bodyRead))
				closeReason = evidence.CloseBodyTimeout
				closeReasonText = "body_timeout"
			} else if errors.Is(bodyErr, errBodyLimit) {
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitBodyBytes, uint64(bodyRead))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "body_bytes"
			} else if errors.Is(bodyErr, errConnectionLimit) {
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitConnectionBytes, uint64(rt.cfg.Limits.MaxConnectionBytes))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "connection_bytes"
			} else {
				writeParserError(rt, connectionID, evidence.ParserInvalidHTTP, uint64(requestEnd))
				rt.emit(evidence.Event{EventType: "parser_error", ServiceID: service.id, ConnectionID: connectionIDText, RequestID: requestIDText, OperationalCode: "body_parse_error"})
				closeReason = evidence.CloseParserFailure
				closeReasonText = "body_parse_error"
			}
			postFailureCapture(rr, rt)
			return
		}
		if trailerBytes := semanticHeaderBytes(req.Trailer); trailerBytes > rt.cfg.Limits.MaxHeaderBytes {
			emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitHeaderBytes, uint64(trailerBytes))
			closeReason = evidence.CloseLimitReached
			closeReasonText = "trailer_bytes"
			postFailureCapture(rr, rt)
			return
		}
		requestNumber := counters.addRequest()
		closeAfter := req.Close || requestNumber >= rt.cfg.Limits.MaxRequestsPerConnection
		if requestNumber >= rt.cfg.Limits.MaxRequestsPerConnection {
			emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitRequestsPerConnection, uint64(requestNumber))
		}
		if time.Now().After(lifetimeEnd) {
			emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitConnectionLifetime, uint64(time.Since(started).Seconds()))
			closeReason = evidence.CloseLimitReached
			closeReasonText = "connection_lifetime"
			return
		}

		rawPath := rawPathFromTarget(req.RequestURI)
		selection := SelectResponse(service.cfg, req.Method, rawPath, routeState, closeAfter)
		if strings.EqualFold(req.Method, "CONNECT") && selection.Plan.Status >= 200 && selection.Plan.Status < 300 {
			writeParserError(rt, connectionID, evidence.ParserProhibitedConnect, uint64(requestEnd))
			rt.emit(evidence.Event{EventType: "parser_error", ServiceID: service.id, ConnectionID: connectionIDText, RequestID: requestIDText, OperationalCode: "connect_tunnel_prohibited"})
			closeReason = evidence.CloseParserFailure
			closeReasonText = "connect_tunnel_prohibited"
			return
		}
		xw.streaming = selection.Plan.Mode == "ndjson"
		streamDeadline := time.Now().Add(time.Duration(rt.cfg.Limits.MaxStreamSeconds) * time.Second)
		lifetimeBoundsResponse := !streamDeadline.Before(lifetimeEnd)
		streamCtx, cancelStream := context.WithDeadline(ctx, limitDeadline(streamDeadline, lifetimeEnd))
		responseBudget := rt.cfg.Limits.MaxResponseBytes - (currentBytesOut(counters) - responseStart)
		if responseBudget < 0 {
			responseBudget = 0
		}
		result := response.Write(streamCtx, xw, req.ProtoMajor, req.ProtoMinor, req.Method, selection.Plan, responseBudget)
		streamErr := streamCtx.Err()
		if result.Complete {
			streamErr = nil
		}
		cancelStream()
		xw.clearDeadline()
		responseEnd := currentBytesOut(counters)

		headers := req.Header.Clone()
		for name, values := range req.Trailer {
			for _, value := range values {
				headers.Add(name, value)
			}
		}
		if req.Host != "" {
			headers.Set("Host", req.Host)
		}
		safeHeaders, headerTruncated := evidence.SanitizeHeaders(headers, rt.cfg.Limits.MaxStructuredHeaders)
		queryFields, queryTruncated := evidence.QueryMetadataFromURL(req.URL, rt.cfg.Limits.MaxQueryFields)
		sanitizedTarget, targetTruncated := evidence.SanitizeRequestTarget(rawPath, req.URL, rt.cfg.Limits.MaxQueryFields)
		var declared *int64
		if req.ContentLength >= 0 {
			v := req.ContentLength
			declared = &v
		}
		writeCode := ""
		if streamErr != nil {
			if errors.Is(streamErr, context.DeadlineExceeded) && lifetimeBoundsResponse {
				writeCode = "connection_lifetime"
			} else if errors.Is(streamErr, context.DeadlineExceeded) {
				writeCode = "stream_timeout"
			} else if errors.Is(streamErr, context.Canceled) {
				writeCode = "shutdown"
			}
		} else if result.Error != nil {
			writeCode = writeErrorCode(result.Error)
		}
		rt.emit(evidence.Event{
			EventType: "exchange",
			ServiceID: service.id,
			ConnectionID: connectionIDText,
			RequestID: requestIDText,
			TimestampStartNS: requestStartedAt.UnixNano(),
			TimestampEndNS: time.Now().UnixNano(),
			HTTPVersion: requestProtocol(req),
			Method: req.Method,
			RequestTargetSanitized: sanitizedTarget,
			RawPath: rawPath,
			QueryFields: queryFields,
			SanitizedHeaders: safeHeaders,
			ContentType: req.Header.Get("Content-Type"),
			DeclaredContentLength: declared,
			MatchedRoute: selection.MatchedRoute,
			Classification: selection.Classification,
			ResponseSource: selection.Source,
			ResponseSequence: selection.Sequence,
			ResponseStatus: selection.Plan.Status,
			RequestBytes: requestEnd - requestStart,
			RequestStreamStart: requestStart,
			RequestStreamLength: requestEnd - requestStart,
			RequestComplete: true,
			ResponseBytes: responseEnd - responseStart,
			ResponseStreamStart: responseStart,
			ResponseStreamLength: responseEnd - responseStart,
			ResponseSHA256: xw.Sum(),
			ResponseComplete: result.Complete && streamErr == nil,
			WriteError: writeCode,
			MetadataTruncated: headerTruncated || queryTruncated || targetTruncated,
		})

		if result.Error != nil || streamErr != nil {
			switch {
			case errors.Is(result.Error, response.ErrResponseLimit):
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitResponseBytes, uint64(rt.cfg.Limits.MaxResponseBytes))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "response_bytes"
			case errors.Is(streamErr, context.DeadlineExceeded) && lifetimeBoundsResponse:
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitConnectionLifetime, uint64(time.Since(started).Seconds()))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "connection_lifetime"
			case errors.Is(streamErr, context.DeadlineExceeded):
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitStreamLifetime, uint64(rt.cfg.Limits.MaxStreamSeconds))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "stream_timeout"
			case errors.Is(streamErr, context.Canceled):
				closeReason = evidence.CloseShutdown
				closeReasonText = "shutdown"
			case isTimeout(result.Error) && !time.Now().Before(lifetimeEnd):
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitConnectionLifetime, uint64(time.Since(started).Seconds()))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "connection_lifetime"
			case isTimeout(result.Error):
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitWriteTimeout, uint64(rt.cfg.Limits.WriteTimeoutSeconds))
				closeReason = evidence.CloseWriteTimeout
				closeReasonText = "write_timeout"
			case errors.Is(result.Error, errConnectionLimit):
				emitLimitWithRequest(rt, service.id, connectionID, connectionIDText, requestIDText, evidence.LimitConnectionBytes, uint64(rt.cfg.Limits.MaxConnectionBytes))
				closeReason = evidence.CloseLimitReached
				closeReasonText = "connection_bytes"
			default:
				closeReason = reasonForWriteError(result.Error)
				closeReasonText = writeErrorCode(result.Error)
			}
			return
		}
		if closeAfter {
			if requestNumber >= rt.cfg.Limits.MaxRequestsPerConnection {
				closeReason = evidence.CloseLimitReached
				closeReasonText = "max_requests"
			} else {
				closeReason = evidence.CloseNormal
				closeReasonText = "connection_close"
			}
			return
		}
	}
}

var errBodyLimit = errors.New("body byte limit reached")

func consumeBody(req *http.Request, maxBytes int64) (int64, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return 0, nil
	}
	limited := io.LimitReader(req.Body, maxBytes+1)
	buffer := make([]byte, 32*1024)
	n, err := io.CopyBuffer(io.Discard, limited, buffer)
	if err != nil {
		return n, err
	}
	if n > maxBytes {
		return n, errBodyLimit
	}
	if err := req.Body.Close(); err != nil {
		return n, err
	}
	return n, nil
}

func requestMayHaveBody(req *http.Request) bool {
	return req.ContentLength != 0 || len(req.TransferEncoding) > 0
}

func semanticHeaderBytes(headers http.Header) int64 {
	if len(headers) == 0 {
		return 0
	}
	var total int64 = 2 // terminating CRLF
	for name, values := range headers {
		if len(values) == 0 {
			total += int64(len(name) + 4)
			continue
		}
		for _, value := range values {
			total += int64(len(name) + 2 + len(value) + 2)
		}
	}
	return total
}

func logicalConsumed(rr *recordingReader, br *bufio.Reader) int64 {
	bytesIn, _, _ := rr.counters.snapshot()
	return bytesIn - int64(br.Buffered())
}

func currentBytesOut(c *connectionCounters) int64 {
	_, out, _ := c.snapshot()
	return out
}

func postFailureCapture(rr *recordingReader, rt *serverRuntime) {
	if err := rr.beginPostFailure(time.Duration(rt.cfg.Limits.PostFailureCaptureTimeoutSeconds) * time.Second); err != nil {
		return
	}
	defer rr.clearReadDeadline()
	remaining := rt.cfg.Limits.MaxPostFailureCaptureBytes
	buf := make([]byte, 32*1024)
	for remaining > 0 {
		next := int64(len(buf))
		if next > remaining {
			next = remaining
		}
		n, err := rr.Read(buf[:int(next)])
		if n > 0 {
			remaining -= int64(n)
		}
		if err != nil {
			return
		}
	}
	if err := rt.bwj.WriteLimit(rr.connectionID, evidence.LimitPostFailureCaptureBytes, uint64(rt.cfg.Limits.MaxPostFailureCaptureBytes)); err != nil {
		rt.fail(err)
	}
}

func emitLimit(rt *serverRuntime, serviceID string, connectionID evidence.ID, connectionIDText string, code evidence.LimitCode, observed uint64) {
	if err := rt.bwj.WriteLimit(connectionID, code, observed); err != nil {
		rt.fail(err)
	}
	rt.emit(evidence.Event{EventType: "limit_reached", ServiceID: serviceID, ConnectionID: connectionIDText, OperationalCode: limitCodeText(code)})
}

func emitLimitWithRequest(rt *serverRuntime, serviceID string, connectionID evidence.ID, connectionIDText, requestID string, code evidence.LimitCode, observed uint64) {
	if err := rt.bwj.WriteLimit(connectionID, code, observed); err != nil {
		rt.fail(err)
	}
	rt.emit(evidence.Event{EventType: "limit_reached", ServiceID: serviceID, ConnectionID: connectionIDText, RequestID: requestID, OperationalCode: limitCodeText(code)})
}

func limitCodeText(code evidence.LimitCode) string {
	switch code {
	case evidence.LimitHeaderBytes:
		return "max_header_bytes"
	case evidence.LimitBodyBytes:
		return "max_body_bytes"
	case evidence.LimitRequestsPerConnection:
		return "max_requests_per_connection"
	case evidence.LimitConnectionLifetime:
		return "max_connection_lifetime"
	case evidence.LimitConnectionBytes:
		return "max_connection_bytes"
	case evidence.LimitResponseBytes:
		return "max_response_bytes"
	case evidence.LimitStreamLifetime:
		return "max_stream_seconds"
	case evidence.LimitPostFailureCaptureBytes:
		return "max_post_failure_capture_bytes"
	case evidence.LimitHeaderTimeout:
		return "header_timeout"
	case evidence.LimitBodyTimeout:
		return "body_timeout"
	case evidence.LimitIdleTimeout:
		return "idle_timeout"
	case evidence.LimitWriteTimeout:
		return "write_timeout"
	default:
		return "limit_reached"
	}
}

func writeParserError(rt *serverRuntime, connectionID evidence.ID, code evidence.ParserCode, position uint64) {
	if err := rt.bwj.WriteParserError(connectionID, code, position); err != nil {
		rt.fail(err)
	}
}

func reasonForWriteError(err error) evidence.CloseReason {
	if isTimeout(err) {
		return evidence.CloseWriteTimeout
	}
	if errors.Is(err, errConnectionLimit) || errors.Is(err, response.ErrResponseLimit) {
		return evidence.CloseLimitReached
	}
	return evidence.CloseInternalError
}

func writeErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if isTimeout(err) {
		return "write_timeout"
	}
	if errors.Is(err, errConnectionLimit) {
		return "connection_bytes"
	}
	if errors.Is(err, response.ErrResponseLimit) {
		return "response_bytes"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "stream_timeout"
	}
	return "write_failed"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func limitDeadline(candidate, lifetime time.Time) time.Time {
	if lifetime.IsZero() || candidate.Before(lifetime) {
		return candidate
	}
	return lifetime
}

func splitAddress(addr net.Addr) (string, int) {
	if addr == nil {
		return "", 0
	}
	host, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0
	}
	var p int
	_, _ = fmt.Sscanf(port, "%d", &p)
	return host, p
}

func boundedErrorText(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	text = strings.ReplaceAll(text, "\n", " ")
	if len(text) > 256 {
		text = text[:256]
	}
	return text
}
