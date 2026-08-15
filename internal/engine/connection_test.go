package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"notaihoney/internal/config"
	"notaihoney/internal/evidence"
)

func connectionTestRuntime(t *testing.T, maxRequests int) (*serverRuntime, *serviceRuntime, string, string) {
	t.Helper()
	root := t.TempDir()
	journal := filepath.Join(root, "journal")
	events := filepath.Join(root, "events")
	if err := os.Mkdir(journal, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(events, 0700); err != nil {
		t.Fatal(err)
	}
	runID, err := evidence.NewID()
	if err != nil {
		t.Fatal(err)
	}
	bwj, err := evidence.NewBWJWriter(journal, runID, 1<<20, 3600)
	if err != nil {
		t.Fatal(err)
	}
	jsonl, err := evidence.NewJSONLWriter(events, runID, 1<<20, 3600, 65536)
	if err != nil {
		t.Fatal(err)
	}
	bodyFirst := "first"
	bodyDefault := "default"
	bodyMissing := "missing"
	cfg := &config.Config{
		Version: 1,
		Sensor: config.SensorConfig{ID: "test"},
		ConfigSHA256: strings.Repeat("a", 64),
		Limits: config.LimitsConfig{
			MaxConnectionsTotal: 4,
			MaxConnectionsPerService: 4,
			MaxRequestsPerConnection: maxRequests,
			MaxConnectionLifetimeSeconds: 10,
			MaxConnectionBytes: 1 << 20,
			MaxHeaderBytes: 32768,
			MaxBodyBytes: 65536,
			MaxResponseBytes: 65536,
			MaxStructuredEventBytes: 65536,
			MaxStructuredHeaders: 32,
			MaxQueryFields: 32,
			TLSHandshakeTimeoutSeconds: 1,
			HeaderTimeoutSeconds: 1,
			BodyTimeoutSeconds: 1,
			WriteTimeoutSeconds: 1,
			IdleTimeoutSeconds: 1,
			MaxStreamSeconds: 2,
			MaxPostFailureCaptureBytes: 4096,
			PostFailureCaptureTimeoutSeconds: 1,
		},
	}
	serviceCfg := &config.Service{
		Enabled: true,
		Listener: &config.ListenerConfig{Protocol: "http"},
		Routes: []config.RouteConfig{{
			Method: "GET",
			Path: "/x",
			Responses: []config.ResponseConfig{
				{Sequence: config.Sequence{Number: 1}, Status: 200, Body: &bodyFirst},
				{Sequence: config.Sequence{Default: true}, Status: 200, Body: &bodyDefault},
			},
		}},
		DefaultResponse: &config.FallbackResponse{Status: 404, Body: &bodyMissing},
	}
	rt := &serverRuntime{
		cfg: cfg,
		runSessionID: runID,
		bwj: bwj,
		jsonl: jsonl,
		globalSlots: make(chan struct{}, 4),
		fatalCh: make(chan error, 1),
		active: make(map[net.Conn]struct{}),
	}
	rt.jsonlHealthy.Store(true)
	service := &serviceRuntime{id: "synthetic", cfg: serviceCfg, slots: make(chan struct{}, 4)}
	t.Cleanup(func() {
		_ = jsonl.Close()
		_ = bwj.Close()
	})
	return rt, service, journal, events
}

func TestConnectionPipeliningSequenceAndRequestRanges(t *testing.T) {
	rt, service, _, eventsDir := connectionTestRuntime(t, 10)
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleConnection(context.Background(), rt, service, server)
		close(done)
	}()
	firstRequest := "GET /x HTTP/1.1\r\nHost: test\r\n\r\n"
	secondRequest := "GET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"
	request := firstRequest + secondRequest
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	responseBytes, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	text := string(responseBytes)
	if strings.Count(text, "200 OK") != 2 || !strings.Contains(text, "first") || !strings.Contains(text, "default") {
		t.Fatalf("unexpected pipelined responses: %q", text)
	}
	exchanges := readExchangeEvents(t, eventsDir)
	if len(exchanges) != 2 {
		t.Fatalf("exchange events=%d", len(exchanges))
	}
	if exchanges[0].RequestStreamStart != 0 || exchanges[0].RequestStreamLength != int64(len(firstRequest)) {
		t.Fatalf("first request range=%d+%d", exchanges[0].RequestStreamStart, exchanges[0].RequestStreamLength)
	}
	if exchanges[1].RequestStreamStart != int64(len(firstRequest)) || exchanges[1].RequestStreamLength != int64(len(secondRequest)) {
		t.Fatalf("second request range=%d+%d", exchanges[1].RequestStreamStart, exchanges[1].RequestStreamLength)
	}
}

func TestMalformedPlaintextIsJournaledBeforeParserFailure(t *testing.T) {
	rt, service, journal, _ := connectionTestRuntime(t, 10)
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleConnection(context.Background(), rt, service, server)
		close(done)
	}()
	malformed := []byte("\x00not-http\r\n\r\n")
	if _, err := client.Write(malformed); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("connection did not terminate")
	}
	if err := rt.bwj.Sync(); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(journal, "*.bwj"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("journal paths: %v %v", paths, err)
	}
	var inbound []byte
	for _, path := range paths {
		result, err := evidence.ReadBWJFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range result.Records {
			if record.Type == evidence.RecordData && record.Direction == evidence.DirectionInbound {
				inbound = append(inbound, record.Payload...)
			}
		}
	}
	if !strings.Contains(string(inbound), string(malformed)) {
		t.Fatalf("malformed plaintext missing from BWJ: %q", inbound)
	}
}

func TestMaxRequestsPerConnectionClosesAfterConfiguredCeiling(t *testing.T) {
	rt, service, _, _ := connectionTestRuntime(t, 1)
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleConnection(context.Background(), rt, service, server)
		close(done)
	}()
	if _, err := client.Write([]byte("GET /x HTTP/1.1\r\nHost: test\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if strings.Count(string(data), "200 OK") != 1 || !strings.Contains(string(data), "Connection: close") {
		t.Fatalf("request ceiling response mismatch: %q", data)
	}
}

func readExchangeEvents(t *testing.T, directory string) []evidence.Event {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var out []evidence.Event
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var event evidence.Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				_ = f.Close()
				t.Fatal(err)
			}
			if event.EventType == "exchange" {
				out = append(out, event)
			}
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		_ = f.Close()
	}
	return out
}

func TestExpect100ContinueIsEngineGeneratedAndJournaled(t *testing.T) {
	rt, service, _, _ := connectionTestRuntime(t, 10)
	bodyOK := "ok"
	service.cfg.Routes = []config.RouteConfig{{
		Method: "POST",
		Path: "/x",
		Responses: []config.ResponseConfig{{Sequence: config.Sequence{Default: true}, Status: 200, Body: &bodyOK}},
	}}
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleConnection(context.Background(), rt, service, server)
		close(done)
	}()
	headers := "POST /x HTTP/1.1\r\nHost: test\r\nContent-Length: 3\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n"
	if _, err := client.Write([]byte(headers)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(client)
	interim, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if interim != "HTTP/1.1 100 Continue\r\n" {
		t.Fatalf("unexpected interim status: %q", interim)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "\r\n" {
		t.Fatalf("unexpected interim terminator %q err=%v", line, err)
	}
	if _, err := client.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	finalBytes, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if !strings.Contains(string(finalBytes), "200 OK") {
		t.Fatalf("missing final response: %q", finalBytes)
	}
}

func TestDeclaredBodyLimitStopsNormalRouting(t *testing.T) {
	rt, service, _, eventsDir := connectionTestRuntime(t, 10)
	rt.cfg.Limits.MaxBodyBytes = 4
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleConnection(context.Background(), rt, service, server)
		close(done)
	}()
	request := "GET /x HTTP/1.1\r\nHost: test\r\nContent-Length: 10\r\n\r\n0123456789"
	writeDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte(request))
		writeDone <- err
	}()
	select {
	case <-writeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("request write stalled")
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("body-limit connection did not terminate")
	}
	if len(readExchangeEvents(t, eventsDir)) != 0 {
		t.Fatal("oversized request must not reach route response exchange")
	}
}

func TestSemanticTrailerBytesAreBoundedSeparately(t *testing.T) {
	headers := http.Header{"X-Trailer": []string{"abcdef"}}
	if got := semanticHeaderBytes(headers); got != int64(len("X-Trailer: abcdef\r\n\r\n")) {
		t.Fatalf("semantic trailer bytes=%d", got)
	}
}

func TestIdleTimeoutClosesConnection(t *testing.T) {
	rt, service, _, eventsDir := connectionTestRuntime(t, 10)
	rt.cfg.Limits.IdleTimeoutSeconds = 1
	rt.cfg.Limits.MaxConnectionLifetimeSeconds = 10
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleConnection(context.Background(), rt, service, server)
		close(done)
	}()
	defer client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("idle timeout did not close connection")
	}
	if reason := lastCloseReason(t, eventsDir); reason != "idle_timeout" {
		t.Fatalf("close reason=%q", reason)
	}
}

func TestAbsoluteConnectionLifetimeOverridesLongerIdleTimeout(t *testing.T) {
	rt, service, _, eventsDir := connectionTestRuntime(t, 10)
	rt.cfg.Limits.IdleTimeoutSeconds = 10
	rt.cfg.Limits.MaxConnectionLifetimeSeconds = 1
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleConnection(context.Background(), rt, service, server)
		close(done)
	}()
	defer client.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("absolute connection lifetime did not close connection")
	}
	if reason := lastCloseReason(t, eventsDir); reason != "connection_lifetime" {
		t.Fatalf("close reason=%q", reason)
	}
}

func TestHeaderAndBodyTimeouts(t *testing.T) {
	t.Run("header", func(t *testing.T) {
		rt, service, _, eventsDir := connectionTestRuntime(t, 10)
		rt.cfg.Limits.HeaderTimeoutSeconds = 1
		rt.cfg.Limits.PostFailureCaptureTimeoutSeconds = 1
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			handleConnection(context.Background(), rt, service, server)
			close(done)
		}()
		if _, err := client.Write([]byte("GET /x HTTP/1.1\r\nHost:")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Fatal("header timeout did not terminate connection")
		}
		_ = client.Close()
		if reason := lastCloseReason(t, eventsDir); reason != "header_timeout" {
			t.Fatalf("close reason=%q", reason)
		}
	})

	t.Run("body", func(t *testing.T) {
		rt, service, _, eventsDir := connectionTestRuntime(t, 10)
		bodyOK := "ok"
		service.cfg.Routes = []config.RouteConfig{{Method: "POST", Path: "/x", Responses: []config.ResponseConfig{{Sequence: config.Sequence{Default: true}, Status: 200, Body: &bodyOK}}}}
		rt.cfg.Limits.BodyTimeoutSeconds = 1
		rt.cfg.Limits.PostFailureCaptureTimeoutSeconds = 1
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			handleConnection(context.Background(), rt, service, server)
			close(done)
		}()
		if _, err := client.Write([]byte("POST /x HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(4 * time.Second):
			t.Fatal("body timeout did not terminate connection")
		}
		_ = client.Close()
		if reason := lastCloseReason(t, eventsDir); reason != "body_timeout" {
			t.Fatalf("close reason=%q", reason)
		}
	})
}

func TestWriteTimeoutAndConnectionByteLimit(t *testing.T) {
	t.Run("write_timeout", func(t *testing.T) {
		rt, service, _, eventsDir := connectionTestRuntime(t, 10)
		rt.cfg.Limits.WriteTimeoutSeconds = 1
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			handleConnection(context.Background(), rt, service, server)
			close(done)
		}()
		if _, err := client.Write([]byte("GET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("write timeout did not terminate stalled response")
		}
		_ = client.Close()
		if reason := lastCloseReason(t, eventsDir); reason != "write_timeout" {
			t.Fatalf("close reason=%q", reason)
		}
	})

	t.Run("connection_bytes", func(t *testing.T) {
		rt, service, _, eventsDir := connectionTestRuntime(t, 10)
		rt.cfg.Limits.MaxConnectionBytes = 32
		server, client := net.Pipe()
		done := make(chan struct{})
		go func() {
			handleConnection(context.Background(), rt, service, server)
			close(done)
		}()
		_, _ = client.Write([]byte("GET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"))
		_ = client.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("connection byte ceiling did not terminate connection")
		}
		if reason := lastCloseReason(t, eventsDir); reason != "connection_bytes" {
			t.Fatalf("close reason=%q", reason)
		}
	})
}

func lastCloseReason(t *testing.T, directory string) string {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(directory, "*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var reason string
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			var event evidence.Event
			if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
				_ = f.Close()
				t.Fatal(err)
			}
			if event.EventType == "connection_close" {
				reason = event.CloseReason
			}
		}
		if err := scanner.Err(); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
		_ = f.Close()
	}
	return reason
}
