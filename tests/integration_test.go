package tests

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"notaihoney/internal/capture"
	"notaihoney/internal/config"
)

func integrationBinary(t *testing.T) string {
	t.Helper()
	binary := os.Getenv("NOTAIHONEY_BINARY")
	if binary == "" {
		t.Skip("set NOTAIHONEY_BINARY to a prebuilt notaihoney executable")
	}
	return binary
}

func repositoryConfig(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "config", "honeypot.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCheckListenerExportCrossProcess(t *testing.T) {
	binary := integrationBinary(t)
	cmd := exec.Command(binary, "check", "--config", repositoryConfig(t), "--emit-listeners=json")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var exported struct {
		ConfigSHA256 string `json:"config_sha256"`
		Listeners    []struct {
			ServiceID string `json:"service_id"`
			Address   string `json:"address"`
			Port      int    `json:"port"`
			Protocol  string `json:"protocol"`
		} `json:"listeners"`
	}
	if err := json.Unmarshal(out, &exported); err != nil {
		t.Fatal(err)
	}
	if exported.ConfigSHA256 == "" || len(exported.Listeners) == 0 {
		t.Fatalf("incomplete export: %s", out)
	}
}

func TestPrivilegedCaptureServeLifecycle(t *testing.T) {
	if os.Getenv("NOTAIHONEY_PRIVILEGED_INTEGRATION") != "1" {
		t.Skip("requires dumpcap privileges and write access to /run/notaihoney")
	}
	binary := integrationBinary(t)
	port := freePort(t)
	root := t.TempDir()
	for _, name := range []string{"pcap", "journal", "events", "index"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	cfg := filepath.Join(root, "honeypot.yaml")
	text := integrationConfig(root, port, 1048576, 1048576)
	if err := os.WriteFile(cfg, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}

	captureCmd := exec.Command(binary, "capture", "--config", cfg)
	if err := captureCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if captureCmd.Process != nil {
			_ = captureCmd.Process.Kill()
		}
	}()
	waitUnixSocket(t, "/run/notaihoney/capture.sock", 5*time.Second)

	serveCmd := exec.Command(binary, "serve", "--config", cfg)
	if err := serveCmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if serveCmd.Process != nil {
			_ = serveCmd.Process.Kill()
		}
	}()
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)

	for _, request := range []string{
		"GET /x HTTP/1.0\r\n\r\n",
		"GET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n",
	} {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = conn.Write([]byte(request))
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_ = conn.Close()
		if n == 0 || !strings.Contains(string(buf[:n]), "200 OK") {
			t.Fatalf("unexpected response: %q", buf[:n])
		}
	}

	// Sequential pipelining on one TCP connection.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET /x HTTP/1.1\r\nHost: test\r\n\r\nGET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	data := make([]byte, 4096)
	n, _ := conn.Read(data)
	_ = conn.Close()
	if n == 0 {
		t.Fatal("no pipelined response")
	}

	// Capture loss is fatal to serve: killing capture closes the health lease.
	_ = captureCmd.Process.Kill()
	captureDone := make(chan error, 1)
	go func() { captureDone <- captureCmd.Wait() }()
	select {
	case <-captureDone:
	case <-time.After(5 * time.Second):
		t.Fatal("capture did not exit")
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- serveCmd.Wait() }()
	select {
	case err := <-serveDone:
		if err == nil {
			t.Fatal("serve must exit non-zero after capture loss")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not terminate after capture loss")
	}
}

func TestServeDoesNotBindWithoutCaptureLease(t *testing.T) {
	requirePrivilegedIntegration(t)
	binary := integrationBinary(t)
	_ = os.Remove(capture.DefaultHealthSocket)
	root, cfgPath, port := writeIntegrationConfig(t, false)
	_ = root

	cmd := exec.Command(binary, "serve", "--config", cfgPath)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "CAPTURE_NOT_READY") {
		t.Fatalf("serve must fail before bind without capture: err=%v output=%s", err, out)
	}
	conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		t.Fatal("public listener bound without capture lease")
	}
}

func TestServeRejectsCaptureConfigMismatchBeforeBind(t *testing.T) {
	requirePrivilegedIntegration(t)
	binary := integrationBinary(t)
	_, cfgPath, port := writeIntegrationConfig(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	health, err := capture.StartHealthServer(ctx, capture.DefaultHealthSocket, strings.Repeat("0", 64), "test-mismatch")
	if err != nil {
		t.Fatal(err)
	}
	defer health.Close()

	cmd := exec.Command(binary, "serve", "--config", cfgPath)
	out, runErr := cmd.CombinedOutput()
	if runErr == nil || !strings.Contains(string(out), "CAPTURE_CONFIG_MISMATCH") {
		t.Fatalf("expected config mismatch: err=%v output=%s", runErr, out)
	}
	conn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 100*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		t.Fatal("public listener bound with mismatched capture configuration")
	}
}

func TestServePerformanceAndSQLiteIndependenceWithHealthLease(t *testing.T) {
	requirePrivilegedIntegration(t)
	binary := integrationBinary(t)
	root, cfgPath, port := writeIntegrationConfig(t, false)
	health := startMatchingHealth(t, cfgPath)
	defer health.Close()
	serve := startServe(t, binary, cfgPath, port)
	defer stopProcess(serve)

	const requests = 20
	started := time.Now()
	for i := 0; i < requests; i++ {
		response := plainRequest(t, port, "GET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
		if !strings.Contains(response, "200 OK") {
			t.Fatalf("unexpected response: %q", response)
		}
	}
	elapsed := time.Since(started).Seconds()
	if elapsed <= 0 || float64(requests)/elapsed < 5.0 {
		t.Fatalf("throughput below 5 requests/second: requests=%d elapsed=%s", requests, time.Since(started))
	}
	if _, err := os.Stat(filepath.Join(root, "index", "honeypot.db")); !os.IsNotExist(err) {
		t.Fatalf("serve must not create SQLite index: %v", err)
	}
}

func TestHTTPSProtocolPolicyCrossProcess(t *testing.T) {
	requirePrivilegedIntegration(t)
	binary := integrationBinary(t)
	root, cfgPath, port := writeIntegrationConfig(t, true)
	writeTestCertificate(t, filepath.Join(root, "tls"))
	health := startMatchingHealth(t, cfgPath)
	defer health.Close()
	serve := startServe(t, binary, cfgPath, port)
	defer stopProcess(serve)

	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         version,
			MaxVersion:         version,
			NextProtos:         []string{"h2", "http/1.1"},
		})
		if err != nil {
			t.Fatalf("TLS %x handshake failed: %v", version, err)
		}
		if conn.ConnectionState().NegotiatedProtocol == "h2" {
			_ = conn.Close()
			t.Fatal("HTTP/2 must not be negotiated")
		}
		_, _ = conn.Write([]byte("GET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"))
		data, _ := io.ReadAll(conn)
		_ = conn.Close()
		if !strings.Contains(string(data), "200 OK") {
			t.Fatalf("HTTPS HTTP/1.1 response missing for TLS %x: %q", version, data)
		}
	}

	legacy, legacyErr := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS11,
		MaxVersion:         tls.VersionTLS11,
	})
	if legacyErr == nil {
		_ = legacy.Close()
		t.Fatal("TLS 1.1 must fail")
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte("GET /x HTTP/1.0\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	data, _ := io.ReadAll(conn)
	_ = conn.Close()
	if strings.Contains(string(data), "200 OK") {
		t.Fatalf("HTTPS HTTP/1.0 must be rejected before routing: %q", data)
	}
}

func TestJSONLFailureDegradesWithoutStoppingRawServing(t *testing.T) {
	requirePrivilegedIntegration(t)
	binary := integrationBinary(t)
	root, cfgPath, port := writeIntegrationConfigWithRotations(t, false, 1048576, 256)
	health := startMatchingHealth(t, cfgPath)
	defer health.Close()
	serve := startServe(t, binary, cfgPath, port)
	defer stopProcess(serve)

	if err := os.RemoveAll(filepath.Join(root, "events")); err != nil {
		t.Fatal(err)
	}
	response := plainRequest(t, port, "GET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
	if !strings.Contains(response, "200 OK") {
		t.Fatalf("JSONL failure must not stop raw serving: %q", response)
	}
	response = plainRequest(t, port, "GET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
	if !strings.Contains(response, "200 OK") {
		t.Fatalf("serving did not remain degraded after JSONL failure: %q", response)
	}
}

func TestRawBWJStorageFailureTerminatesServe(t *testing.T) {
	requirePrivilegedIntegration(t)
	binary := integrationBinary(t)
	root, cfgPath, port := writeIntegrationConfigWithRotations(t, false, 128, 1048576)
	health := startMatchingHealth(t, cfgPath)
	defer health.Close()
	serve := startServe(t, binary, cfgPath, port)

	if err := os.RemoveAll(filepath.Join(root, "journal")); err != nil {
		stopProcess(serve)
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err == nil {
		_, _ = conn.Write([]byte("GET /x HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n"))
		_ = conn.Close()
	}
	done := make(chan error, 1)
	go func() { done <- serve.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("serve must exit non-zero after raw BWJ storage failure")
		}
	case <-time.After(5 * time.Second):
		stopProcess(serve)
		t.Fatal("serve did not terminate after raw BWJ storage failure")
	}
}

func requirePrivilegedIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("NOTAIHONEY_PRIVILEGED_INTEGRATION") != "1" {
		t.Skip("requires write access to /run/notaihoney")
	}
}

func writeIntegrationConfig(t *testing.T, https bool) (string, string, int) {
	return writeIntegrationConfigWithRotations(t, https, 1048576, 1048576)
}

func writeIntegrationConfigWithRotations(t *testing.T, https bool, journalRotate, jsonlRotate int64) (string, string, int) {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"pcap", "journal", "events"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	port := freePort(t)
	text := integrationConfig(root, port, journalRotate, jsonlRotate)
	if https {
		if err := os.Mkdir(filepath.Join(root, "tls"), 0700); err != nil {
			t.Fatal(err)
		}
		text = strings.Replace(text, "global: {}", fmt.Sprintf("global:\n  tls:\n    directory: %q", filepath.Join(root, "tls")), 1)
		text = strings.Replace(text, "protocol: http", "protocol: https", 1)
	}
	cfgPath := filepath.Join(root, "honeypot.yaml")
	if err := os.WriteFile(cfgPath, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return root, cfgPath, port
}

func startMatchingHealth(t *testing.T, cfgPath string) *capture.HealthServer {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	health, err := capture.StartHealthServer(ctx, capture.DefaultHealthSocket, cfg.ConfigSHA256, "integration-health")
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = health.Close()
		cancel()
	})
	return health
}

func startServe(t *testing.T, binary, cfgPath string, port int) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(binary, "serve", "--config", cfgPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitTCP(t, fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	return cmd
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func plainRequest(t *testing.T, port int, request string) string {
	t.Helper()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func writeTestCertificate(t *testing.T, directory string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "notaihoney-integration"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "server.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitTCP(t *testing.T, address string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("TCP listener %s did not become ready", address)
}

func waitUnixSocket(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Unix socket %s did not become ready", path)
}

func integrationConfig(root string, port int, journalRotate, jsonlRotate int64) string {
	return fmt.Sprintf(`version: 1
global: {}
sensor:
  id: integration
evidence:
  min_free_bytes: 1
  pcap:
    interface: lo
    directory: %q
    rotate_size_bytes: 1048576
    rotate_seconds: 60
  wire_journal:
    directory: %q
    rotate_size_bytes: %d
    rotate_seconds: 60
  jsonl:
    directory: %q
    rotate_size_bytes: %d
    rotate_seconds: 60
limits:
  max_connections_total: 32
  max_connections_per_service: 16
  max_requests_per_connection: 10
  max_connection_lifetime_seconds: 60
  max_connection_bytes: 1048576
  max_header_bytes: 32768
  max_body_bytes: 65536
  max_response_bytes: 65536
  max_structured_event_bytes: 65536
  max_structured_headers: 32
  max_query_fields: 32
  tls_handshake_timeout_seconds: 2
  header_timeout_seconds: 2
  body_timeout_seconds: 2
  write_timeout_seconds: 2
  idle_timeout_seconds: 2
  max_stream_seconds: 5
  max_post_failure_capture_bytes: 65536
  post_failure_capture_timeout_seconds: 2
services:
  synthetic:
    enabled: true
    listener:
      address: 127.0.0.1
      port: %d
      protocol: http
    identity:
      product: synthetic
    routes:
      - method: GET
        path: /x
        responses:
          - sequence: default
            status: 200
            body: "ok"
    default_response:
      status: 404
      body: "missing"
analysis:
  sqlite:
    path: %q
`, filepath.Join(root, "pcap"), filepath.Join(root, "journal"), journalRotate, filepath.Join(root, "events"), jsonlRotate, port, filepath.Join(root, "index", "honeypot.db"))
}
