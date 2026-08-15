package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validConfigYAML = `version: 1
global: {}
sensor:
  id: sensor-01
evidence:
  min_free_bytes: 1
  pcap:
    interface: lo
    directory: /tmp
    rotate_size_bytes: 1048576
    rotate_seconds: 60
  wire_journal:
    directory: /tmp
    rotate_size_bytes: 1048576
    rotate_seconds: 60
  jsonl:
    directory: /tmp
    rotate_size_bytes: 1048576
    rotate_seconds: 60
limits:
  max_connections_total: 16
  max_connections_per_service: 8
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
  example:
    enabled: true
    listener:
      address: 127.0.0.1
      port: 18080
      protocol: http
    identity:
      product: example
    default_headers:
      Content-Type: application/json
    routes:
      - method: GET
        path: /x
        responses:
          - sequence: default
            status: 200
            body: "ok"
    default_response:
      status: 404
      body: "not found"
`

func loadText(t *testing.T, text string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "honeypot.yaml")
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func TestExactByteSHA256(t *testing.T) {
	cfg, err := loadText(t, validConfigYAML)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(validConfigYAML))
	if got, want := cfg.ConfigSHA256, hex.EncodeToString(sum[:]); got != want {
		t.Fatalf("hash=%s want=%s", got, want)
	}
	cfg2, err := loadText(t, "# comment\n"+validConfigYAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigSHA256 == cfg2.ConfigSHA256 {
		t.Fatal("comment change must alter exact-byte hash")
	}
}

func TestStrictYAMLRejections(t *testing.T) {
	cases := map[string]string{
		"duplicate": strings.Replace(validConfigYAML, "version: 1", "version: 1\nversion: 1", 1),
		"unknown": strings.Replace(validConfigYAML, "sensor:\n", "unknown_top: true\nsensor:\n", 1),
		"anchor": strings.Replace(validConfigYAML, "id: sensor-01", "id: &id sensor-01", 1),
		"alias": strings.Replace(validConfigYAML, "product: example", "product: *id", 1),
		"merge": strings.Replace(validConfigYAML, "global: {}", "global:\n  <<: {}", 1),
		"custom_tag": strings.Replace(validConfigYAML, "id: sensor-01", "id: !custom sensor-01", 1),
		"multiple_docs": validConfigYAML + "\n---\nversion: 1\n",
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadText(t, text); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestSequenceAndFramingValidation(t *testing.T) {
	badSequence := strings.Replace(validConfigYAML, "- sequence: default", "- sequence: 2", 1)
	if _, err := loadText(t, badSequence); err == nil {
		t.Fatal("non-contiguous/missing default sequence must fail")
	}
	badHeader := strings.Replace(validConfigYAML, "Content-Type: application/json", "Content-Length: '2'", 1)
	if _, err := loadText(t, badHeader); err == nil {
		t.Fatal("YAML framing header must fail")
	}
}

func TestListenerConflictAndGlobalLimit(t *testing.T) {
	second := `
  second:
    enabled: true
    listener:
      address: 0.0.0.0
      port: 18080
      protocol: http
    identity:
      product: second
    routes:
      - method: GET
        path: /y
        responses:
          - sequence: default
            status: 200
            body: "ok"
    default_response:
      status: 404
      body: "not found"
`
	text := validConfigYAML + second
	if _, err := loadText(t, text); err == nil {
		t.Fatal("conflicting wildcard listener must fail")
	}
	badLimit := strings.Replace(validConfigYAML, "max_connections_per_service: 8", "max_connections_per_service: 32", 1)
	if _, err := loadText(t, badLimit); err == nil {
		t.Fatal("per-service limit above global limit must fail")
	}
}

func TestTypeMismatchHardCeilingsAndRouteUniqueness(t *testing.T) {
	if _, err := loadText(t, strings.Replace(validConfigYAML, "version: 1", "version: one", 1)); err == nil {
		t.Fatal("type mismatch must fail")
	}
	if _, err := loadText(t, strings.Replace(validConfigYAML, "max_header_bytes: 32768", "max_header_bytes: 1048577", 1)); err == nil {
		t.Fatal("hard header ceiling must fail")
	}
	duplicateRoute := strings.Replace(validConfigYAML,
		"    default_response:\n      status: 404",
		"      - method: GET\n        path: /x\n        responses:\n          - sequence: default\n            status: 200\n            body: \"again\"\n    default_response:\n      status: 404", 1)
	if _, err := loadText(t, duplicateRoute); err == nil {
		t.Fatal("duplicate method/raw-path route must fail")
	}
}

func TestTLSConditionalAndResponseStatusRules(t *testing.T) {
	httpsWithoutTLS := strings.Replace(validConfigYAML, "protocol: http", "protocol: https", 1)
	if _, err := loadText(t, httpsWithoutTLS); err == nil {
		t.Fatal("HTTPS without global TLS must fail")
	}
	httpsWithTLS := strings.Replace(httpsWithoutTLS, "global: {}", "global:\n  tls:\n    directory: /tmp/tls", 1)
	if _, err := loadText(t, httpsWithTLS); err != nil {
		t.Fatalf("HTTPS with global TLS schema should pass common validation: %v", err)
	}

	oneXX := strings.Replace(validConfigYAML, "status: 200", "status: 100", 1)
	if _, err := loadText(t, oneXX); err == nil {
		t.Fatal("YAML 1xx response must fail")
	}
	body204 := strings.Replace(validConfigYAML, "status: 200", "status: 204", 1)
	if _, err := loadText(t, body204); err == nil {
		t.Fatal("204 response with body must fail")
	}
	connect2xx := strings.Replace(validConfigYAML, "- method: GET", "- method: CONNECT", 1)
	if _, err := loadText(t, connect2xx); err == nil {
		t.Fatal("configured successful CONNECT route must fail")
	}
}

func TestDisabledServiceStillRejectsInvalidSuppliedFields(t *testing.T) {
	text := strings.Replace(validConfigYAML, "enabled: true", "enabled: false", 1)
	text = strings.Replace(text, "protocol: http", "protocol: ftp", 1)
	if _, err := loadText(t, text); err == nil {
		t.Fatal("invalid enum in supplied disabled-service fields must fail")
	}
}
