package evidence

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestStructuredSecretsAreSanitized(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer secret-value")
	h.Set("Cookie", "session=secret")
	h.Set("User-Agent", "test-agent")
	meta, _ := SanitizeHeaders(h, 10)
	for _, item := range meta {
		if (item.Name == "Authorization" || item.Name == "Cookie") && item.Value != "" {
			t.Fatalf("secret copied into structured metadata: %#v", item)
		}
	}
}

func TestQueryMetadataDoesNotStoreValues(t *testing.T) {
	u, _ := url.Parse("http://example.invalid/x?token=supersecret&a=1")
	meta, _ := QueryMetadataFromURL(u, 10)
	encoded := ""
	for _, field := range meta {
		encoded += field.Name + field.SHA256
	}
	if strings.Contains(encoded, "supersecret") {
		t.Fatal("raw query value leaked")
	}
}

func TestBoundedEventSetsTruncation(t *testing.T) {
	e := Event{EventSchemaVersion: 1, EventType: "exchange", TimestampNS: 1, SensorID: "s", RunSessionID: "r", ConfigSchemaVersion: 1, ConfigSHA256: "h"}
	for i := 0; i < 100; i++ {
		e.SanitizedHeaders = append(e.SanitizedHeaders, HeaderMetadata{Name: "X", Value: strings.Repeat("a", 100)})
	}
	b, err := boundedEventJSON(e, 512)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 512 || !strings.Contains(string(b), `"metadata_truncated":true`) {
		t.Fatalf("bounded event failed: %d %s", len(b), b)
	}
}

func TestStructuredHeaderAndQueryBounds(t *testing.T) {
	headers := make(http.Header)
	headers.Set("A", "1")
	headers.Set("B", "2")
	meta, truncated := SanitizeHeaders(headers, 1)
	if len(meta) != 1 || !truncated {
		t.Fatalf("header bound not enforced: len=%d truncated=%v", len(meta), truncated)
	}
	u, err := url.Parse("http://example.invalid/x?a=1&b=2")
	if err != nil {
		t.Fatal(err)
	}
	query, truncated := QueryMetadataFromURL(u, 1)
	if len(query) != 1 || !truncated {
		t.Fatalf("query bound not enforced: len=%d truncated=%v", len(query), truncated)
	}
}

func TestEventCarriesForensicCorrelationFields(t *testing.T) {
	event := Event{
		EventSchemaVersion: EventSchemaVersion,
		EventType: "exchange",
		TimestampNS: 1,
		SensorID: "sensor",
		RunSessionID: "run",
		ConfigSchemaVersion: 1,
		ConfigSHA256: strings.Repeat("a", 64),
		ServiceID: "service",
		ConnectionID: "connection",
		RequestID: "request",
		RequestStreamStart: 10,
		RequestStreamLength: 20,
		RequestComplete: true,
		ResponseStreamStart: 30,
		ResponseStreamLength: 40,
		ResponseSHA256: strings.Repeat("b", 64),
		ResponseComplete: true,
	}
	b, err := boundedEventJSON(event, 4096)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, field := range []string{"config_sha256", "connection_id", "request_id", "request_stream_start", "response_sha256"} {
		if !strings.Contains(text, "\""+field+"\"") {
			t.Fatalf("missing %s in %s", field, text)
		}
	}
}

func TestExchangeRequiredZeroAndFalseFieldsAreSerialized(t *testing.T) {
	event := Event{
		EventSchemaVersion: EventSchemaVersion,
		EventType: "exchange",
		TimestampNS: 1,
		SensorID: "sensor",
		RunSessionID: "run",
		ConfigSchemaVersion: 1,
		ConfigSHA256: strings.Repeat("a", 64),
		ServiceID: "service",
		ConnectionID: "connection",
		RequestID: "request",
		TimestampStartNS: 1,
		TimestampEndNS: 2,
		HTTPVersion: "HTTP/1.1",
		Method: "GET",
		RawPath: "/",
		ResponseSource: "service_default",
		ResponseStatus: 200,
		ResponseSHA256: strings.Repeat("b", 64),
	}
	b, err := boundedEventJSON(event, 4096)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	for _, fragment := range []string{
		`"request_stream_start":0`,
		`"request_stream_length":0`,
		`"request_complete":false`,
		`"response_stream_start":0`,
		`"response_stream_length":0`,
		`"response_complete":false`,
		`"write_error":""`,
	} {
		if !strings.Contains(text, fragment) {
			t.Fatalf("missing required exchange field %s in %s", fragment, text)
		}
	}
}
