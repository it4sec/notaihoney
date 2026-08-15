package evidence

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const EventSchemaVersion = 1

type HeaderMetadata struct {
	Name      string `json:"name"`
	Present   bool   `json:"present"`
	Scheme    string `json:"scheme,omitempty"`
	Length    int    `json:"length"`
	SHA256    string `json:"sha256"`
	Value     string `json:"value,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

type QueryMetadata struct {
	Name   string `json:"name"`
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
}

type Event struct {
	EventSchemaVersion int    `json:"event_schema_version"`
	EventType          string `json:"event_type"`
	TimestampNS        int64  `json:"timestamp_ns"`
	SensorID           string `json:"sensor_id"`
	RunSessionID       string `json:"run_session_id"`
	ConfigSchemaVersion int   `json:"config_schema_version"`
	ConfigSHA256       string `json:"config_sha256"`

	ServiceID   string `json:"service_id,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	RequestID    string `json:"request_id,omitempty"`

	SourceIP        string `json:"source_ip,omitempty"`
	SourcePort      int    `json:"source_port,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	DestinationPort int    `json:"destination_port,omitempty"`
	ListenerProtocol string `json:"listener_protocol,omitempty"`

	TimestampStartNS int64 `json:"timestamp_start_ns,omitempty"`
	TimestampEndNS   int64 `json:"timestamp_end_ns,omitempty"`
	HTTPVersion      string `json:"http_version,omitempty"`
	Method           string `json:"method,omitempty"`
	RequestTargetSanitized string `json:"request_target_sanitized,omitempty"`
	RawPath          string `json:"raw_path,omitempty"`
	QueryFields      []QueryMetadata `json:"query_fields,omitempty"`
	SanitizedHeaders []HeaderMetadata `json:"sanitized_headers,omitempty"`
	ContentType      string `json:"content_type,omitempty"`
	DeclaredContentLength *int64 `json:"declared_content_length,omitempty"`
	MatchedRoute     string `json:"matched_route,omitempty"`
	Classification   string `json:"classification,omitempty"`
	ResponseSource   string `json:"response_source,omitempty"`
	ResponseSequence *int   `json:"response_sequence,omitempty"`
	ResponseStatus   int    `json:"response_status,omitempty"`
	RequestBytes     int64  `json:"request_bytes,omitempty"`
	RequestStreamStart int64 `json:"request_stream_start,omitempty"`
	RequestStreamLength int64 `json:"request_stream_length,omitempty"`
	RequestComplete  bool   `json:"request_complete,omitempty"`
	ResponseBytes    int64  `json:"response_bytes,omitempty"`
	ResponseStreamStart int64 `json:"response_stream_start,omitempty"`
	ResponseStreamLength int64 `json:"response_stream_length,omitempty"`
	ResponseSHA256   string `json:"response_sha256,omitempty"`
	ResponseComplete bool   `json:"response_complete,omitempty"`
	WriteError       string `json:"write_error,omitempty"`
	MetadataTruncated bool  `json:"metadata_truncated,omitempty"`

	ApplicationVersion string `json:"application_version,omitempty"`
	GoVersion          string `json:"go_version,omitempty"`
	BuildID            string `json:"build_id,omitempty"`
	TLSEnabled         bool   `json:"tls_enabled,omitempty"`
	TLSCertificateSHA256 string `json:"tls_certificate_sha256,omitempty"`
	TLSCertificateNotBefore string `json:"tls_certificate_not_before,omitempty"`
	TLSCertificateNotAfter string `json:"tls_certificate_not_after,omitempty"`

	TLSErrorCode      string `json:"bounded_tls_error_code,omitempty"`
	HandshakeElapsedMS int64 `json:"handshake_elapsed_ms,omitempty"`
	OperationalCode   string `json:"operational_code,omitempty"`
	OperationalAction string `json:"action,omitempty"`
	CloseReason       string `json:"close_reason,omitempty"`
	BytesIn           int64  `json:"bytes_in,omitempty"`
	BytesOut          int64  `json:"bytes_out,omitempty"`
	RequestCount      int    `json:"request_count,omitempty"`
}

// MarshalJSON keeps non-applicable fields compact for non-exchange events,
// but an exchange always carries its required forensic byte/range and
// completeness fields even when their valid value is zero or false.
func (e Event) MarshalJSON() ([]byte, error) {
	type eventAlias Event
	if e.EventType != "exchange" {
		return json.Marshal(eventAlias(e))
	}
	type exchangeEvent struct {
		eventAlias
		TimestampStartNS       int64            `json:"timestamp_start_ns"`
		TimestampEndNS         int64            `json:"timestamp_end_ns"`
		HTTPVersion            string           `json:"http_version"`
		Method                 string           `json:"method"`
		RequestTargetSanitized string           `json:"request_target_sanitized"`
		RawPath                string           `json:"raw_path"`
		QueryFields            []QueryMetadata  `json:"query_fields"`
		SanitizedHeaders       []HeaderMetadata `json:"sanitized_headers"`
		MatchedRoute           string           `json:"matched_route"`
		Classification         string           `json:"classification"`
		ResponseSource         string           `json:"response_source"`
		ResponseStatus         int              `json:"response_status"`
		RequestBytes           int64            `json:"request_bytes"`
		RequestStreamStart     int64            `json:"request_stream_start"`
		RequestStreamLength    int64            `json:"request_stream_length"`
		RequestComplete        bool             `json:"request_complete"`
		ResponseBytes          int64            `json:"response_bytes"`
		ResponseStreamStart    int64            `json:"response_stream_start"`
		ResponseStreamLength   int64            `json:"response_stream_length"`
		ResponseSHA256         string           `json:"response_sha256"`
		ResponseComplete       bool             `json:"response_complete"`
		WriteError             string           `json:"write_error"`
	}
	return json.Marshal(exchangeEvent{
		eventAlias: eventAlias(e),
		TimestampStartNS: e.TimestampStartNS,
		TimestampEndNS: e.TimestampEndNS,
		HTTPVersion: e.HTTPVersion,
		Method: e.Method,
		RequestTargetSanitized: e.RequestTargetSanitized,
		RawPath: e.RawPath,
		QueryFields: e.QueryFields,
		SanitizedHeaders: e.SanitizedHeaders,
		MatchedRoute: e.MatchedRoute,
		Classification: e.Classification,
		ResponseSource: e.ResponseSource,
		ResponseStatus: e.ResponseStatus,
		RequestBytes: e.RequestBytes,
		RequestStreamStart: e.RequestStreamStart,
		RequestStreamLength: e.RequestStreamLength,
		RequestComplete: e.RequestComplete,
		ResponseBytes: e.ResponseBytes,
		ResponseStreamStart: e.ResponseStreamStart,
		ResponseStreamLength: e.ResponseStreamLength,
		ResponseSHA256: e.ResponseSHA256,
		ResponseComplete: e.ResponseComplete,
		WriteError: e.WriteError,
	})
}

type JSONLWriter struct {
	mu             sync.Mutex
	directory      string
	runSessionID   ID
	rotateSize     int64
	rotateDuration time.Duration
	maxEventBytes  int
	file           *os.File
	buffer         *bufio.Writer
	sequence       uint64
	createdAt      time.Time
	bytesWritten   int64
	closed         bool
}

func NewJSONLWriter(directory string, runSessionID ID, rotateSizeBytes int64, rotateSeconds, maxEventBytes int) (*JSONLWriter, error) {
	if err := CheckWritable(directory); err != nil {
		return nil, err
	}
	w := &JSONLWriter{
		directory:      directory,
		runSessionID:   runSessionID,
		rotateSize:     rotateSizeBytes,
		rotateDuration: time.Duration(rotateSeconds) * time.Second,
		maxEventBytes:  maxEventBytes,
	}
	if err := w.openNextLocked(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *JSONLWriter) WriteEvent(event Event) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	if event.EventSchemaVersion == 0 {
		event.EventSchemaVersion = EventSchemaVersion
	}
	if event.TimestampNS == 0 {
		event.TimestampNS = time.Now().UnixNano()
	}
	if w.maxEventBytes <= 1 {
		return fmt.Errorf("max_structured_event_bytes is too small")
	}
	encoded, err := boundedEventJSON(event, w.maxEventBytes-1)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if w.shouldRotateLocked(int64(len(encoded))) {
		if err := w.rotateLocked(); err != nil {
			return err
		}
	}
	if _, err := w.buffer.Write(encoded); err != nil {
		return fmt.Errorf("JSONL write: %w", err)
	}
	if err := w.buffer.Flush(); err != nil {
		return fmt.Errorf("JSONL flush: %w", err)
	}
	w.bytesWritten += int64(len(encoded))
	return nil
}

func boundedEventJSON(event Event, maximum int) ([]byte, error) {
	if maximum <= 0 {
		return nil, fmt.Errorf("invalid structured event bound")
	}
	marshal := func(e Event) ([]byte, error) { return json.Marshal(e) }
	b, err := marshal(event)
	if err != nil {
		return nil, err
	}
	if len(b) <= maximum {
		return b, nil
	}
	event.MetadataTruncated = true
	for len(event.SanitizedHeaders) > 0 || len(event.QueryFields) > 0 {
		if len(event.SanitizedHeaders) >= len(event.QueryFields) && len(event.SanitizedHeaders) > 0 {
			event.SanitizedHeaders = event.SanitizedHeaders[:len(event.SanitizedHeaders)-1]
		} else if len(event.QueryFields) > 0 {
			event.QueryFields = event.QueryFields[:len(event.QueryFields)-1]
		}
		b, err = marshal(event)
		if err != nil {
			return nil, err
		}
		if len(b) <= maximum {
			return b, nil
		}
	}
	for _, target := range []*string{&event.RequestTargetSanitized, &event.RawPath, &event.ContentType, &event.MatchedRoute, &event.Classification, &event.WriteError} {
		if len(*target) > 256 {
			*target = (*target)[:256]
		}
	}
	b, err = marshal(event)
	if err != nil {
		return nil, err
	}
	if len(b) <= maximum {
		return b, nil
	}
	// Mandatory correlation fields are retained even under an unusually small
	// operator bound; variable exchange metadata is discarded first.
	minimal := Event{
		EventSchemaVersion: event.EventSchemaVersion,
		EventType: event.EventType,
		TimestampNS: event.TimestampNS,
		SensorID: event.SensorID,
		RunSessionID: event.RunSessionID,
		ConfigSchemaVersion: event.ConfigSchemaVersion,
		ConfigSHA256: event.ConfigSHA256,
		ServiceID: event.ServiceID,
		ConnectionID: event.ConnectionID,
		RequestID: event.RequestID,
		MetadataTruncated: true,
	}
	if event.EventType == "exchange" {
		minimal.TimestampStartNS = event.TimestampStartNS
		minimal.TimestampEndNS = event.TimestampEndNS
		minimal.HTTPVersion = event.HTTPVersion
		minimal.Method = event.Method
		minimal.ResponseSource = event.ResponseSource
		minimal.ResponseSequence = event.ResponseSequence
		minimal.ResponseStatus = event.ResponseStatus
		minimal.RequestBytes = event.RequestBytes
		minimal.RequestStreamStart = event.RequestStreamStart
		minimal.RequestStreamLength = event.RequestStreamLength
		minimal.RequestComplete = event.RequestComplete
		minimal.ResponseBytes = event.ResponseBytes
		minimal.ResponseStreamStart = event.ResponseStreamStart
		minimal.ResponseStreamLength = event.ResponseStreamLength
		minimal.ResponseSHA256 = event.ResponseSHA256
		minimal.ResponseComplete = event.ResponseComplete
		minimal.WriteError = event.WriteError
	}
	b, err = marshal(minimal)
	if err != nil {
		return nil, err
	}
	if len(b) > maximum {
		return nil, fmt.Errorf("structured event mandatory fields exceed max_structured_event_bytes")
	}
	return b, nil
}

func (w *JSONLWriter) shouldRotateLocked(next int64) bool {
	if w.file == nil {
		return true
	}
	if w.rotateSize > 0 && w.bytesWritten > 0 && w.bytesWritten+next > w.rotateSize {
		return true
	}
	return w.rotateDuration > 0 && time.Since(w.createdAt) >= w.rotateDuration
}

func (w *JSONLWriter) rotateLocked() error {
	if w.buffer != nil {
		if err := w.buffer.Flush(); err != nil {
			return err
		}
	}
	if w.file != nil {
		if err := w.file.Sync(); err != nil {
			return err
		}
		if err := w.file.Close(); err != nil {
			return err
		}
	}
	return w.openNextLocked()
}

func (w *JSONLWriter) openNextLocked() error {
	w.sequence++
	name := fmt.Sprintf("events_%s_%020d.jsonl", FormatID(w.runSessionID), w.sequence)
	path := filepath.Join(w.directory, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	w.file = f
	w.buffer = bufio.NewWriterSize(f, 64*1024)
	w.createdAt = time.Now()
	w.bytesWritten = 0
	return nil
}

func (w *JSONLWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	if w.file == nil {
		return nil
	}
	if err := w.buffer.Flush(); err != nil {
		w.file.Close()
		return err
	}
	if err := w.file.Sync(); err != nil {
		w.file.Close()
		return err
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func SanitizeHeaders(headers http.Header, maxHeaders int) ([]HeaderMetadata, bool) {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	truncated := len(names) > maxHeaders
	if len(names) > maxHeaders {
		names = names[:maxHeaders]
	}
	out := make([]HeaderMetadata, 0, len(names))
	for _, name := range names {
		joined := strings.Join(headers.Values(name), ", ")
		sum := sha256.Sum256([]byte(joined))
		meta := HeaderMetadata{Name: name, Present: true, Length: len(joined), SHA256: hex.EncodeToString(sum[:])}
		lower := strings.ToLower(name)
		if lower == "authorization" || lower == "proxy-authorization" || lower == "cookie" || lower == "set-cookie" {
			if fields := strings.Fields(joined); len(fields) > 0 && (lower == "authorization" || lower == "proxy-authorization") {
				meta.Scheme = fields[0]
			}
		} else {
			meta.Value = joined
			if len(meta.Value) > 1024 {
				meta.Value = meta.Value[:1024]
				meta.Truncated = true
				truncated = true
			}
		}
		out = append(out, meta)
	}
	return out, truncated
}

func QueryMetadataFromURL(u *url.URL, maxFields int) ([]QueryMetadata, bool) {
	if u == nil || u.RawQuery == "" || maxFields <= 0 {
		return nil, u != nil && u.RawQuery != ""
	}
	raw := u.RawQuery
	out := make([]QueryMetadata, 0, minInt(maxFields, 16))
	truncated := false
	for len(raw) > 0 {
		part := raw
		if i := strings.IndexByte(raw, '&'); i >= 0 {
			part = raw[:i]
			raw = raw[i+1:]
		} else {
			raw = ""
		}
		if part == "" {
			continue
		}
		if len(out) >= maxFields {
			truncated = true
			break
		}
		nameRaw, valueRaw := part, ""
		if i := strings.IndexByte(part, '='); i >= 0 {
			nameRaw, valueRaw = part[:i], part[i+1:]
		}
		name, nameErr := url.QueryUnescape(nameRaw)
		value, valueErr := url.QueryUnescape(valueRaw)
		if nameErr != nil {
			name = "<invalid-encoding>"
			truncated = true
		}
		if valueErr != nil {
			// Hash the exact encoded value when decoding is invalid. Raw query
			// bytes remain authoritative in BWJ, while structured metadata stays bounded.
			value = valueRaw
			truncated = true
		}
		if len(name) > 256 {
			name = name[:256]
			truncated = true
		}
		sum := sha256.Sum256([]byte(value))
		out = append(out, QueryMetadata{Name: name, Length: len(value), SHA256: hex.EncodeToString(sum[:])})
	}
	return out, truncated
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func SanitizeRequestTarget(rawPath string, u *url.URL, maxFields int) (string, bool) {
	fields, truncated := QueryMetadataFromURL(u, maxFields)
	if len(fields) == 0 {
		return rawPath, truncated
	}
	names := make([]string, 0, len(fields))
	for _, field := range fields {
		names = append(names, url.QueryEscape(field.Name))
	}
	return rawPath + "?" + strings.Join(names, "&"), truncated
}
