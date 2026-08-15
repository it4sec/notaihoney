package config

import (
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
)

const (
	maxServices             = 64
	maxRoutesPerService     = 1024
	maxResponsesPerRoute    = 64
	maxChunksPerResponse    = 4096
	maxConfiguredHeaders    = 128
	maxHeaderNameBytes      = 256
	maxHeaderValueBytes     = 8 * 1024
	maxStaticFixtureBytes   = 64 * 1024 * 1024
	maxSensorIDBytes        = 128
	maxServiceIDBytes       = 64
	maxProductBytes         = 128
	maxVariantBytes         = 128
	maxMethodBytes          = 32
	maxRawPathBytes         = 4 * 1024
	maxClassificationBytes  = 128
	maxConnections          = 8192
	maxRequests             = 100000
	maxConnectionSeconds    = 86400
	maxConnectionBytes      = 1 << 30
	maxHeaderBytes          = 1 << 20
	maxBodyBytes            = 64 << 20
	maxResponseBytes        = 64 << 20
	maxStructuredEventBytes = 1 << 20
	maxStructuredHeaders    = 256
	maxQueryFields          = 1024
	maxPostFailureBytes     = 64 << 20
	maxTimeoutSeconds       = 86400
	maxTLSHandshakeSeconds  = 30
	maxDelayMS              = 86400 * 1000
)

var prohibitedResponseHeaders = map[string]struct{}{
	"content-length":    {},
	"transfer-encoding": {},
	"connection":        {},
	"upgrade":           {},
	"trailer":           {},
}

type listenerEntry struct {
	service string
	addr    net.IP
	port    int
}

func Validate(cfg *Config) error {
	if cfg.Version != 1 {
		return fmt.Errorf("unsupported schema version %d", cfg.Version)
	}
	if cfg.Sensor.ID == "" || len(cfg.Sensor.ID) > maxSensorIDBytes {
		return fmt.Errorf("sensor.id must be 1..%d bytes", maxSensorIDBytes)
	}
	if len(cfg.Services) == 0 || len(cfg.Services) > maxServices {
		return fmt.Errorf("services count must be 1..%d", maxServices)
	}
	if err := validateEvidence(cfg.Evidence); err != nil {
		return err
	}
	if err := validateLimits(cfg.Limits); err != nil {
		return err
	}

	httpsEnabled := false
	staticBytes := int64(0)
	listeners := make([]listenerEntry, 0, len(cfg.Services))

	serviceIDs := make([]string, 0, len(cfg.Services))
	for id := range cfg.Services {
		serviceIDs = append(serviceIDs, id)
	}
	sort.Strings(serviceIDs)
	for _, id := range serviceIDs {
		service := cfg.Services[id]
		if id == "" || len(id) > maxServiceIDBytes {
			return fmt.Errorf("service_id %q must be 1..%d bytes", id, maxServiceIDBytes)
		}

		if service.Identity != nil {
			if service.Identity.Product == "" || len(service.Identity.Product) > maxProductBytes {
				return fmt.Errorf("services.%s.identity.product must be 1..%d bytes", id, maxProductBytes)
			}
			if len(service.Identity.Variant) > maxVariantBytes {
				return fmt.Errorf("services.%s.identity.variant exceeds %d bytes", id, maxVariantBytes)
			}
		}

		var listenerIP net.IP
		if service.Listener != nil {
			listenerIP = net.ParseIP(service.Listener.Address)
			if listenerIP == nil {
				return fmt.Errorf("services.%s.listener.address must be an IP literal", id)
			}
			if service.Listener.Port < 1 || service.Listener.Port > 65535 {
				return fmt.Errorf("services.%s.listener.port must be 1..65535", id)
			}
			if service.Listener.Protocol != "http" && service.Listener.Protocol != "https" {
				return fmt.Errorf("services.%s.listener.protocol must be http or https", id)
			}
		}

		if err := validateHeaders(service.DefaultHeaders, fmt.Sprintf("services.%s.default_headers", id)); err != nil {
			return err
		}
		if len(service.Routes) > maxRoutesPerService {
			return fmt.Errorf("services.%s.routes count exceeds %d", id, maxRoutesPerService)
		}
		seenRoutes := make(map[string]struct{}, len(service.Routes))
		for i := range service.Routes {
			route := &service.Routes[i]
			if route.Method == "" || len(route.Method) > maxMethodBytes || !isHTTPToken(route.Method) {
				return fmt.Errorf("services.%s.routes[%d].method is invalid", id, i)
			}
			if len(route.Path) > maxRawPathBytes || (route.Path != "" && route.Path != "*" && route.Path[0] != '/') || !validConfiguredRawPath(route.Path) {
				return fmt.Errorf("services.%s.routes[%d].path must be an exact raw path of at most %d bytes", id, i, maxRawPathBytes)
			}
			if len(route.Classification) > maxClassificationBytes {
				return fmt.Errorf("services.%s.routes[%d].classification exceeds %d bytes", id, i, maxClassificationBytes)
			}
			key := route.Method + "\x00" + route.Path
			if _, exists := seenRoutes[key]; exists {
				return fmt.Errorf("services.%s has duplicate route (%s, %s)", id, route.Method, route.Path)
			}
			seenRoutes[key] = struct{}{}
			if len(route.Responses) == 0 || len(route.Responses) > maxResponsesPerRoute {
				return fmt.Errorf("services.%s.routes[%d].responses count must be 1..%d", id, i, maxResponsesPerRoute)
			}
			bytes, err := validateRouteResponses(id, i, route, cfg.Limits.MaxResponseBytes)
			if err != nil {
				return err
			}
			staticBytes += bytes
			if staticBytes > maxStaticFixtureBytes {
				return fmt.Errorf("aggregate static response fixtures exceed %d bytes", maxStaticFixtureBytes)
			}
		}
		if service.DefaultResponse != nil {
			bytes, err := validateFallback(id, service.DefaultResponse, cfg.Limits.MaxResponseBytes)
			if err != nil {
				return err
			}
			staticBytes += bytes
			if staticBytes > maxStaticFixtureBytes {
				return fmt.Errorf("aggregate static response fixtures exceed %d bytes", maxStaticFixtureBytes)
			}
		}

		if !service.Enabled {
			continue
		}
		if service.Listener == nil {
			return fmt.Errorf("services.%s.listener is required when enabled", id)
		}
		if service.Identity == nil {
			return fmt.Errorf("services.%s.identity is required when enabled", id)
		}
		if len(service.Routes) == 0 {
			return fmt.Errorf("services.%s.routes must contain at least one route when enabled", id)
		}
		if service.DefaultResponse == nil {
			return fmt.Errorf("services.%s.default_response is required when enabled", id)
		}
		if service.Listener.Protocol == "https" {
			httpsEnabled = true
		}
		listeners = append(listeners, listenerEntry{service: id, addr: listenerIP, port: service.Listener.Port})
	}
	if err := validateListenerConflicts(listeners); err != nil {
		return err
	}
	if httpsEnabled {
		if cfg.Global.TLS == nil || strings.TrimSpace(cfg.Global.TLS.Directory) == "" {
			return fmt.Errorf("global.tls.directory is required when HTTPS is enabled")
		}
	} else if cfg.Global.TLS != nil && strings.TrimSpace(cfg.Global.TLS.Directory) == "" {
		return fmt.Errorf("global.tls.directory cannot be empty")
	}
	if cfg.Analysis != nil && strings.TrimSpace(cfg.Analysis.SQLite.Path) == "" {
		return fmt.Errorf("analysis.sqlite.path cannot be empty")
	}
	return nil
}

func validateEvidence(e EvidenceConfig) error {
	if e.MinFreeBytes == 0 {
		return fmt.Errorf("evidence.min_free_bytes must be positive")
	}
	if strings.TrimSpace(e.PCAP.Interface) == "" || strings.TrimSpace(e.PCAP.Directory) == "" {
		return fmt.Errorf("evidence.pcap.interface and directory are required")
	}
	if err := validateRotation("evidence.pcap", e.PCAP.RotateSizeBytes, e.PCAP.RotateSeconds); err != nil {
		return err
	}
	if strings.TrimSpace(e.WireJournal.Directory) == "" {
		return fmt.Errorf("evidence.wire_journal.directory is required")
	}
	if err := validateRotation("evidence.wire_journal", e.WireJournal.RotateSizeBytes, e.WireJournal.RotateSeconds); err != nil {
		return err
	}
	if strings.TrimSpace(e.JSONL.Directory) == "" {
		return fmt.Errorf("evidence.jsonl.directory is required")
	}
	if err := validateRotation("evidence.jsonl", e.JSONL.RotateSizeBytes, e.JSONL.RotateSeconds); err != nil {
		return err
	}
	return nil
}

func validateRotation(name string, size int64, seconds int) error {
	if size <= 0 {
		return fmt.Errorf("%s.rotate_size_bytes must be positive", name)
	}
	if seconds <= 0 || seconds > maxTimeoutSeconds {
		return fmt.Errorf("%s.rotate_seconds must be 1..%d", name, maxTimeoutSeconds)
	}
	return nil
}

func validateLimits(l LimitsConfig) error {
	if l.MaxConnectionsTotal < 1 || l.MaxConnectionsTotal > maxConnections {
		return fmt.Errorf("limits.max_connections_total must be 1..%d", maxConnections)
	}
	if l.MaxConnectionsPerService < 1 || l.MaxConnectionsPerService > maxConnections {
		return fmt.Errorf("limits.max_connections_per_service must be 1..%d", maxConnections)
	}
	if l.MaxConnectionsPerService > l.MaxConnectionsTotal {
		return fmt.Errorf("max_connections_per_service must be <= max_connections_total")
	}
	if l.MaxRequestsPerConnection < 1 || l.MaxRequestsPerConnection > maxRequests {
		return fmt.Errorf("limits.max_requests_per_connection must be 1..%d", maxRequests)
	}
	if l.MaxConnectionLifetimeSeconds < 1 || l.MaxConnectionLifetimeSeconds > maxConnectionSeconds {
		return fmt.Errorf("limits.max_connection_lifetime_seconds must be 1..%d", maxConnectionSeconds)
	}
	if l.MaxConnectionBytes < 1 || l.MaxConnectionBytes > maxConnectionBytes {
		return fmt.Errorf("limits.max_connection_bytes must be 1..%d", maxConnectionBytes)
	}
	if l.MaxHeaderBytes < 1 || l.MaxHeaderBytes > maxHeaderBytes {
		return fmt.Errorf("limits.max_header_bytes must be 1..%d", maxHeaderBytes)
	}
	if l.MaxBodyBytes < 1 || l.MaxBodyBytes > maxBodyBytes {
		return fmt.Errorf("limits.max_body_bytes must be 1..%d", maxBodyBytes)
	}
	if l.MaxResponseBytes < 1 || l.MaxResponseBytes > maxResponseBytes {
		return fmt.Errorf("limits.max_response_bytes must be 1..%d", maxResponseBytes)
	}
	if l.MaxStructuredEventBytes < 1 || l.MaxStructuredEventBytes > maxStructuredEventBytes {
		return fmt.Errorf("limits.max_structured_event_bytes must be 1..%d", maxStructuredEventBytes)
	}
	if l.MaxStructuredHeaders < 1 || l.MaxStructuredHeaders > maxStructuredHeaders {
		return fmt.Errorf("limits.max_structured_headers must be 1..%d", maxStructuredHeaders)
	}
	if l.MaxQueryFields < 1 || l.MaxQueryFields > maxQueryFields {
		return fmt.Errorf("limits.max_query_fields must be 1..%d", maxQueryFields)
	}
	if l.MaxPostFailureCaptureBytes < 1 || l.MaxPostFailureCaptureBytes > maxPostFailureBytes {
		return fmt.Errorf("limits.max_post_failure_capture_bytes must be 1..%d", maxPostFailureBytes)
	}
	if l.TLSHandshakeTimeoutSeconds < 1 || l.TLSHandshakeTimeoutSeconds > maxTLSHandshakeSeconds {
		return fmt.Errorf("limits.tls_handshake_timeout_seconds must be 1..%d", maxTLSHandshakeSeconds)
	}
	for name, value := range map[string]int{
		"header_timeout_seconds":               l.HeaderTimeoutSeconds,
		"body_timeout_seconds":                 l.BodyTimeoutSeconds,
		"write_timeout_seconds":                l.WriteTimeoutSeconds,
		"idle_timeout_seconds":                 l.IdleTimeoutSeconds,
		"max_stream_seconds":                   l.MaxStreamSeconds,
		"post_failure_capture_timeout_seconds": l.PostFailureCaptureTimeoutSeconds,
	} {
		if value < 1 || value > maxTimeoutSeconds {
			return fmt.Errorf("limits.%s must be 1..%d", name, maxTimeoutSeconds)
		}
	}
	return nil
}

func validateRouteResponses(serviceID string, routeIndex int, route *RouteConfig, responseLimit int64) (int64, error) {
	defaultCount := 0
	numbers := make([]int, 0, len(route.Responses))
	var total int64
	for i := range route.Responses {
		resp := &route.Responses[i]
		if resp.Sequence.Default {
			defaultCount++
		} else {
			numbers = append(numbers, resp.Sequence.Number)
		}
		bytes, err := validateResponse(fmt.Sprintf("services.%s.routes[%d].responses[%d]", serviceID, routeIndex, i), route.Method, resp, responseLimit)
		if err != nil {
			return 0, err
		}
		total += bytes
	}
	if defaultCount != 1 {
		return 0, fmt.Errorf("services.%s.routes[%d] must contain exactly one default response", serviceID, routeIndex)
	}
	sort.Ints(numbers)
	for i, n := range numbers {
		if n != i+1 {
			return 0, fmt.Errorf("services.%s.routes[%d] numeric sequences must be contiguous 1..N", serviceID, routeIndex)
		}
	}
	return total, nil
}

func validateResponse(name, method string, r *ResponseConfig, responseLimit int64) (int64, error) {
	if err := validateStatus(name, method, r.Status); err != nil {
		return 0, err
	}
	if err := validateHeaders(r.Headers, name+".headers"); err != nil {
		return 0, err
	}
	if r.DelayMS < 0 || r.DelayMS > maxDelayMS {
		return 0, fmt.Errorf("%s.delay_ms must be 0..%d", name, maxDelayMS)
	}
	mode := r.ResponseMode
	if mode == "" {
		mode = "immediate"
	}
	if mode != "immediate" && mode != "ndjson" {
		return 0, fmt.Errorf("%s.response_mode must be immediate or ndjson", name)
	}
	if r.Status == http.StatusNoContent || r.Status == http.StatusNotModified {
		if r.Body != nil || len(r.Chunks) != 0 {
			return 0, fmt.Errorf("%s status %d cannot define body or chunks", name, r.Status)
		}
		if mode != "immediate" {
			return 0, fmt.Errorf("%s status %d must use immediate response mode", name, r.Status)
		}
		return 0, nil
	}
	if mode == "immediate" {
		if len(r.Chunks) != 0 {
			return 0, fmt.Errorf("%s immediate response cannot define chunks", name)
		}
		if r.Body == nil {
			return 0, fmt.Errorf("%s immediate response requires body", name)
		}
		if int64(len(*r.Body)) > responseLimit {
			return 0, fmt.Errorf("%s body exceeds configured max_response_bytes", name)
		}
		return int64(len(*r.Body)), nil
	}
	if r.Body != nil {
		return 0, fmt.Errorf("%s ndjson response cannot define body", name)
	}
	if len(r.Chunks) == 0 || len(r.Chunks) > maxChunksPerResponse {
		return 0, fmt.Errorf("%s ndjson chunks count must be 1..%d", name, maxChunksPerResponse)
	}
	var total int64
	for i, chunk := range r.Chunks {
		if chunk.DelayMS < 0 || chunk.DelayMS > maxDelayMS {
			return 0, fmt.Errorf("%s.chunks[%d].delay_ms must be 0..%d", name, i, maxDelayMS)
		}
		if chunk.Body == nil {
			return 0, fmt.Errorf("%s.chunks[%d].body is required", name, i)
		}
		total += int64(len(*chunk.Body))
		if total > responseLimit {
			return 0, fmt.Errorf("%s chunks exceed configured max_response_bytes", name)
		}
	}
	return total, nil
}

func validateFallback(serviceID string, r *FallbackResponse, responseLimit int64) (int64, error) {
	name := fmt.Sprintf("services.%s.default_response", serviceID)
	if err := validateStatus(name, "", r.Status); err != nil {
		return 0, err
	}
	if err := validateHeaders(r.Headers, name+".headers"); err != nil {
		return 0, err
	}
	if r.DelayMS < 0 || r.DelayMS > maxDelayMS {
		return 0, fmt.Errorf("%s.delay_ms must be 0..%d", name, maxDelayMS)
	}
	if r.Status == http.StatusNoContent || r.Status == http.StatusNotModified {
		if r.Body != nil {
			return 0, fmt.Errorf("%s status %d cannot define a body", name, r.Status)
		}
		return 0, nil
	}
	if r.Body == nil {
		return 0, fmt.Errorf("%s.body is required", name)
	}
	if int64(len(*r.Body)) > responseLimit {
		return 0, fmt.Errorf("%s.body exceeds configured max_response_bytes", name)
	}
	return int64(len(*r.Body)), nil
}

func validateStatus(name, method string, status int) error {
	if status < 200 || status > 599 || status == http.StatusSwitchingProtocols {
		return fmt.Errorf("%s.status must be 200..599 and cannot be 101", name)
	}
	if strings.EqualFold(method, "CONNECT") && status >= 200 && status < 300 {
		return fmt.Errorf("%s successful CONNECT tunnel semantics are prohibited", name)
	}
	return nil
}

func validateHeaders(headers map[string]string, name string) error {
	if len(headers) > maxConfiguredHeaders {
		return fmt.Errorf("%s exceeds %d headers", name, maxConfiguredHeaders)
	}
	seen := make(map[string]struct{}, len(headers))
	for key, value := range headers {
		lowerKey := strings.ToLower(key)
		if _, exists := seen[lowerKey]; exists {
			return fmt.Errorf("%s contains case-insensitive duplicate header %q", name, key)
		}
		seen[lowerKey] = struct{}{}
		if key == "" || len(key) > maxHeaderNameBytes || !isHTTPToken(key) {
			return fmt.Errorf("%s contains invalid header name", name)
		}
		if len(value) > maxHeaderValueBytes || strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s header %q has invalid value", name, key)
		}
		if _, prohibited := prohibitedResponseHeaders[strings.ToLower(key)]; prohibited {
			return fmt.Errorf("%s may not define framing header %q", name, key)
		}
	}
	return nil
}

func validateListenerConflicts(entries []listenerEntry) error {
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].port != entries[j].port {
				continue
			}
			if ipsConflict(entries[i].addr, entries[j].addr) {
				return fmt.Errorf("listener conflict between services %s and %s on port %d", entries[i].service, entries[j].service, entries[i].port)
			}
		}
	}
	return nil
}

func ipsConflict(a, b net.IP) bool {
	if a.IsUnspecified() || b.IsUnspecified() {
		return true
	}
	return a.Equal(b)
}

func isHTTPToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || unicode.IsControl(r) || strings.ContainsRune("()<>@,;:\\\"/[]?={} \t", r) {
			return false
		}
	}
	return true
}

func validConfiguredRawPath(path string) bool {
	if path == "*" {
		return true
	}
	if strings.ContainsAny(path, "?#") {
		return false
	}
	for _, r := range path {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func HasHTTPS(cfg *Config) bool {
	for _, svc := range cfg.Services {
		if svc.Enabled && svc.Listener != nil && svc.Listener.Protocol == "https" {
			return true
		}
	}
	return false
}

func SQLitePath(cfg *Config) string {
	if cfg.Analysis == nil {
		return ""
	}
	return filepath.Clean(cfg.Analysis.SQLite.Path)
}
