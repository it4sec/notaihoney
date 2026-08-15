package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

const MaxConfigBytes = 8 * 1024 * 1024

type Config struct {
	Version  int                `yaml:"version"`
	Global   GlobalConfig       `yaml:"global"`
	Sensor   SensorConfig       `yaml:"sensor"`
	Evidence EvidenceConfig     `yaml:"evidence"`
	Limits   LimitsConfig       `yaml:"limits"`
	Services map[string]Service `yaml:"services"`
	Analysis *AnalysisConfig    `yaml:"analysis,omitempty"`

	Raw          []byte `yaml:"-"`
	ConfigSHA256 string `yaml:"-"`
	SourcePath   string `yaml:"-"`
}

type GlobalConfig struct {
	TLS *TLSGlobalConfig `yaml:"tls,omitempty"`
}

type TLSGlobalConfig struct {
	Directory string `yaml:"directory"`
}

type SensorConfig struct {
	ID string `yaml:"id"`
}

type EvidenceConfig struct {
	MinFreeBytes uint64          `yaml:"min_free_bytes"`
	PCAP         PCAPConfig      `yaml:"pcap"`
	WireJournal  RotationConfig  `yaml:"wire_journal"`
	JSONL        RotationConfig  `yaml:"jsonl"`
}

type PCAPConfig struct {
	Interface       string `yaml:"interface"`
	Directory       string `yaml:"directory"`
	RotateSizeBytes int64  `yaml:"rotate_size_bytes"`
	RotateSeconds   int    `yaml:"rotate_seconds"`
}

type RotationConfig struct {
	Directory       string `yaml:"directory"`
	RotateSizeBytes int64  `yaml:"rotate_size_bytes"`
	RotateSeconds   int    `yaml:"rotate_seconds"`
}

type LimitsConfig struct {
	MaxConnectionsTotal              int   `yaml:"max_connections_total"`
	MaxConnectionsPerService         int   `yaml:"max_connections_per_service"`
	MaxRequestsPerConnection         int   `yaml:"max_requests_per_connection"`
	MaxConnectionLifetimeSeconds     int   `yaml:"max_connection_lifetime_seconds"`
	MaxConnectionBytes               int64 `yaml:"max_connection_bytes"`
	MaxHeaderBytes                   int64 `yaml:"max_header_bytes"`
	MaxBodyBytes                     int64 `yaml:"max_body_bytes"`
	MaxResponseBytes                 int64 `yaml:"max_response_bytes"`
	MaxStructuredEventBytes          int   `yaml:"max_structured_event_bytes"`
	MaxStructuredHeaders             int   `yaml:"max_structured_headers"`
	MaxQueryFields                   int   `yaml:"max_query_fields"`
	TLSHandshakeTimeoutSeconds       int   `yaml:"tls_handshake_timeout_seconds"`
	HeaderTimeoutSeconds             int   `yaml:"header_timeout_seconds"`
	BodyTimeoutSeconds               int   `yaml:"body_timeout_seconds"`
	WriteTimeoutSeconds              int   `yaml:"write_timeout_seconds"`
	IdleTimeoutSeconds               int   `yaml:"idle_timeout_seconds"`
	MaxStreamSeconds                 int   `yaml:"max_stream_seconds"`
	MaxPostFailureCaptureBytes       int64 `yaml:"max_post_failure_capture_bytes"`
	PostFailureCaptureTimeoutSeconds int   `yaml:"post_failure_capture_timeout_seconds"`
}

type Service struct {
	Enabled         bool              `yaml:"enabled"`
	Listener        *ListenerConfig   `yaml:"listener,omitempty"`
	Identity        *IdentityConfig   `yaml:"identity,omitempty"`
	DefaultHeaders  map[string]string `yaml:"default_headers,omitempty"`
	Routes          []RouteConfig     `yaml:"routes,omitempty"`
	DefaultResponse *FallbackResponse `yaml:"default_response,omitempty"`
}

type ListenerConfig struct {
	Address  string `yaml:"address"`
	Port     int    `yaml:"port"`
	Protocol string `yaml:"protocol"`
}

type IdentityConfig struct {
	Product string `yaml:"product"`
	Variant string `yaml:"variant,omitempty"`
}

type RouteConfig struct {
	Method         string           `yaml:"method"`
	Path           string           `yaml:"path"`
	Classification string           `yaml:"classification,omitempty"`
	Responses      []ResponseConfig `yaml:"responses"`
}

type Sequence struct {
	Default bool
	Number  int
}

func (s *Sequence) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.ScalarNode {
		return fmt.Errorf("sequence must be a positive integer or default")
	}
	if node.Tag == "!!str" && node.Value == "default" {
		s.Default = true
		s.Number = 0
		return nil
	}
	if node.Tag != "!!int" {
		return fmt.Errorf("sequence must be a positive integer or default")
	}
	var n int
	if err := node.Decode(&n); err != nil || n <= 0 {
		return fmt.Errorf("sequence must be a positive integer or default")
	}
	s.Default = false
	s.Number = n
	return nil
}

type ResponseConfig struct {
	Sequence     Sequence          `yaml:"sequence"`
	Status       int               `yaml:"status"`
	Headers      map[string]string `yaml:"headers,omitempty"`
	ResponseMode string            `yaml:"response_mode,omitempty"`
	DelayMS      int               `yaml:"delay_ms,omitempty"`
	Body         *string           `yaml:"body,omitempty"`
	Chunks       []ChunkConfig     `yaml:"chunks,omitempty"`
}

type ChunkConfig struct {
	DelayMS int     `yaml:"delay_ms,omitempty"`
	Body    *string `yaml:"body"`
}

type FallbackResponse struct {
	Status  int               `yaml:"status"`
	Headers map[string]string `yaml:"headers,omitempty"`
	DelayMS int               `yaml:"delay_ms,omitempty"`
	Body    *string           `yaml:"body"`
}

type AnalysisConfig struct {
	SQLite SQLiteConfig `yaml:"sqlite"`
}

type SQLiteConfig struct {
	Path string `yaml:"path"`
}

// Load reads the configuration exactly once, hashes those exact bytes, parses
// those same bytes, and performs common schema validation.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("CONFIG_INVALID open config: %w", err)
	}
	defer f.Close()

	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, fmt.Errorf("CONFIG_INVALID read config: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("CONFIG_INVALID configuration exceeds %d bytes", MaxConfigBytes)
	}

	sum := sha256.Sum256(data)
	if err := inspectYAMLSyntax(data); err != nil {
		return nil, fmt.Errorf("CONFIG_INVALID %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("CONFIG_INVALID decode: %w", err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("CONFIG_INVALID multiple YAML documents are prohibited")
		}
		return nil, fmt.Errorf("CONFIG_INVALID trailing YAML: %w", err)
	}

	cfg.Raw = append([]byte(nil), data...)
	cfg.ConfigSHA256 = hex.EncodeToString(sum[:])
	cfg.SourcePath = path
	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("CONFIG_INVALID %w", err)
	}
	return &cfg, nil
}

func inspectYAMLSyntax(data []byte) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		return fmt.Errorf("YAML syntax: %w", err)
	}
	if len(doc.Content) == 0 {
		return fmt.Errorf("empty YAML document")
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return fmt.Errorf("top-level YAML document must be a mapping")
	}
	if err := requireTopLevelKeys(root); err != nil {
		return err
	}
	if err := inspectNode(root); err != nil {
		return err
	}
	var second yaml.Node
	if err := dec.Decode(&second); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple YAML documents are prohibited")
		}
		return fmt.Errorf("YAML syntax: %w", err)
	}
	return nil
}

func requireTopLevelKeys(root *yaml.Node) error {
	required := map[string]bool{
		"version": false,
		"global": false,
		"sensor": false,
		"evidence": false,
		"limits": false,
		"services": false,
	}
	for i := 0; i < len(root.Content); i += 2 {
		if _, ok := required[root.Content[i].Value]; ok {
			required[root.Content[i].Value] = true
		}
	}
	for key, present := range required {
		if !present {
			return fmt.Errorf("required top-level field %q is missing", key)
		}
	}
	return nil
}

func inspectNode(node *yaml.Node) error {
	if node.Anchor != "" {
		return fmt.Errorf("YAML anchors are prohibited")
	}
	if node.Kind == yaml.AliasNode {
		return fmt.Errorf("YAML aliases are prohibited")
	}
	if !allowedYAMLTag(node.Tag) {
		return fmt.Errorf("custom or unsupported YAML tag %q", node.Tag)
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("mapping keys must be strings")
			}
			if key.Value == "<<" {
				return fmt.Errorf("YAML merge keys are prohibited")
			}
			if _, ok := seen[key.Value]; ok {
				return fmt.Errorf("duplicate YAML mapping key %q", key.Value)
			}
			seen[key.Value] = struct{}{}
		}
	}
	for _, child := range node.Content {
		if err := inspectNode(child); err != nil {
			return err
		}
	}
	return nil
}

func allowedYAMLTag(tag string) bool {
	switch tag {
	case "", "!!map", "!!seq", "!!str", "!!int", "!!bool", "!!null":
		return true
	default:
		return false
	}
}
