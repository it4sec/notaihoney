package engine

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"notaihoney/internal/config"
)

type TLSMetadata struct {
	Enabled           bool
	CertificateSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
}

func LoadTLS(cfg *config.Config) (*tls.Config, TLSMetadata, error) {
	if !config.HasHTTPS(cfg) {
		return nil, TLSMetadata{}, nil
	}
	directory := cfg.Global.TLS.Directory
	certPath := filepath.Join(directory, "server.crt")
	keyPath := filepath.Join(directory, "server.key")
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, TLSMetadata{}, fmt.Errorf("TLS_KEYPAIR_LOAD_FAILED directory=%s: %w", directory, err)
	}
	if len(pair.Certificate) == 0 {
		return nil, TLSMetadata{}, fmt.Errorf("TLS_KEYPAIR_LOAD_FAILED certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, TLSMetadata{}, fmt.Errorf("TLS_KEYPAIR_LOAD_FAILED parse leaf: %w", err)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, TLSMetadata{}, fmt.Errorf("TLS_CERTIFICATE_NOT_YET_VALID not_before=%s", leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(leaf.NotAfter) {
		return nil, TLSMetadata{}, fmt.Errorf("TLS_CERTIFICATE_EXPIRED not_after=%s", leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	sum := sha256.Sum256(pair.Certificate[0])
	metadata := TLSMetadata{
		Enabled:           true,
		CertificateSHA256: hex.EncodeToString(sum[:]),
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
	}
	return &tls.Config{
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
		ClientAuth:   tls.NoClientCert,
	}, metadata, nil
}

func handshakeTLS(ctx context.Context, raw net.Conn, tlsConfig *tls.Config, timeout time.Duration) (*tls.Conn, time.Duration, error) {
	started := time.Now()
	if err := raw.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, 0, err
	}
	conn := tls.Server(raw, tlsConfig)
	err := conn.HandshakeContext(ctx)
	elapsed := time.Since(started)
	if clearErr := raw.SetDeadline(time.Time{}); err == nil && clearErr != nil {
		err = clearErr
	}
	if err != nil {
		return nil, elapsed, err
	}
	state := conn.ConnectionState()
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
		return nil, elapsed, fmt.Errorf("unsupported ALPN")
	}
	return conn, elapsed, nil
}

func boundedTLSErrorCode(err error) string {
	if err == nil {
		return ""
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return "handshake_timeout"
	}
	text := strings.ToLower(err.Error())
	if strings.Contains(text, "protocol version") {
		return "protocol_version"
	}
	if strings.Contains(text, "alpn") {
		return "alpn_rejected"
	}
	return "handshake_failed"
}
