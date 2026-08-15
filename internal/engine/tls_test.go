package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"notaihoney/internal/config"
)

func TestLoadTLSFixedPolicy(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server.key"), keyPEM, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Global: config.GlobalConfig{TLS: &config.TLSGlobalConfig{Directory: dir}},
		Services: map[string]config.Service{
			"s": {Enabled: true, Listener: &config.ListenerConfig{Protocol: "https"}},
		},
	}
	tlsCfg, meta, err := LoadTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg.MinVersion != 0x0303 || tlsCfg.MaxVersion != 0x0304 {
		t.Fatalf("unexpected TLS versions: %x..%x", tlsCfg.MinVersion, tlsCfg.MaxVersion)
	}
	if len(tlsCfg.NextProtos) != 1 || tlsCfg.NextProtos[0] != "http/1.1" || meta.CertificateSHA256 == "" {
		t.Fatal("TLS policy/metadata mismatch")
	}
}
