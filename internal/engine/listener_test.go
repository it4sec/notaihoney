package engine

import (
	"net"
	"strconv"
	"testing"

	"notaihoney/internal/config"
)

func TestMultiBindRollback(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	cfg := &config.Config{
		Limits: config.LimitsConfig{MaxConnectionsPerService: 1},
		Services: map[string]config.Service{
			"a": {Enabled: true, Listener: &config.ListenerConfig{Address: "127.0.0.1", Port: port, Protocol: "http"}},
			"b": {Enabled: true, Listener: &config.ListenerConfig{Address: "127.0.0.1", Port: port, Protocol: "http"}},
		},
	}
	if listeners, err := bindConfiguredListeners(cfg); err == nil {
		closeListeners(listeners)
		t.Fatal("expected second bind failure")
	}
	again, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("first listener was not rolled back: %v", err)
	}
	_ = again.Close()
}

func TestGlobalAndServiceAdmissionCeilings(t *testing.T) {
	global := make(chan struct{}, 2)
	serviceA := make(chan struct{}, 1)
	serviceB := make(chan struct{}, 2)
	if !tryAcquireConnectionSlots(global, serviceA) {
		t.Fatal("first admission should succeed")
	}
	if tryAcquireConnectionSlots(global, serviceA) {
		t.Fatal("service ceiling should reject second admission")
	}
	if len(global) != 1 {
		t.Fatal("failed service acquisition must return the global slot")
	}
	if !tryAcquireConnectionSlots(global, serviceB) {
		t.Fatal("second global slot should be available to another service")
	}
	if tryAcquireConnectionSlots(global, serviceB) {
		t.Fatal("global ceiling should reject admission")
	}
}
