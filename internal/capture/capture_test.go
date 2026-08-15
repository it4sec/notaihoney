package capture

import (
	"testing"

	"notaihoney/internal/config"
)

func TestCaptureFilterDerivedFromListeners(t *testing.T) {
	cfg := &config.Config{Services: map[string]config.Service{
		"b":        {Enabled: true, Listener: &config.ListenerConfig{Port: 9000}},
		"a":        {Enabled: true, Listener: &config.ListenerConfig{Port: 8000}},
		"disabled": {Enabled: false, Listener: &config.ListenerConfig{Port: 7000}},
	}}
	if got, want := CaptureFilter(cfg), "tcp and (port 8000 or port 9000)"; got != want {
		t.Fatalf("filter=%q want=%q", got, want)
	}
}
