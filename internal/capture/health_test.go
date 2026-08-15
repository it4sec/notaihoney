package capture

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestHealthProtocolHashAndLeaseClosure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "capture.sock")
	server, err := StartHealthServer(ctx, path, "abc", "session")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireLease(ctx, path, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLease(ctx, path, "different"); err == nil {
		t.Fatal("expected config hash mismatch")
	}
	_ = server.Close()
	select {
	case <-lease.Lost():
	case <-time.After(time.Second):
		t.Fatal("lease loss was not detected")
	}
}
