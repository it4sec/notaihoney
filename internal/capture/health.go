package capture

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const DefaultHealthSocket = "/run/notaihoney/capture.sock"

type HealthServer struct {
	path      string
	hash      string
	sessionID string
	listener  net.Listener
	mu        sync.Mutex
	leases    map[net.Conn]struct{}
	closed    bool
}

func StartHealthServer(ctx context.Context, path, configSHA256, captureSessionID string) (*HealthServer, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("create capture runtime directory: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale capture socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen capture health socket: %w", err)
	}
	if err := os.Chmod(path, 0660); err != nil {
		listener.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("chmod capture health socket: %w", err)
	}
	s := &HealthServer{
		path:      path,
		hash:      configSHA256,
		sessionID: captureSessionID,
		listener:  listener,
		leases:    make(map[net.Conn]struct{}),
	}
	go s.acceptLoop(ctx)
	return s, nil
}

func (s *HealthServer) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleLease(ctx, conn)
	}
}

func (s *HealthServer) handleLease(ctx context.Context, conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.leases, conn)
		s.mu.Unlock()
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReaderSize(conn, 512)
	line, err := readHealthLine(reader)
	if err != nil || strings.TrimSpace(line) != "HEALTH" {
		return
	}
	if _, err := fmt.Fprintf(conn, "READY %s %s\n", s.hash, s.sessionID); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.leases[conn] = struct{}{}
	s.mu.Unlock()

	buf := make([]byte, 1)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

func (s *HealthServer) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	leases := make([]net.Conn, 0, len(s.leases))
	for conn := range s.leases {
		leases = append(leases, conn)
	}
	s.mu.Unlock()
	for _, conn := range leases {
		_ = conn.Close()
	}
	err := s.listener.Close()
	_ = os.Remove(s.path)
	return err
}

type Lease struct {
	conn      net.Conn
	lost      chan struct{}
	closeOnce sync.Once
}

func AcquireLease(ctx context.Context, path, expectedConfigSHA256 string) (*Lease, error) {
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, fmt.Errorf("CAPTURE_NOT_READY socket=%s: %w", path, err)
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := fmt.Fprint(conn, "HEALTH\n"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("CAPTURE_NOT_READY health request: %w", err)
	}
	reader := bufio.NewReaderSize(conn, 512)
	line, err := readHealthLine(reader)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("CAPTURE_NOT_READY health response: %w", err)
	}
	parts := strings.Fields(line)
	if len(parts) != 3 || parts[0] != "READY" {
		conn.Close()
		return nil, fmt.Errorf("CAPTURE_NOT_READY invalid health response")
	}
	if parts[1] != expectedConfigSHA256 {
		conn.Close()
		return nil, fmt.Errorf("CAPTURE_CONFIG_MISMATCH expected=%s actual=%s", expectedConfigSHA256, parts[1])
	}
	_ = conn.SetDeadline(time.Time{})
	lease := &Lease{conn: conn, lost: make(chan struct{})}
	go lease.watch(ctx, reader)
	return lease, nil
}

func readHealthLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return "", fmt.Errorf("health line exceeds 512 bytes")
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

func (l *Lease) watch(ctx context.Context, reader *bufio.Reader) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = reader.ReadByte()
	}()
	select {
	case <-ctx.Done():
		_ = l.Close()
	case <-done:
		l.closeOnce.Do(func() {
			close(l.lost)
			_ = l.conn.Close()
		})
	}
}

func (l *Lease) Lost() <-chan struct{} { return l.lost }

func (l *Lease) Close() error {
	var err error
	l.closeOnce.Do(func() {
		err = l.conn.Close()
		close(l.lost)
	})
	return err
}
