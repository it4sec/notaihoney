package capture

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"notaihoney/internal/config"
	"notaihoney/internal/evidence"
)

const dumpcapPath = "/usr/bin/dumpcap"

func CaptureFilter(cfg *config.Config) string {
	portsSet := make(map[int]struct{})
	for _, service := range cfg.Services {
		if service.Enabled && service.Listener != nil {
			portsSet[service.Listener.Port] = struct{}{}
		}
	}
	ports := make([]int, 0, len(portsSet))
	for port := range portsSet {
		ports = append(ports, port)
	}
	sort.Ints(ports)
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, "port "+strconv.Itoa(port))
	}
	if len(parts) == 1 {
		return "tcp and " + parts[0]
	}
	return "tcp and (" + strings.Join(parts, " or ") + ")"
}

func Run(ctx context.Context, cfg *config.Config) error {
	if _, err := net.InterfaceByName(cfg.Evidence.PCAP.Interface); err != nil {
		return fmt.Errorf("CONFIG_INVALID capture_interface=%s: %w", cfg.Evidence.PCAP.Interface, err)
	}
	if err := evidence.CheckWritable(cfg.Evidence.PCAP.Directory); err != nil {
		return fmt.Errorf("CONFIG_INVALID pcap_directory=%s: %w", cfg.Evidence.PCAP.Directory, err)
	}
	if _, err := evidence.RequireFreeBytes(cfg.Evidence.PCAP.Directory, cfg.Evidence.MinFreeBytes); err != nil {
		return err
	}
	if _, err := os.Stat(dumpcapPath); err != nil {
		return fmt.Errorf("INTERNAL_FATAL dumpcap_path=%s: %w", dumpcapPath, err)
	}
	filter := CaptureFilter(cfg)
	if filter == "tcp and ()" {
		return fmt.Errorf("CONFIG_INVALID no enabled capture listeners")
	}

	captureID, err := evidence.NewID()
	if err != nil {
		return fmt.Errorf("INTERNAL_FATAL capture_session_id: %w", err)
	}
	captureIDText := evidence.FormatID(captureID)
	baseOutput := filepath.Join(cfg.Evidence.PCAP.Directory, "pcap_"+captureIDText+".pcapng")
	rotateKB := (cfg.Evidence.PCAP.RotateSizeBytes + 1023) / 1024
	args := []string{
		"-q",
		"-i", cfg.Evidence.PCAP.Interface,
		"-f", filter,
		"-w", baseOutput,
		"-b", "filesize:" + strconv.FormatInt(rotateKB, 10),
		"-b", "duration:" + strconv.Itoa(cfg.Evidence.PCAP.RotateSeconds),
	}
	// Cancellation is supervised below so controlled shutdown can first close
	// READY leases and then ask dumpcap to terminate cleanly before escalation.
	cmd := exec.Command(dumpcapPath, args...)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("INTERNAL_FATAL dumpcap_start: %w", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	if err := waitForPCAPReady(ctx, cfg.Evidence.PCAP.Directory, captureIDText, waitCh); err != nil {
		stopDumpcap(cmd, waitCh)
		return err
	}
	if _, err := evidence.RequireFreeBytes(cfg.Evidence.PCAP.Directory, cfg.Evidence.MinFreeBytes); err != nil {
		stopDumpcap(cmd, waitCh)
		return err
	}

	health, err := StartHealthServer(ctx, DefaultHealthSocket, cfg.ConfigSHA256, captureIDText)
	if err != nil {
		stopDumpcap(cmd, waitCh)
		return fmt.Errorf("INTERNAL_FATAL capture_health: %w", err)
	}
	defer health.Close()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			health.Close()
			stopDumpcap(cmd, waitCh)
			return nil
		case err := <-waitCh:
			health.Close()
			if err == nil {
				return fmt.Errorf("INTERNAL_FATAL dumpcap exited unexpectedly")
			}
			return fmt.Errorf("INTERNAL_FATAL dumpcap exited: %w", err)
		case <-ticker.C:
			available, err := evidence.FreeBytes(cfg.Evidence.PCAP.Directory)
			if err != nil || available <= cfg.Evidence.MinFreeBytes {
				health.Close()
				stopDumpcap(cmd, waitCh)
				if err != nil {
					return fmt.Errorf("EVIDENCE_STORAGE_LOW sink=pcap path=%s: %w", cfg.Evidence.PCAP.Directory, err)
				}
				return fmt.Errorf("EVIDENCE_STORAGE_LOW sink=pcap path=%s available_bytes=%d minimum_bytes=%d", cfg.Evidence.PCAP.Directory, available, cfg.Evidence.MinFreeBytes)
			}
		}
	}
}

func stopDumpcap(cmd *exec.Cmd, waitCh <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-waitCh:
		return
	case <-time.After(2 * time.Second):
	}
	_ = cmd.Process.Kill()
	select {
	case <-waitCh:
	case <-time.After(2 * time.Second):
	}
}

func waitForPCAPReady(ctx context.Context, directory, captureSessionID string, waitCh <-chan error) error {
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	pattern := filepath.Join(directory, "pcap_"+captureSessionID+"*.pcapng")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-waitCh:
			if err == nil {
				return fmt.Errorf("INTERNAL_FATAL dumpcap exited before READY")
			}
			return fmt.Errorf("INTERNAL_FATAL dumpcap failed before READY: %w", err)
		case <-deadline.C:
			return fmt.Errorf("CAPTURE_NOT_READY dumpcap did not open PCAP output")
		case <-ticker.C:
			matches, err := filepath.Glob(pattern)
			if err != nil {
				return fmt.Errorf("INTERNAL_FATAL pcap readiness pattern: %w", err)
			}
			for _, output := range matches {
				info, err := os.Stat(output)
				if err == nil && !info.IsDir() {
					return nil
				}
			}
		}
	}
}

// CheckOperational validates capture prerequisites that can be checked without
// starting dumpcap. Full interface/filter/output readiness is established only
// by Run before the health socket becomes READY.
func CheckOperational(cfg *config.Config) error {
	if _, err := net.InterfaceByName(cfg.Evidence.PCAP.Interface); err != nil {
		return fmt.Errorf("CONFIG_INVALID capture_interface=%s: %w", cfg.Evidence.PCAP.Interface, err)
	}
	if err := evidence.CheckWritable(cfg.Evidence.PCAP.Directory); err != nil {
		return fmt.Errorf("CONFIG_INVALID pcap_directory=%s: %w", cfg.Evidence.PCAP.Directory, err)
	}
	if _, err := evidence.RequireFreeBytes(cfg.Evidence.PCAP.Directory, cfg.Evidence.MinFreeBytes); err != nil {
		return err
	}
	if _, err := os.Stat(dumpcapPath); err != nil {
		return fmt.Errorf("INTERNAL_FATAL dumpcap_path=%s: %w", dumpcapPath, err)
	}
	if CaptureFilter(cfg) == "tcp and ()" {
		return fmt.Errorf("CONFIG_INVALID no enabled capture listeners")
	}
	return nil
}
