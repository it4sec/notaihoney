package engine

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"notaihoney/internal/capture"
	"notaihoney/internal/config"
	"notaihoney/internal/evidence"
)

const runtimeDirectory = "/run/notaihoney"

type BuildInfo struct {
	ApplicationVersion string
	BuildID            string
}

type serverRuntime struct {
	cfg          *config.Config
	runSessionID evidence.ID
	bwj          *evidence.BWJWriter
	jsonl        *evidence.JSONLWriter
	tlsConfig    *tls.Config
	tlsMetadata  TLSMetadata
	globalSlots  chan struct{}
	fatalOnce    sync.Once
	fatalCh      chan error
	jsonlHealthy atomic.Bool
	activeMu     sync.Mutex
	active       map[net.Conn]struct{}
}

func Run(ctx context.Context, cfg *config.Config, build BuildInfo) error {
	if err := evidence.CheckWritable(cfg.Evidence.WireJournal.Directory); err != nil {
		return fmt.Errorf("BWJ_WRITE_FAILED path=%s: %w", cfg.Evidence.WireJournal.Directory, err)
	}
	if _, err := evidence.RequireFreeBytes(cfg.Evidence.WireJournal.Directory, cfg.Evidence.MinFreeBytes); err != nil {
		return err
	}
	if err := evidence.CheckWritable(cfg.Evidence.JSONL.Directory); err != nil {
		return fmt.Errorf("CONFIG_INVALID jsonl path=%s: %w", cfg.Evidence.JSONL.Directory, err)
	}
	if err := evidence.ValidateDirectory(runtimeDirectory); err != nil {
		return fmt.Errorf("CAPTURE_NOT_READY runtime_directory=%s: %w", runtimeDirectory, err)
	}

	tlsConfig, tlsMetadata, err := LoadTLS(cfg)
	if err != nil {
		return err
	}
	runSessionID, err := evidence.NewID()
	if err != nil {
		return fmt.Errorf("INTERNAL_FATAL run_session_id: %w", err)
	}
	bwj, err := evidence.NewBWJWriter(cfg.Evidence.WireJournal.Directory, runSessionID, cfg.Evidence.WireJournal.RotateSizeBytes, cfg.Evidence.WireJournal.RotateSeconds)
	if err != nil {
		return err
	}
	jsonl, err := evidence.NewJSONLWriter(cfg.Evidence.JSONL.Directory, runSessionID, cfg.Evidence.JSONL.RotateSizeBytes, cfg.Evidence.JSONL.RotateSeconds, cfg.Limits.MaxStructuredEventBytes)
	if err != nil {
		_ = bwj.Close()
		return fmt.Errorf("CONFIG_INVALID jsonl startup: %w", err)
	}

	rt := &serverRuntime{
		cfg:          cfg,
		runSessionID: runSessionID,
		bwj:          bwj,
		jsonl:        jsonl,
		tlsConfig:    tlsConfig,
		tlsMetadata:  tlsMetadata,
		globalSlots:  make(chan struct{}, cfg.Limits.MaxConnectionsTotal),
		fatalCh:      make(chan error, 1),
		active:       make(map[net.Conn]struct{}),
	}
	rt.jsonlHealthy.Store(true)

	startupEvent := evidence.Event{
		EventType:            "sensor_state",
		ApplicationVersion:   build.ApplicationVersion,
		GoVersion:            runtime.Version(),
		BuildID:              build.BuildID,
		TLSEnabled:           tlsMetadata.Enabled,
		TLSCertificateSHA256: tlsMetadata.CertificateSHA256,
	}
	if tlsMetadata.Enabled {
		startupEvent.TLSCertificateNotBefore = tlsMetadata.NotBefore.UTC().Format(time.RFC3339)
		startupEvent.TLSCertificateNotAfter = tlsMetadata.NotAfter.UTC().Format(time.RFC3339)
	}
	rt.decorateEvent(&startupEvent)
	if err := jsonl.WriteEvent(startupEvent); err != nil {
		_ = jsonl.Close()
		_ = bwj.Close()
		return fmt.Errorf("CONFIG_INVALID initial JSONL write: %w", err)
	}

	lease, err := capture.AcquireLease(ctx, capture.DefaultHealthSocket, cfg.ConfigSHA256)
	if err != nil {
		_ = jsonl.Close()
		_ = bwj.Close()
		return err
	}

	services, err := bindConfiguredListeners(cfg)
	if err != nil {
		_ = lease.Close()
		_ = jsonl.Close()
		_ = bwj.Close()
		return err
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for _, service := range services {
		wg.Add(1)
		go acceptLoop(runCtx, rt, service, &wg)
	}

	storageTicker := time.NewTicker(time.Second)
	defer storageTicker.Stop()
	var terminal error
selectLoop:
	for {
		select {
		case <-ctx.Done():
			break selectLoop
		case <-lease.Lost():
			if ctx.Err() == nil {
				terminal = fmt.Errorf("CAPTURE_LOST action=close_listeners")
			}
			break selectLoop
		case err := <-rt.fatalCh:
			terminal = err
			break selectLoop
		case <-storageTicker.C:
			if available, err := evidence.FreeBytes(cfg.Evidence.WireJournal.Directory); err != nil || available <= cfg.Evidence.MinFreeBytes {
				if err != nil {
					terminal = fmt.Errorf("EVIDENCE_STORAGE_LOW sink=bwj path=%s: %w", cfg.Evidence.WireJournal.Directory, err)
				} else {
					terminal = fmt.Errorf("EVIDENCE_STORAGE_LOW sink=bwj path=%s available_bytes=%d minimum_bytes=%d", cfg.Evidence.WireJournal.Directory, available, cfg.Evidence.MinFreeBytes)
				}
				break selectLoop
			}
		}
	}

	// Fatal and graceful shutdown both close public listeners first. There is
	// no same-process listener recovery state machine.
	closeListeners(services)
	cancel()
	rt.closeActiveConnections()
	wg.Wait()
	_ = lease.Close()

	if terminal != nil {
		rt.emit(evidence.Event{EventType: "operational_error", OperationalCode: errorCategory(terminal), OperationalAction: "process_exit"})
	}
	jsonlErr := jsonl.Close()
	bwjErr := bwj.Close()
	if terminal != nil {
		return terminal
	}
	if bwjErr != nil {
		return fmt.Errorf("BWJ_WRITE_FAILED shutdown: %w", bwjErr)
	}
	if jsonlErr != nil {
		log.Printf("JSONL_WRITE_FAILED action=shutdown error=%s", boundedErrorText(jsonlErr))
	}
	return nil
}

func (rt *serverRuntime) fail(err error) {
	if err == nil {
		return
	}
	rt.fatalOnce.Do(func() {
		select {
		case rt.fatalCh <- err:
		default:
		}
	})
}

func (rt *serverRuntime) decorateEvent(event *evidence.Event) {
	if event.TimestampNS == 0 {
		event.TimestampNS = time.Now().UnixNano()
	}
	event.SensorID = rt.cfg.Sensor.ID
	event.RunSessionID = evidence.FormatID(rt.runSessionID)
	event.ConfigSchemaVersion = rt.cfg.Version
	event.ConfigSHA256 = rt.cfg.ConfigSHA256
}

func (rt *serverRuntime) emit(event evidence.Event) {
	if !rt.jsonlHealthy.Load() {
		return
	}
	rt.decorateEvent(&event)
	if err := rt.jsonl.WriteEvent(event); err != nil {
		if rt.jsonlHealthy.CompareAndSwap(true, false) {
			log.Printf("JSONL_WRITE_FAILED action=continue_raw_evidence error=%s", boundedErrorText(err))
		}
	}
}

func (rt *serverRuntime) registerConnection(conn net.Conn) {
	rt.activeMu.Lock()
	rt.active[conn] = struct{}{}
	rt.activeMu.Unlock()
}

func (rt *serverRuntime) unregisterConnection(conn net.Conn) {
	rt.activeMu.Lock()
	delete(rt.active, conn)
	rt.activeMu.Unlock()
}

func (rt *serverRuntime) closeActiveConnections() {
	rt.activeMu.Lock()
	connections := make([]net.Conn, 0, len(rt.active))
	for conn := range rt.active {
		connections = append(connections, conn)
	}
	rt.activeMu.Unlock()
	for _, conn := range connections {
		_ = conn.Close()
	}
}

func errorCategory(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	for _, category := range []string{
		"CONFIG_INVALID", "CAPTURE_NOT_READY", "CAPTURE_CONFIG_MISMATCH", "CAPTURE_LOST",
		"LISTENER_BIND_FAILED", "BWJ_WRITE_FAILED", "EVIDENCE_STORAGE_LOW",
		"TLS_KEYPAIR_LOAD_FAILED", "TLS_CERTIFICATE_EXPIRED", "TLS_CERTIFICATE_NOT_YET_VALID",
		"TLS_HANDSHAKE_TIMEOUT", "INTERNAL_FATAL",
	} {
		if len(text) >= len(category) && text[:len(category)] == category {
			return category
		}
	}
	return "INTERNAL_FATAL"
}

// CheckOperational validates serve prerequisites without binding public
// listeners. It may open TLS material and acquire/close the capture lease.
func CheckOperational(ctx context.Context, cfg *config.Config) error {
	if err := evidence.CheckWritable(cfg.Evidence.WireJournal.Directory); err != nil {
		return fmt.Errorf("BWJ_WRITE_FAILED path=%s: %w", cfg.Evidence.WireJournal.Directory, err)
	}
	if _, err := evidence.RequireFreeBytes(cfg.Evidence.WireJournal.Directory, cfg.Evidence.MinFreeBytes); err != nil {
		return err
	}
	if err := evidence.CheckWritable(cfg.Evidence.JSONL.Directory); err != nil {
		return fmt.Errorf("CONFIG_INVALID jsonl path=%s: %w", cfg.Evidence.JSONL.Directory, err)
	}
	if err := evidence.ValidateDirectory(runtimeDirectory); err != nil {
		return fmt.Errorf("CAPTURE_NOT_READY runtime_directory=%s: %w", runtimeDirectory, err)
	}
	if _, _, err := LoadTLS(cfg); err != nil {
		return err
	}
	lease, err := capture.AcquireLease(ctx, capture.DefaultHealthSocket, cfg.ConfigSHA256)
	if err != nil {
		return err
	}
	return lease.Close()
}
