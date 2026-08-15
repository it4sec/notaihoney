package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"

	"notaihoney/internal/capture"
	"notaihoney/internal/config"
	"notaihoney/internal/engine"
	indexer "notaihoney/internal/index"
)

var (
	applicationVersion = "dev"
	buildID            = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "serve":
		path, err := parseConfigOnly("serve", args[1:])
		if err != nil {
			return err
		}
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return engine.Run(ctx, cfg, engine.BuildInfo{ApplicationVersion: applicationVersion, BuildID: buildID})
	case "capture":
		path, err := parseConfigOnly("capture", args[1:])
		if err != nil {
			return err
		}
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return capture.Run(ctx, cfg)
	case "check":
		return runCheck(args[1:])
	case "index":
		path, err := parseConfigOnly("index", args[1:])
		if err != nil {
			return err
		}
		cfg, err := config.Load(path)
		if err != nil {
			return err
		}
		return indexer.Run(cfg)
	default:
		return usageError()
	}
}

func parseConfigOnly(name string, args []string) (string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "/etc/notaihoney/honeypot.yaml", "path to honeypot YAML")
	if err := fs.Parse(args); err != nil {
		return "", err
	}
	if fs.NArg() != 0 {
		return "", fmt.Errorf("unexpected positional arguments")
	}
	return *configPath, nil
}

func runCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "/etc/notaihoney/honeypot.yaml", "path to honeypot YAML")
	emitListeners := fs.String("emit-listeners", "", "emit validated listeners; supported value: json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	if *emitListeners != "" {
		if *emitListeners != "json" {
			return fmt.Errorf("unsupported --emit-listeners value %q", *emitListeners)
		}
		return emitListenerJSON(cfg)
	}

	fmt.Println("schema: PASS")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var operationalErrors []error
	if err := engine.CheckOperational(ctx, cfg); err != nil {
		fmt.Println("serve_operational: FAIL")
		fmt.Fprintf(os.Stderr, "serve operational: %v\n", err)
		operationalErrors = append(operationalErrors, err)
	} else {
		fmt.Println("serve_operational: PASS")
	}
	if err := capture.CheckOperational(cfg); err != nil {
		fmt.Println("capture_operational: FAIL")
		fmt.Fprintf(os.Stderr, "capture operational: %v\n", err)
		operationalErrors = append(operationalErrors, err)
	} else {
		fmt.Println("capture_operational: NOT_CHECKED")
		fmt.Fprintln(os.Stderr, "capture operational: static prerequisites passed; dumpcap initialization is checked by capture mode")
	}
	fmt.Printf("config_sha256: %s\n", cfg.ConfigSHA256)
	if len(operationalErrors) != 0 {
		return fmt.Errorf("check operational prerequisites failed: %w", errors.Join(operationalErrors...))
	}
	return nil
}

type listenerJSON struct {
	ServiceID string `json:"service_id"`
	Address   string `json:"address"`
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
}

type listenerExport struct {
	ConfigSHA256 string         `json:"config_sha256"`
	Listeners    []listenerJSON `json:"listeners"`
}

func emitListenerJSON(cfg *config.Config) error {
	ids := make([]string, 0, len(cfg.Services))
	for id, service := range cfg.Services {
		if service.Enabled {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	export := listenerExport{ConfigSHA256: cfg.ConfigSHA256, Listeners: make([]listenerJSON, 0, len(ids))}
	for _, id := range ids {
		listener := cfg.Services[id].Listener
		export.Listeners = append(export.Listeners, listenerJSON{ServiceID: id, Address: listener.Address, Port: listener.Port, Protocol: listener.Protocol})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(export)
}

func usageError() error {
	return errors.New("usage: notaihoney <serve|capture|check|index> --config <path>")
}
