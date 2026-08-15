package engine

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"

	"notaihoney/internal/config"
)

type serviceRuntime struct {
	id       string
	cfg      *config.Service
	listener net.Listener
	slots    chan struct{}
}

func bindConfiguredListeners(cfg *config.Config) ([]*serviceRuntime, error) {
	ids := make([]string, 0, len(cfg.Services))
	for id, service := range cfg.Services {
		if service.Enabled {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	bound := make([]*serviceRuntime, 0, len(ids))
	for _, id := range ids {
		service := &cfg.Services[id]
		address := net.JoinHostPort(service.Listener.Address, strconv.Itoa(service.Listener.Port))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			for _, prior := range bound {
				_ = prior.listener.Close()
			}
			return nil, fmt.Errorf("LISTENER_BIND_FAILED service_id=%s address=%s: %w", id, address, err)
		}
		bound = append(bound, &serviceRuntime{
			id: id,
			cfg: service,
			listener: listener,
			slots: make(chan struct{}, cfg.Limits.MaxConnectionsPerService),
		})
	}
	return bound, nil
}

func closeListeners(services []*serviceRuntime) {
	for _, service := range services {
		if service.listener != nil {
			_ = service.listener.Close()
		}
	}
}

func acceptLoop(ctx context.Context, rt *serverRuntime, service *serviceRuntime, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		conn, err := service.listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
			}
			rt.fail(fmt.Errorf("INTERNAL_FATAL service_id=%s accept: %w", service.id, err))
			return
		}

		// Both admission slots are charged immediately after Accept and before
		// TLS or HTTP processing. Admission is deliberately non-blocking.
		if !tryAcquireConnectionSlots(rt.globalSlots, service.slots) {
			_ = conn.Close()
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() {
				<-service.slots
				<-rt.globalSlots
			}()
			handleConnection(ctx, rt, service, conn)
		}()
	}
}

func tryAcquireConnectionSlots(global, service chan struct{}) bool {
	select {
	case global <- struct{}{}:
	default:
		return false
	}
	select {
	case service <- struct{}{}:
		return true
	default:
		<-global
		return false
	}
}
