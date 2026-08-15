package engine

import (
	"testing"

	"notaihoney/internal/config"
)

func strptr(s string) *string { return &s }

func TestExactRouteAndConnectionSequence(t *testing.T) {
	service := &config.Service{
		DefaultHeaders: map[string]string{"Content-Type": "text/plain"},
		Routes: []config.RouteConfig{{
			Method: "GET", Path: "/a/../b", Classification: "exact",
			Responses: []config.ResponseConfig{
				{Sequence: config.Sequence{Number: 1}, Status: 200, Body: strptr("first")},
				{Sequence: config.Sequence{Default: true}, Status: 200, Body: strptr("default")},
			},
		}},
		DefaultResponse: &config.FallbackResponse{Status: 404, Body: strptr("missing")},
	}
	state := NewRouteState()
	first := SelectResponse(service, "GET", "/a/../b", state, false)
	if first.Source != "route_sequence" || string(first.Plan.Body) != "first" {
		t.Fatalf("unexpected first selection: %#v", first)
	}
	second := SelectResponse(service, "GET", "/a/../b", state, false)
	if second.Source != "route_default" || string(second.Plan.Body) != "default" {
		t.Fatalf("unexpected second selection: %#v", second)
	}
	unmatched := SelectResponse(service, "GET", "/b", state, false)
	if unmatched.Source != "service_default" || unmatched.Plan.Status != 404 {
		t.Fatalf("path was normalized unexpectedly: %#v", unmatched)
	}
	fresh := SelectResponse(service, "GET", "/a/../b", NewRouteState(), false)
	if fresh.Source != "route_sequence" {
		t.Fatal("new TCP connection state did not reset sequence")
	}
}
