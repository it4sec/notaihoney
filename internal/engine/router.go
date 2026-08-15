package engine

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"notaihoney/internal/config"
	"notaihoney/internal/response"
)

type RouteState struct {
	counts map[string]int
}

func NewRouteState() *RouteState {
	return &RouteState{counts: make(map[string]int)}
}

type Selection struct {
	MatchedRoute   string
	Classification string
	Source         string
	Sequence       *int
	Plan           response.Plan
}

func SelectResponse(service *config.Service, method, rawPath string, state *RouteState, closeConnection bool) Selection {
	for i := range service.Routes {
		route := &service.Routes[i]
		if route.Method != method || route.Path != rawPath {
			continue
		}
		key := route.Method + "\x00" + route.Path
		state.counts[key]++
		ordinal := state.counts[key]
		var chosen *config.ResponseConfig
		var sequence *int
		for j := range route.Responses {
			candidate := &route.Responses[j]
			if !candidate.Sequence.Default && candidate.Sequence.Number == ordinal {
				chosen = candidate
				n := candidate.Sequence.Number
				sequence = &n
				break
			}
		}
		source := "route_sequence"
		if chosen == nil {
			for j := range route.Responses {
				if route.Responses[j].Sequence.Default {
					chosen = &route.Responses[j]
					break
				}
			}
			source = "route_default"
		}
		return Selection{
			MatchedRoute: route.Method + " " + route.Path,
			Classification: route.Classification,
			Source: source,
			Sequence: sequence,
			Plan: planFromResponse(service.DefaultHeaders, chosen, closeConnection),
		}
	}
	return Selection{
		Source: "service_default",
		Plan: planFromFallback(service.DefaultHeaders, service.DefaultResponse, closeConnection),
	}
}

func planFromResponse(defaults map[string]string, r *config.ResponseConfig, closeConnection bool) response.Plan {
	mode := r.ResponseMode
	if mode == "" {
		mode = "immediate"
	}
	plan := response.Plan{
		Status: r.Status,
		Headers: mergeHeaders(defaults, r.Headers),
		Mode: mode,
		Delay: time.Duration(r.DelayMS) * time.Millisecond,
		Close: closeConnection,
	}
	if r.Body != nil {
		plan.Body = []byte(*r.Body)
	}
	for _, chunk := range r.Chunks {
		body := []byte(nil)
		if chunk.Body != nil {
			body = []byte(*chunk.Body)
		}
		plan.Chunks = append(plan.Chunks, response.Chunk{Delay: time.Duration(chunk.DelayMS) * time.Millisecond, Body: body})
	}
	return plan
}

func planFromFallback(defaults map[string]string, r *config.FallbackResponse, closeConnection bool) response.Plan {
	plan := response.Plan{
		Status: r.Status,
		Headers: mergeHeaders(defaults, r.Headers),
		Mode: "immediate",
		Delay: time.Duration(r.DelayMS) * time.Millisecond,
		Close: closeConnection,
	}
	if r.Body != nil {
		plan.Body = []byte(*r.Body)
	}
	return plan
}

func mergeHeaders(defaults, overrides map[string]string) map[string]string {
	result := make(map[string]string, len(defaults)+len(overrides))
	canonicalKeys := make(map[string]string)
	keys := make([]string, 0, len(defaults))
	for key := range defaults {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		canonical := http.CanonicalHeaderKey(key)
		result[canonical] = defaults[key]
		canonicalKeys[strings.ToLower(canonical)] = canonical
	}
	keys = keys[:0]
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		canonical := http.CanonicalHeaderKey(key)
		lower := strings.ToLower(canonical)
		if old, ok := canonicalKeys[lower]; ok && old != canonical {
			delete(result, old)
		}
		result[canonical] = overrides[key]
		canonicalKeys[lower] = canonical
	}
	return result
}
