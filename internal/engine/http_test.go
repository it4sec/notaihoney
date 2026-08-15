package engine

import (
	"bufio"
	"net/http"
	"strings"
	"testing"
)

func TestRawPathFromTarget(t *testing.T) {
	cases := map[string]string{
		"/a/%2f/b?x=1": "/a/%2f/b",
		"http://example.invalid/a/../b?x=1": "/a/../b",
		"http://example.invalid?x=1": "",
		"example.invalid:443": "",
		"*": "*",
	}
	for input, want := range cases {
		if got := rawPathFromTarget(input); got != want {
			t.Errorf("rawPathFromTarget(%q)=%q want %q", input, got, want)
		}
	}
}

func TestPinnedGoParserHTTP10HTTP11AndPipelining(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(
		"GET /one HTTP/1.0\r\n\r\n" +
			"GET /two HTTP/1.1\r\nHost: example\r\n\r\n"))
	first, err := readRequest(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !supportedPlainHTTP(first) || first.ProtoMinor != 0 || first.RequestURI != "/one" {
		t.Fatalf("unexpected first request: %#v", first)
	}
	second, err := readRequest(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !supportedPlainHTTP(second) || second.ProtoMinor != 1 || second.RequestURI != "/two" {
		t.Fatalf("unexpected second request: %#v", second)
	}
}

func TestHTTPSVersionAndExpectPolicy(t *testing.T) {
	h10 := &http.Request{ProtoMajor: 1, ProtoMinor: 0}
	h11 := &http.Request{ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header)}
	if supportedHTTPSHTTP(h10) || !supportedHTTPSHTTP(h11) {
		t.Fatal("HTTPS must accept application HTTP/1.1 only")
	}
	h11.Header.Set("Expect", "100-continue")
	cont, unsupported := expectMode(h11)
	if !cont || unsupported {
		t.Fatal("100-continue must be supported generically")
	}
	h11.Header.Set("Expect", "something-else")
	if cont, unsupported := expectMode(h11); cont || !unsupported {
		t.Fatal("unsupported expectation must be rejected")
	}
}
