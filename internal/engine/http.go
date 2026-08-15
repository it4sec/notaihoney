package engine

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
)

func readRequest(reader *bufio.Reader) (*http.Request, error) {
	return http.ReadRequest(reader)
}

// rawPathFromTarget extracts the raw path bytes from the already parsed
// RequestURI without path cleaning, unescaping, or proxy behavior.
func rawPathFromTarget(target string) string {
	if target == "*" {
		return "*"
	}
	if strings.HasPrefix(target, "/") {
		if i := strings.IndexByte(target, '?'); i >= 0 {
			return target[:i]
		}
		return target
	}
	if scheme := strings.Index(target, "://"); scheme >= 0 {
		rest := target[scheme+3:]
		endAuthority := len(rest)
		for i, r := range rest {
			if r == '/' || r == '?' {
				endAuthority = i
				break
			}
		}
		if endAuthority == len(rest) || rest[endAuthority] == '?' {
			return ""
		}
		path := rest[endAuthority:]
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
		return path
	}
	// Authority-form (CONNECT) and other non-origin targets deliberately do
	// not become a normalized path.
	return ""
}

func supportedPlainHTTP(req *http.Request) bool {
	return req.ProtoMajor == 1 && (req.ProtoMinor == 0 || req.ProtoMinor == 1)
}

func supportedHTTPSHTTP(req *http.Request) bool {
	return req.ProtoMajor == 1 && req.ProtoMinor == 1
}

func expectMode(req *http.Request) (continueExpected bool, unsupported bool) {
	value := strings.TrimSpace(req.Header.Get("Expect"))
	if value == "" {
		return false, false
	}
	if strings.EqualFold(value, "100-continue") {
		return true, false
	}
	return false, true
}

func interimContinueBytes() []byte {
	return []byte("HTTP/1.1 100 Continue\r\n\r\n")
}

func requestProtocol(req *http.Request) string {
	return fmt.Sprintf("HTTP/%d.%d", req.ProtoMajor, req.ProtoMinor)
}
