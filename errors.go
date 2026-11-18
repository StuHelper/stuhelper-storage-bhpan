// Package bhpan implements the BUAA cloud-drive protocol for server-side callers.
package bhpan

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	ErrCredentials  = errors.New("bhpan: authentication rejected")
	ErrChallenge    = errors.New("bhpan: interactive authentication required")
	ErrSession      = errors.New("bhpan: session unavailable or expired")
	ErrGrantExpired = errors.New("bhpan: transfer grant expired")
	ErrInput        = errors.New("bhpan: invalid input")
	ErrProtocol     = errors.New("bhpan: invalid provider response")
	ErrDestination  = errors.New("bhpan: untrusted destination")
	ErrPermission   = errors.New("bhpan: permission denied")
	ErrNotFound     = errors.New("bhpan: item not found")
	ErrConflict     = errors.New("bhpan: item conflict")
	ErrRejected     = errors.New("bhpan: request rejected")
	ErrUnavailable  = errors.New("bhpan: provider unavailable")
)

// Error contains only an operation identifier, HTTP status, classified error
// kind, numeric provider subcode, and parsed Retry-After duration — never
// provider text messages, URLs, account names, cookies, or transport strings.
type Error struct {
	Operation    string
	Status       int
	Kind         error
	ProviderCode int
	RetryAfter   time.Duration
}

func (e *Error) Error() string {
	switch {
	case e.ProviderCode != 0 && e.RetryAfter > 0:
		return fmt.Sprintf("bhpan %s: %v (HTTP %d, code %d, retry_after %s)", e.Operation, e.Kind, e.Status, e.ProviderCode, e.RetryAfter)
	case e.ProviderCode != 0:
		return fmt.Sprintf("bhpan %s: %v (HTTP %d, code %d)", e.Operation, e.Kind, e.Status, e.ProviderCode)
	case e.RetryAfter > 0:
		return fmt.Sprintf("bhpan %s: %v (HTTP %d, retry_after %s)", e.Operation, e.Kind, e.Status, e.RetryAfter)
	default:
		return fmt.Sprintf("bhpan %s: %v (HTTP %d)", e.Operation, e.Kind, e.Status)
	}
}
func (e *Error) Unwrap() error { return e.Kind }

func extractProviderCode(body []byte) int {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return 0
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(trimmed, &envelope) != nil {
		return 0
	}
	for _, key := range []string{"code", "error_code"} {
		raw := bytes.TrimSpace(envelope[key])
		if len(raw) == 0 || strings.HasPrefix(string(raw), "+") {
			continue
		}
		v, err := strconv.ParseInt(string(raw), 10, 64)
		if err == nil && v != 0 && v >= math.MinInt && v <= math.MaxInt {
			return int(v)
		}
	}
	return 0
}

func parseRetryAfterAt(headers http.Header, now time.Time) time.Duration {
	if headers == nil {
		return 0
	}
	raw := strings.TrimSpace(headers.Get("Retry-After"))
	if raw == "" {
		return 0
	}
	if !strings.HasPrefix(raw, "+") {
		if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
			if secs <= 0 {
				return 0
			}
			const maxSeconds = math.MaxInt64 / int64(time.Second)
			if secs > maxSeconds {
				return time.Duration(maxSeconds) * time.Second
			}
			return time.Duration(secs) * time.Second
		}
	}
	if t, err := http.ParseTime(raw); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}
