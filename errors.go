// Package bhpan implements the BUAA cloud-drive protocol for server-side callers.
package bhpan

import (
	"errors"
	"fmt"
)

var (
	ErrCredentials = errors.New("bhpan: authentication rejected")
	ErrChallenge   = errors.New("bhpan: interactive authentication required")
	ErrSession     = errors.New("bhpan: session unavailable or expired")
	ErrInput       = errors.New("bhpan: invalid input")
	ErrProtocol    = errors.New("bhpan: invalid provider response")
	ErrDestination = errors.New("bhpan: untrusted destination")
	ErrPermission  = errors.New("bhpan: permission denied")
	ErrNotFound    = errors.New("bhpan: item not found")
	ErrConflict    = errors.New("bhpan: item conflict")
	ErrRejected    = errors.New("bhpan: request rejected")
	ErrUnavailable = errors.New("bhpan: provider unavailable")
)

// Error contains only an operation identifier and status, never provider payloads,
// URLs, account names, cookies or transport error strings.
type Error struct {
	Operation string
	Status    int
	Kind      error
}

func (e *Error) Error() string {
	return fmt.Sprintf("bhpan %s: %v (HTTP %d)", e.Operation, e.Kind, e.Status)
}
func (e *Error) Unwrap() error { return e.Kind }
