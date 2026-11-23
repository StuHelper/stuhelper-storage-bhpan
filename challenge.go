package bhpan

import (
	"errors"
	"fmt"
)

// ChallengeKind classifies an interactive authentication step without retaining
// provider HTML, account identifiers, or session cookies.
type ChallengeKind string

const (
	ChallengeUnknown ChallengeKind = ""
	ChallengeCaptcha ChallengeKind = "captcha"
	ChallengeMFA     ChallengeKind = "mfa"
)

// ChallengeError wraps an operational *Error whose Kind is ErrChallenge and
// records the sanitized interactive challenge category.
type ChallengeError struct {
	Err       *Error
	Challenge ChallengeKind
}

func (e *ChallengeError) Error() string {
	if e.Err == nil {
		if e.Challenge != "" {
			return fmt.Sprintf("%v [%s]", ErrChallenge, e.Challenge)
		}
		return ErrChallenge.Error()
	}
	if e.Challenge != "" {
		return fmt.Sprintf("%s [%s]", e.Err.Error(), e.Challenge)
	}
	return e.Err.Error()
}

func (e *ChallengeError) Unwrap() error {
	if e.Err != nil {
		return e.Err
	}
	return ErrChallenge
}

// ChallengeOf extracts the sanitized ChallengeKind when err wraps a
// *ChallengeError, or returns ChallengeUnknown otherwise.
func ChallengeOf(err error) ChallengeKind {
	var ce *ChallengeError
	if errors.As(err, &ce) {
		return ce.Challenge
	}
	return ChallengeUnknown
}

func challengeError(op string, status int, kind ChallengeKind) error {
	return &ChallengeError{
		Err:       &Error{Operation: op, Status: status, Kind: ErrChallenge},
		Challenge: kind,
	}
}
