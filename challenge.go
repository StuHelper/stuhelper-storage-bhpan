package bhpan

import (
	"errors"
	"fmt"
	"html"
	"strings"
)

// ChallengeKind classifies an interactive authentication step without retaining
// provider HTML, account identifiers, or session cookies.
type ChallengeKind string

const (
	ChallengeUnknown     ChallengeKind = ""
	ChallengeRiskConfirm ChallengeKind = "risk_confirm"
	ChallengeCaptcha     ChallengeKind = "captcha"
	ChallengeMFA         ChallengeKind = "mfa"
)

// LoginOptions carries explicit caller-verified consent flags for interactive
// authentication prompts that do not involve CAPTCHA or multi-factor gates.
type LoginOptions struct {
	// AcknowledgeRisk authorizes submitting BUAA CAS's anomalous-device /
	// unfamiliar-location risk confirmation prompt (continueForm) after the user
	// explicitly confirms the risk in the product UI.
	AcknowledgeRisk bool
}

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

func parseInputAttrs(body []byte) []map[string]string {
	tags := inputTag.FindAll(body, -1)
	out := make([]map[string]string, 0, len(tags))
	for _, tag := range tags {
		attrs := map[string]string{}
		for _, a := range attribute.FindAllSubmatch(tag, -1) {
			value := string(a[2])
			if value == "" {
				value = string(a[3])
			}
			if value == "" {
				value = string(a[4])
			}
			attrs[strings.ToLower(string(a[1]))] = html.UnescapeString(value)
		}
		out = append(out, attrs)
	}
	return out
}

func detectCASChallenge(body []byte) ChallengeKind {
	for _, attrs := range parseInputAttrs(body) {
		if _, disabled := attrs["disabled"]; disabled || strings.EqualFold(attrs["type"], "hidden") {
			continue
		}
		for _, field := range []string{attrs["name"], attrs["id"]} {
			switch strings.ToLower(strings.TrimSpace(field)) {
			case "captcha", "captcharesponse", "validatecode", "j_captcha_response", "ltcaptcha", "captcha_code", "vcode", "verifycode":
				return ChallengeCaptcha
			case "otp", "passcode", "smscode", "dynamiccode", "mfacode", "mfa", "authcode", "totp":
				return ChallengeMFA
			}
		}
	}
	if strings.Contains(string(body), "continueForm") {
		return ChallengeRiskConfirm
	}
	return ChallengeUnknown
}

func parseContinueEventID(body []byte) string {
	for _, attrs := range parseInputAttrs(body) {
		if attrs["name"] == "_eventId" && textOK(attrs["value"]) {
			return attrs["value"]
		}
	}
	return "ignoreAndContinue"
}
