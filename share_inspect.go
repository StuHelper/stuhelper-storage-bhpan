package bhpan

import (
	"context"
	"net/url"
	"strings"
)

// ShareInfo contains sanitized public metadata returned by the share preflight
// endpoint without authenticating or attaching personal session credentials.
type ShareInfo struct {
	ID               string `json:"id"`
	Title            string `json:"title,omitempty"`
	PasswordRequired bool   `json:"password_required"`
	ExpiresAt        string `json:"expires_at,omitempty"`
	LimitedTimes     int64  `json:"limited_times,omitempty"`
}

func validShareID(id string) bool {
	return textOK(id) && len(id) <= 512 && id != "." && id != ".." && !strings.ContainsAny(id, "%/\\;=\" \t")
}

// ParseShareURL extracts and validates the share identifier from a full share
// URL matching the default BHpan origin (https://bhpan.buaa.edu.cn).
func ParseShareURL(raw string) (string, error) {
	return parseShareURLForOrigin("https://bhpan.buaa.edu.cn", raw)
}

// ParseShareURL extracts and validates the share identifier from a full share
// URL matching this Client's configured CloudURL origin.
func (c *Client) ParseShareURL(raw string) (string, error) {
	return parseShareURLForOrigin(c.cloud, raw)
}

func parseShareURLForOrigin(cloudOrigin, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 || strings.ContainsAny(raw, "\r\n\x00") {
		return "", ErrInput
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", ErrInput
	}
	if u.Scheme != "https" || u.User != nil || originOf(u) != cloudOrigin {
		return "", ErrDestination
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", ErrInput
	}
	id, ok := strings.CutPrefix(u.EscapedPath(), "/link/")
	if !ok || !validShareID(id) {
		return "", ErrInput
	}
	return id, nil
}

// InspectShare fetches public metadata for an anonymous share without sending
// personal account tokens or cookies, allowing callers to verify existence,
// title, expiration, and whether an extraction password is required.
func (c *Client) InspectShare(ctx context.Context, id string) (ShareInfo, error) {
	if !validShareID(id) {
		return ShareInfo{}, ErrInput
	}
	hc := c.anonymousClient(nil)
	var wire struct {
		Protected    *bool  `json:"password_required"`
		Title        string `json:"title"`
		ExpiresAt    string `json:"expires_at"`
		LimitedTimes *int64 `json:"limited_times"`
	}
	if err := c.json(ctx, hc, "", "share-info", "GET", "/api/shared-link/v1/links/"+url.PathEscape(id), nil, &wire); err != nil {
		return ShareInfo{}, err
	}
	if wire.Protected == nil || len(wire.Title) > 4096 || strings.ContainsAny(wire.Title, "\r\n\x00") || len(wire.ExpiresAt) > 128 || strings.ContainsAny(wire.ExpiresAt, "\r\n\x00") {
		return ShareInfo{}, ErrProtocol
	}
	limit := int64(0)
	if wire.LimitedTimes != nil {
		if *wire.LimitedTimes < -1 {
			return ShareInfo{}, ErrProtocol
		}
		limit = *wire.LimitedTimes
	}
	return ShareInfo{
		ID:               id,
		Title:            wire.Title,
		PasswordRequired: *wire.Protected,
		ExpiresAt:        wire.ExpiresAt,
		LimitedTimes:     limit,
	}, nil
}
