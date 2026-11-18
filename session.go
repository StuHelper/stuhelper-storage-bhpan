package bhpan

import (
	"context"
	"errors"
	"net/url"
	"strings"
)

// RefreshSession renews the active OAuth session cookie without requiring user
// credentials, updates the cached bearer token, and verifies access against the
// document-library endpoint. Expired sessions are cleared, while transient
// network or provider failures preserve existing state and original error kinds.
func (c *Client) RefreshSession(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !textOK(c.token) {
		return &Error{Operation: "session-refresh", Status: 0, Kind: ErrSession}
	}
	_, _, final, status, err := request(ctx, c.client, "session-refresh", "GET", c.cloud+"/anyshare/oauth2/login/refreshToken", "", "", nil)
	if err != nil {
		return err
	}
	if err = statusError("session-refresh", status); err != nil {
		if errors.Is(err, ErrSession) {
			c.reset()
		}
		return err
	}
	if final == nil || originOf(final) != c.cloud || final.Path == "/oauth2/signin" || strings.HasPrefix(final.Path, "/login") {
		c.reset()
		return &Error{Operation: "session-refresh", Status: status, Kind: ErrSession}
	}
	base, _ := url.Parse(c.cloud + "/anyshare/")
	var nextToken string
	for _, cookie := range c.client.Jar.Cookies(base) {
		if cookie.Name == "client.oauth2_token" {
			nextToken = cookie.Value
		}
	}
	if !textOK(nextToken) {
		c.reset()
		return &Error{Operation: "session-refresh", Status: status, Kind: ErrSession}
	}
	// The provider has already rotated its cookie. Keep bearer requests in sync
	// even when verification fails temporarily. A definite expiry resets both.
	c.token = nextToken
	var roots []Library
	if err := c.json(ctx, c.client, nextToken, "session-verify", "GET", "/api/efast/v1/owned-doc-lib", nil, &roots); err != nil {
		if errors.Is(err, ErrSession) {
			c.reset()
		}
		return err
	}
	if len(roots) == 0 {
		return &Error{Operation: "session-verify", Status: 200, Kind: ErrProtocol}
	}
	for _, root := range roots {
		if !textOK(root.ID) {
			return &Error{Operation: "session-verify", Status: 200, Kind: ErrProtocol}
		}
	}
	return nil
}
