package bhpan

import (
	"context"
	"net/url"
)

func (c *Client) verifySession(ctx context.Context) error {
	base, _ := url.Parse(c.cloud + "/anyshare/")
	for _, cookie := range c.client.Jar.Cookies(base) {
		if cookie.Name == "client.oauth2_token" {
			c.token = cookie.Value
		}
	}
	if !textOK(c.token) {
		return ErrSession
	}
	var roots []Library
	if err := c.json(ctx, c.client, c.token, "login-verify", "GET", "/api/efast/v1/owned-doc-lib", nil, &roots); err != nil {
		return err
	}
	if len(roots) == 0 {
		return ErrProtocol
	}
	for _, root := range roots {
		if !textOK(root.ID) {
			return ErrProtocol
		}
	}
	return nil
}
