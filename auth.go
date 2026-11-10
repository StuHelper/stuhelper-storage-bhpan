package bhpan

import (
	"context"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var inputTag = regexp.MustCompile(`(?is)<input\b[^>]*>`)
var attribute = regexp.MustCompile(`(?is)([a-z_][a-z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')`)

func execution(body []byte) string {
	for _, tag := range inputTag.FindAll(body, -1) {
		attrs := map[string]string{}
		for _, a := range attribute.FindAllSubmatch(tag, -1) {
			value := string(a[2])
			if value == "" {
				value = string(a[3])
			}
			attrs[strings.ToLower(string(a[1]))] = html.UnescapeString(value)
		}
		if attrs["name"] == "execution" {
			return attrs["value"]
		}
	}
	return ""
}

// Login uses BUAA CAS and AnyShare OAuth. A failed login always discards the
// previous session. No automatic retry or password retention occurs.
func (c *Client) Login(ctx context.Context, username, password string) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reset()
	defer func() {
		if err != nil {
			c.reset()
		}
	}()
	if !textOK(username) || len(username) > 128 || password == "" || len(password) > 1024 {
		return ErrInput
	}
	body, _, _, status, err := request(ctx, c.client, "login-page", "GET", c.sso+"/login", "", "", nil)
	if err != nil {
		return err
	}
	if err = statusError("login-page", status); err != nil {
		return err
	}
	ticket := execution(body)
	if ticket == "" {
		return ErrProtocol
	}
	form := url.Values{"username": {username}, "password": {password}, "execution": {ticket}, "type": {"username_password"}, "_eventId": {"submit"}, "submit": {"登录"}}
	body, headers, final, status, err := request(ctx, c.client, "login", "POST", c.sso+"/login", "application/x-www-form-urlencoded", "", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	if strings.Contains(string(body), "continueForm") {
		// Preserve the provider's explicit risk-acknowledgement step as a challenge.
		// The caller must authorize it; a password alone does not imply consent.
		return ErrChallenge
	}
	if (status == 200 || status >= 400 && status < 500) && final.Path == "/login" && execution(body) != "" {
		return ErrCredentials
	}
	portal, _ := url.Parse(headers.Get("Location"))
	portalRedirect := status == http.StatusFound && portal != nil && portal.Hostname() == "uc.buaa.edu.cn" && portal.Path == "/"
	if !portalRedirect {
		if err = statusError("login", status); err != nil {
			return err
		}
	}
	_, _, final, status, err = request(ctx, c.client, "oauth", "GET", c.cloud+"/anyshare/oauth2/login?redirect=%2Fanyshare%2Fzh-cn%2Fportal", "", "", nil)
	if err != nil {
		return err
	}
	if err = statusError("oauth", status); err != nil {
		return err
	}
	if originOf(final) != c.cloud {
		return ErrSession
	}
	switch final.Path {
	case "/oauth2/signin":
		challenge := final.Query().Get("login_challenge")
		if !textOK(challenge) {
			return ErrProtocol
		}
		base, _ := url.Parse(c.cloud)
		c.client.Jar.SetCookies(base, []*http.Cookie{{Name: "login_challenge", Value: challenge, Path: "/", Secure: true}})
		_, _, final, status, err = request(ctx, c.client, "oauth-callback", "GET", c.sso+"/login?"+url.Values{"service": {c.cloud + "/oauth2/signin"}}.Encode(), "", "", nil)
		c.client.Jar.SetCookies(base, []*http.Cookie{{Name: "login_challenge", Value: "", Path: "/", Secure: true, MaxAge: -1}})
		if err != nil {
			return err
		}
		if err = statusError("oauth-callback", status); err != nil {
			return err
		}
		if originOf(final) != c.cloud || final.Path != "/anyshare/oauth2/login/callback" {
			return ErrSession
		}
	case "/anyshare/oauth2/login/callback":
		_, _, _, status, err = request(ctx, c.client, "oauth-refresh", "GET", c.cloud+"/anyshare/oauth2/login/refreshToken", "", "", nil)
		if err != nil {
			return err
		}
		if err = statusError("oauth-refresh", status); err != nil {
			return err
		}
	default:
		return ErrSession
	}
	return c.verifySession(ctx)
}

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
