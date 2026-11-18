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
var attribute = regexp.MustCompile(`(?is)([a-z_][a-z0-9_-]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))`)
var disabledAttr = regexp.MustCompile(`(?i)(?:^|\s)disabled(?:\s|=|>|/)`)

func isCASChallengeField(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "captcha", "captcharesponse", "j_captcha_response", "captcha_code", "vcode", "verifycode", "validatecode",
		"otp", "totp", "mfa", "smscode", "dynamiccode", "authcode":
		return true
	default:
		return false
	}
}

func parseLoginPage(body []byte) (ticket string, challenge bool) {
	if strings.Contains(string(body), "continueForm") {
		challenge = true
	}
	for _, tag := range inputTag.FindAll(body, -1) {
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
		if attrs["name"] == "execution" && ticket == "" {
			ticket = attrs["value"]
		}
		if !disabledAttr.Match(tag) && strings.ToLower(attrs["type"]) != "hidden" && isCASChallengeField(attrs["name"]) {
			challenge = true
		}
	}
	return ticket, challenge
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
	ticket, challenge := parseLoginPage(body)
	if challenge {
		return &Error{"login-page", status, ErrChallenge}
	}
	if ticket == "" {
		return ErrProtocol
	}
	form := url.Values{"username": {username}, "password": {password}, "execution": {ticket}, "type": {"username_password"}, "_eventId": {"submit"}, "submit": {"登录"}}
	body, headers, final, status, err := request(ctx, c.client, "login", "POST", c.sso+"/login", "application/x-www-form-urlencoded", "", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	postTicket, postChallenge := parseLoginPage(body)
	if postChallenge {
		// Preserve risk-acknowledgement, captcha, and MFA steps as challenges.
		// The caller must authorize interactive steps; a password alone does not imply consent.
		return &Error{"login", status, ErrChallenge}
	}
	if (status == 200 || status >= 400 && status < 500) && final.Path == "/login" && postTicket != "" {
		return &Error{"login", status, ErrCredentials}
	}
	portal, parseErr := url.Parse(headers.Get("Location"))
	portalRedirect := (status == http.StatusFound || status == http.StatusSeeOther) &&
		parseErr == nil && portal != nil &&
		(portal.Scheme == "http" || portal.Scheme == "https") &&
		portal.User == nil && portal.Fragment == "" &&
		strings.EqualFold(portal.Hostname(), "uc.buaa.edu.cn") &&
		(portal.Path == "" || strings.HasPrefix(portal.Path, "/"))
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
