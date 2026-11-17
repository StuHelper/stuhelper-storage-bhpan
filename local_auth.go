package bhpan

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Public encryption key published by the provider's sign-in page. This is
// protocol material, not a service credential. Source is recorded in the spec.
const localPasswordKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4E+eiWRwffhRIPQYvlXU
jf0b3HqCmosiCxbFCYI/gdfDBhrTUzbt3fL3o/gRQQBEPf69vhJMFH2ZMtaJM6oh
E3yQef331liPVM0YvqMOgvoID+zDa1NIZFObSsjOKhvZtv9esO0REeiVEPKNc+Dp
6il3x7TV9VKGEv0+iriNjqv7TGAexo2jVtLm50iVKTju2qmCDG83SnVHzsiNj70M
iviqiLpgz72IxjF+xN4bRw8I5dD0GwwO8kDoJUGWgTds+VckCwdtZA65oui9Osk5
t1a4pg6Xu9+HFcEuqwJTDxATvGAz1/YW0oUisjM0ObKTRDVSfnTYeaBsN6L+M+8g
CwIDAQAB
-----END PUBLIC KEY-----`

var scriptTag = regexp.MustCompile(`(?is)<script\b([^>]*)>(.*?)</script>`)

func resolveLocalPublicKey(override string) (*rsa.PublicKey, error) {
	if override == "" {
		key, err := parseLocalPublicKey(localPasswordKey)
		if err != nil {
			return nil, ErrProtocol
		}
		return key, nil
	}
	return parseLocalPublicKey(override)
}

func parseLocalPublicKey(raw string) (*rsa.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	block, rest := pem.Decode([]byte(trimmed))
	if block == nil || len(bytes.TrimSpace(rest)) != 0 || block.Type != "PUBLIC KEY" {
		return nil, ErrInput
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, ErrInput
	}
	rsaKey, ok := parsed.(*rsa.PublicKey)
	if !ok || rsaKey.N == nil || rsaKey.N.BitLen() < 2048 || rsaKey.E < 3 {
		return nil, ErrInput
	}
	return rsaKey, nil
}

func extractNextData(body []byte) ([]byte, bool) {
	for _, m := range scriptTag.FindAllSubmatch(body, -1) {
		attrs := map[string]string{}
		for _, a := range attribute.FindAllSubmatch(m[1], -1) {
			value := string(a[2])
			if value == "" {
				value = string(a[3])
			}
			attrs[strings.ToLower(string(a[1]))] = html.UnescapeString(value)
		}
		if attrs["id"] == "__NEXT_DATA__" {
			return m[2], true
		}
	}
	return nil, false
}

// LoginLocal authenticates a cloud-local account. It is never used as a fallback
// for a failed CAS login; credentials are only sent to the selected authority.
func (c *Client) LoginLocal(ctx context.Context, username, password string) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reset()
	defer func() {
		if err != nil {
			c.reset()
		}
	}()
	key := c.localKey
	if key == nil {
		return ErrProtocol
	}
	maxPassword := key.Size() - 11
	if maxPassword > 1024 {
		maxPassword = 1024
	}
	if !textOK(username) || len(username) > 128 || password == "" || len(password) > maxPassword {
		return ErrInput
	}
	body, _, final, status, err := request(ctx, c.client, "local-login-page", "GET", c.cloud+"/anyshare/oauth2/login?redirect=%2Fanyshare%2Fzh-cn%2Fportal", "", "", nil)
	if err != nil {
		return err
	}
	if err = statusError("local-login-page", status); err != nil {
		return err
	}
	if originOf(final) != c.cloud || final.Path != "/oauth2/signin" {
		return ErrProtocol
	}
	scriptPayload, ok := extractNextData(body)
	if !ok {
		return ErrProtocol
	}
	var page struct {
		Props struct {
			PageProps struct {
				Challenge string          `json:"challenge"`
				CSRF      string          `json:"csrftoken"`
				Device    json.RawMessage `json:"device"`
				Auth      struct {
					Captcha struct {
						Enabled bool `json:"isenable"`
						After   int  `json:"passwderrcnt"`
					} `json:"vcode_login_config"`
					Factors map[string]bool `json:"dualfactor_auth_server_status"`
				} `json:"authconfig"`
			} `json:"pageProps"`
		} `json:"props"`
	}
	if json.Unmarshal(scriptPayload, &page) != nil {
		return ErrProtocol
	}
	p := page.Props.PageProps
	if !textOK(p.Challenge) || p.Challenge != final.Query().Get("login_challenge") || !textOK(p.CSRF) || len(p.Device) == 0 {
		return ErrProtocol
	}
	if p.Auth.Captcha.Enabled && p.Auth.Captcha.After == 0 {
		return ErrChallenge
	}
	for _, enabled := range p.Auth.Factors {
		if enabled {
			return ErrChallenge
		}
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, key, []byte(password))
	if err != nil {
		return ErrInput
	}
	payload := map[string]any{"_csrf": p.CSRF, "challenge": p.Challenge, "account": username, "password": base64.StdEncoding.EncodeToString(encrypted), "remember": false, "device": p.Device, "vcode": map[string]string{"id": "", "content": ""}, "dualfactorauthinfo": map[string]any{"validcode": map[string]string{"vcode": ""}, "OTP": map[string]string{"OTP": ""}}}
	encoded, _ := json.Marshal(payload)
	local := *c.client
	local.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	body, _, _, status, err = request(ctx, &local, "local-login", "POST", c.cloud+"/oauth2/signin", "application/json", "", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	if status == 400 || status == 401 || status == 403 {
		return ErrCredentials
	}
	if err = statusError("local-login", status); err != nil {
		return err
	}
	var reply struct {
		Redirect string `json:"redirect"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.Redirect == "" {
		return ErrProtocol
	}
	dest, e := url.Parse(reply.Redirect)
	if e != nil || dest.User != nil || originOf(dest) != c.cloud || dest.Fragment != "" {
		return ErrDestination
	}
	_, _, final, status, err = request(ctx, c.client, "local-callback", "GET", dest.String(), "", "", nil)
	if err != nil {
		return err
	}
	if err = statusError("local-callback", status); err != nil {
		return err
	}
	if originOf(final) != c.cloud || final.Path != "/anyshare/oauth2/login/callback" {
		return ErrSession
	}
	return c.verifySession(ctx)
}
