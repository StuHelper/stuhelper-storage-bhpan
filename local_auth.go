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
	"net/http"
	"net/url"
	"regexp"
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

var nextData = regexp.MustCompile(`(?s)<script\s+id="__NEXT_DATA__"[^>]*>(.*?)</script>`)

func hasChallengeValue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x != ""
	case map[string]any:
		if len(x) == 0 {
			return false
		}
		if en, ok := x["isenable"].(bool); ok {
			return en
		}
		for _, child := range x {
			if hasChallengeValue(child) {
				return true
			}
		}
	}
	return false
}

func mapHasChallenge(m map[string]any, captchaEnabled bool, captchaAfter int) bool {
	if m == nil {
		return false
	}
	for _, key := range []string{
		"vcode", "needvcode", "need_vcode",
		"dualfactorauthinfo", "OTP", "otp", "validcode", "enable_otp", "enable_dualfactor", "need_second_auth", "mfa",
	} {
		if hasChallengeValue(m[key]) {
			return true
		}
	}
	if captchaEnabled && captchaAfter > 0 {
		if cnt, ok := m["errcnt"].(float64); ok && int(cnt) >= captchaAfter {
			return true
		}
	}
	return false
}

func localSigninChallenge(body []byte, captchaEnabled bool, captchaAfter int) bool {
	var envelope map[string]any
	if json.Unmarshal(body, &envelope) != nil {
		return false
	}
	if code, ok := envelope["code"].(float64); ok {
		c := int64(code)
		if c == 401001002 || c == 401001003 || (c >= 401001030 && c <= 401001039) {
			return true
		}
	}
	if mapHasChallenge(envelope, captchaEnabled, captchaAfter) {
		return true
	}
	if detail, ok := envelope["detail"].(map[string]any); ok && mapHasChallenge(detail, captchaEnabled, captchaAfter) {
		return true
	}
	return false
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
	if !textOK(username) || len(username) > 128 || password == "" || len(password) > 245 {
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
	match := nextData.FindSubmatch(body)
	if len(match) != 2 {
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
	if json.Unmarshal(match[1], &page) != nil {
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
	block, _ := pem.Decode([]byte(localPasswordKey))
	if block == nil {
		return ErrProtocol
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return ErrProtocol
	}
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, key.(*rsa.PublicKey), []byte(password))
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
		if localSigninChallenge(body, p.Auth.Captcha.Enabled, p.Auth.Captcha.After) {
			return &Error{"local-login", status, ErrChallenge}
		}
		return &Error{"local-login", status, ErrCredentials}
	}
	if err = statusError("local-login", status); err != nil {
		return err
	}
	var reply struct {
		Redirect string `json:"redirect"`
	}
	if json.Unmarshal(body, &reply) != nil || reply.Redirect == "" {
		if localSigninChallenge(body, p.Auth.Captcha.Enabled, p.Auth.Captcha.After) {
			return &Error{"local-login", status, ErrChallenge}
		}
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
