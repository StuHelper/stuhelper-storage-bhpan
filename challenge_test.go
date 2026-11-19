package bhpan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestChallengeClassificationAndRiskConfirmation(t *testing.T) {
	ctx := context.Background()

	// 1. SSO risk confirmation: denied without explicit authorization, completed when AcknowledgeRisk is true.
	t.Run("sso-risk-confirm", func(t *testing.T) {
		var cloud string
		var postCount atomic.Int32
		c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/login":
				if r.URL.Query().Get("service") != "" {
					http.Redirect(w, r, cloud+"/anyshare/oauth2/login/callback", http.StatusFound)
					return
				}
				if r.Method == http.MethodGet {
					fmt.Fprint(w, `<input name="execution" value="exec-1">`)
					return
				}
				check(t, r.ParseForm())
				n := postCount.Add(1)
				if r.Form.Get("_eventId") == "submit" {
					http.SetCookie(w, &http.Cookie{Name: "cas_pending", Value: "pending-cookie", Path: "/"})
					fmt.Fprint(w, `<form id="continueForm"><input type="hidden" name="execution" value="exec-risk-2"><input type="hidden" name="_eventId" value="ignoreAndContinue"></form>`)
					return
				}
				if r.Form.Get("execution") != "exec-risk-2" || r.Form.Get("_eventId") != "ignoreAndContinue" || r.Form.Get("password") != "" {
					t.Errorf("unexpected risk confirmation form (post %d): %v", n, r.Form)
				}
				http.SetCookie(w, &http.Cookie{Name: "sso", Value: "confirmed-session", Path: "/"})
				http.Redirect(w, r, "http://uc.buaa.edu.cn/", http.StatusFound)
			case "/anyshare/oauth2/login":
				http.Redirect(w, r, "/oauth2/signin?login_challenge=ch1", http.StatusFound)
			case "/oauth2/signin":
				fmt.Fprint(w, "signin")
			case "/anyshare/oauth2/login/callback":
				http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "confirmed-token", Path: "/"})
				fmt.Fprint(w, "callback")
			case "/api/efast/v1/owned-doc-lib":
				reply(w, []any{map[string]string{"id": "gns://root", "name": "Drive"}})
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
			}
		})
		cloud = s.URL

		// Default Login must reject continueForm with ChallengeRiskConfirm and clear cookies.
		err := c.Login(ctx, "student", "secret-pass")
		var apiErr *Error
		if !errors.Is(err, ErrChallenge) || ChallengeOf(err) != ChallengeRiskConfirm || !errors.As(err, &apiErr) || apiErr.Operation != "login" {
			t.Fatalf("expected ChallengeRiskConfirm on default Login, got %v (kind=%q)", err, ChallengeOf(err))
		}
		if strings.Contains(err.Error(), "secret-pass") {
			t.Fatal("password leaked in error")
		}
		base, _ := url.Parse(cloud)
		if len(c.client.Jar.Cookies(base)) != 0 || c.token != "" {
			t.Fatal("unconfirmed login retained cookies or token")
		}

		// Explicit user authorization completes continueForm continuation and establishes session.
		check(t, c.LoginWithOptions(ctx, "student", "secret-pass", LoginOptions{AcknowledgeRisk: true}))
		if c.token != "confirmed-token" {
			t.Fatalf("expected confirmed-token, got %q", c.token)
		}
	})

	// 2. SSO CAPTCHA and MFA challenges are classified and never bypassed even with AcknowledgeRisk.
	t.Run("sso-captcha-and-mfa", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			onGet bool
			html  string
			want  ChallengeKind
		}{
			{"get-captcha", true, `<input name="execution" value="e1"><input name="captcha" value="">`, ChallengeCaptcha},
			{"post-captcha-with-continue", false, `<form id="continueForm"><input name="execution" value="e2"><input name="captchaResponse" value=""></form>`, ChallengeCaptcha},
			{"post-mfa", false, `<input name="execution" value="e3"><input name="otp" value="">`, ChallengeMFA},
		} {
			t.Run(tc.name, func(t *testing.T) {
				var passwordSent atomic.Bool
				c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
					if r.Method == http.MethodGet {
						if tc.onGet {
							fmt.Fprint(w, tc.html)
						} else {
							fmt.Fprint(w, `<input name="execution" value="e1">`)
						}
						return
					}
					passwordSent.Store(true)
					fmt.Fprint(w, tc.html)
				})
				err := c.LoginWithOptions(ctx, "student", "secret-pass", LoginOptions{AcknowledgeRisk: true})
				if !errors.Is(err, ErrChallenge) || ChallengeOf(err) != tc.want {
					t.Fatalf("expected %q, got %v (kind=%q)", tc.want, err, ChallengeOf(err))
				}
				if tc.onGet && passwordSent.Load() {
					t.Fatal("password must not be posted when login page already requires CAPTCHA")
				}
			})
		}
	})

	// 3. Local login CAPTCHA and MFA classification on page config and signin response.
	t.Run("local-captcha-and-mfa", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			authConfig string
			postBody   map[string]any
			want       ChallengeKind
		}{
			{"page-captcha", `{"vcode_login_config":{"isenable":true,"passwderrcnt":0}}`, nil, ChallengeCaptcha},
			{"page-mfa", `{"dualfactor_auth_server_status":{"otp":true}}`, nil, ChallengeMFA},
			{"signin-captcha", `{"vcode_login_config":{"isenable":true,"passwderrcnt":3}}`, map[string]any{"vcodeinfo": map[string]any{"isenable": true, "vcode": "base64-img"}, "message": "secret-vcode-detail"}, ChallengeCaptcha},
			{"signin-mfa", `{}`, map[string]any{"detail": map[string]any{"otp": true}, "message": "secret-otp-detail"}, ChallengeMFA},
		} {
			t.Run(tc.name, func(t *testing.T) {
				c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
					switch r.URL.Path {
					case "/anyshare/oauth2/login":
						http.Redirect(w, r, "/oauth2/signin?login_challenge=lc1", http.StatusFound)
					case "/oauth2/signin":
						if r.Method == http.MethodGet {
							fmt.Fprintf(w, `<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"challenge":"lc1","csrftoken":"csrf1","device":{"client_type":"web"},"authconfig":%s}}}</script>`, tc.authConfig)
							return
						}
						w.WriteHeader(http.StatusBadRequest)
						reply(w, tc.postBody)
					default:
						t.Errorf("unexpected path %s", r.URL.Path)
					}
				})
				err := c.LoginLocal(ctx, "localuser", "secret-local-pass")
				if !errors.Is(err, ErrChallenge) || ChallengeOf(err) != tc.want {
					t.Fatalf("expected %q, got %v (kind=%q)", tc.want, err, ChallengeOf(err))
				}
				if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "base64-img") {
					t.Fatalf("sensitive detail leaked in error: %s", err.Error())
				}
			})
		}
	})
}
