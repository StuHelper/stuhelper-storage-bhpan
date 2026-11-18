package bhpan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSSOLoginDetectsCaptchaAndMFAChallenges(t *testing.T) {
	ctx := context.Background()

	// 1. Active captcha/OTP on GET /login returns ErrChallenge without submitting password.
	for _, field := range []string{"captcha", "captchaResponse", "vcode", "otp", "dynamicCode"} {
		t.Run("get-"+field, func(t *testing.T) {
			var postHits atomic.Int32
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" && r.Method == "GET" {
					fmt.Fprintf(w, `<form><input type="hidden" name="execution" value="t1"><input type="text" name="%s"></form>`, field)
					return
				}
				if r.Method == "POST" {
					postHits.Add(1)
				}
				w.WriteHeader(400)
			})
			err := c.Login(ctx, "student", "secret-password")
			if !errors.Is(err, ErrChallenge) {
				t.Fatalf("expected ErrChallenge, got %v", err)
			}
			if postHits.Load() != 0 {
				t.Fatalf("password submitted despite pre-login challenge (%d POSTs)", postHits.Load())
			}
		})
	}

	// 2. Captcha or MFA returned after POST /login alongside execution returns ErrChallenge, not ErrCredentials.
	for _, htmlBody := range []string{
		`<form><input name="execution" value="t2"><input type="text" name="captcha"></form>`,
		`<form><input name="execution" value="t2"><input name="otp" type="text"></form>`,
	} {
		c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/login" && r.Method == "GET" {
				fmt.Fprint(w, `<input type="hidden" name="execution" value="t1"><input type="hidden" name="captcha" value=""><input name="vcode" disabled>`)
				return
			}
			w.WriteHeader(200)
			fmt.Fprint(w, htmlBody)
		})
		err := c.Login(ctx, "student", "secret-password")
		if !errors.Is(err, ErrChallenge) || errors.Is(err, ErrCredentials) {
			t.Fatalf("expected ErrChallenge on POST challenge, got %v", err)
		}
	}
}

func TestLocalLoginDetectsCaptchaAndMFAResponses(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name       string
		afterCount int
		status     int
		respBody   string
		want       error
	}{
		{
			name:       "vcode-object-401",
			afterCount: 3,
			status:     401,
			respBody:   `{"code":401001002,"message":"private-msg","detail":{"vcode":{"id":"uuid","isenable":true}}}`,
			want:       ErrChallenge,
		},
		{
			name:       "errcnt-reached-threshold",
			afterCount: 3,
			status:     401,
			respBody:   `{"code":401001001,"message":"private-msg","detail":{"errcnt":3}}`,
			want:       ErrChallenge,
		},
		{
			name:       "mfa-required-403",
			afterCount: 3,
			status:     403,
			respBody:   `{"code":401001030,"message":"private-msg","detail":{"dualfactorauthinfo":{"OTP":true}}}`,
			want:       ErrChallenge,
		},
		{
			name:       "wrong-password-below-threshold",
			afterCount: 3,
			status:     401,
			respBody:   `{"code":401001001,"message":"private-msg","detail":{"errcnt":1}}`,
			want:       ErrCredentials,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/anyshare/oauth2/login":
					http.Redirect(w, r, "/oauth2/signin?login_challenge=ch1", 302)
				case "/oauth2/signin":
					if r.Method == "GET" {
						fmt.Fprintf(w, `<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"challenge":"ch1","csrftoken":"csrf1","device":{"client_type":"web"},"authconfig":{"vcode_login_config":{"isenable":true,"passwderrcnt":%d}}}}}</script>`, tc.afterCount)
						return
					}
					w.WriteHeader(tc.status)
					fmt.Fprint(w, tc.respBody)
				default:
					w.WriteHeader(404)
				}
			})
			err := c.LoginLocal(ctx, "localuser", "secret-password")
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "private-msg") || strings.Contains(err.Error(), "secret-password") {
				t.Fatalf("unsafe error output: %v", err)
			}
		})
	}
}

type interceptPortalTransport struct {
	inner      http.RoundTripper
	portalHits atomic.Int32
}

func (t *interceptPortalTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.EqualFold(req.URL.Hostname(), "uc.buaa.edu.cn") {
		t.portalHits.Add(1)
		return &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Body:       http.NoBody,
			Request:    req,
		}, nil
	}
	return t.inner.RoundTrip(req)
}

func TestRedirectBoundariesAndObjectStore3xx(t *testing.T) {
	ctx := context.Background()

	// 1. uc.buaa.edu.cn redirects (without trailing slash, http or https, or subpath) must never be followed.
	for _, location := range []string{
		"http://uc.buaa.edu.cn",
		"https://uc.buaa.edu.cn",
		"https://uc.buaa.edu.cn/index",
	} {
		t.Run(location, func(t *testing.T) {
			var cloud string
			validate := contractValidator(t)
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				validate(r)
				switch r.URL.Path {
				case "/login":
					if r.URL.Query().Get("service") != "" {
						http.Redirect(w, r, cloud+"/anyshare/oauth2/login/callback", 302)
						return
					}
					if r.Method == "GET" {
						fmt.Fprint(w, `<input type="hidden" name="execution" value="exec-1">`)
						return
					}
					http.SetCookie(w, &http.Cookie{Name: "sso", Value: "ok", Path: "/"})
					w.Header().Set("Location", location)
					w.WriteHeader(302)
				case "/anyshare/oauth2/login":
					http.Redirect(w, r, "/anyshare/oauth2/login/callback", 302)
				case "/anyshare/oauth2/login/callback":
					http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "tok", Path: "/"})
					fmt.Fprint(w, "ok")
				case "/anyshare/oauth2/login/refreshToken":
					fmt.Fprint(w, "ok")
				case "/api/efast/v1/owned-doc-lib":
					reply(w, []any{map[string]string{"id": "root", "name": "Drive"}})
				default:
					w.WriteHeader(404)
				}
			}))
			t.Cleanup(server.Close)
			cloud = server.URL
			tr := &interceptPortalTransport{inner: server.Client().Transport}
			c, err := New(Config{CloudURL: cloud, SSOURL: cloud, Transport: tr, Timeout: time.Second})
			check(t, err)
			t.Cleanup(c.Close)

			if err := c.Login(ctx, "student", "pw"); err != nil {
				t.Fatalf("login failed for portal %s: %v", location, err)
			}
			if tr.portalHits.Load() != 0 {
				t.Fatalf("client followed redirect to uc.buaa.edu.cn (%d hits)", tr.portalHits.Load())
			}
		})
	}

	// Portal URL with userinfo or fragment must be rejected as ErrDestination.
	for _, badPortal := range []string{"https://user@uc.buaa.edu.cn/", "https://uc.buaa.edu.cn/#frag"} {
		c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/login" && r.Method == "GET" {
				fmt.Fprint(w, `<input type="hidden" name="execution" value="exec-1">`)
				return
			}
			w.Header().Set("Location", badPortal)
			w.WriteHeader(302)
		})
		if err := c.Login(ctx, "student", "pw"); !errors.Is(err, ErrDestination) {
			t.Fatalf("expected ErrDestination for %s, got %v", badPortal, err)
		}
	}

	// 2. Object store 3xx redirect must return ErrDestination, not retryable ErrUnavailable.
	var base string
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/efast/v1/file/osbeginupload":
			reply(w, map[string]any{"docid": "file", "rev": "rev", "authrequest": []string{"PUT", base + "/redirect-obj", "Authorization: signed", "X-Amz-Date: date", "Content-Type: application/octet-stream"}})
		case "/api/efast/v1/file/osdownload":
			reply(w, map[string]any{"authrequest": []string{"GET", base + "/redirect-obj"}})
		case "/redirect-obj":
			http.Redirect(w, r, "https://evil.example/steal", 307)
		default:
			w.WriteHeader(404)
		}
	})
	base = s.URL
	c.token = "fixture-token"

	u, err := c.BeginUpload(ctx, "root", "a.bin", 4)
	check(t, err)
	if _, err := c.WriteUpload(ctx, u, strings.NewReader("abcd")); !errors.Is(err, ErrDestination) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("WriteUpload 307: expected ErrDestination, got %v", err)
	}
	var dst bytes.Buffer
	if _, err := c.Download(ctx, "file", &dst); !errors.Is(err, ErrDestination) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("Download 307: expected ErrDestination, got %v", err)
	}
}
