package bhpan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

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

func TestObjectStoreRedirectRejected(t *testing.T) {
	ctx := context.Background()
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
