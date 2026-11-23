package bhpan

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLocalLoginRedirectTargets(t *testing.T) {
	const callback = "/anyshare/oauth2/login/callback"
	for _, tc := range []struct {
		name     string
		redirect string
		next     string
		rejected bool
	}{
		{name: "root relative", redirect: callback + "?code=part%2Fpart"},
		{name: "absolute same origin", redirect: "{cloud}" + callback + "?code=part%2Fpart"},
		{name: "same origin OAuth continuation", redirect: "/oauth2/auth?service=%2Fanyshare", next: callback + "?code=part%2Fpart"},
		{name: "wrong port", redirect: "{other}" + callback, rejected: true},
		{name: "protocol relative external", redirect: "//{otherAuthority}" + callback, rejected: true},
		{name: "protocol relative same origin", redirect: "//{cloudAuthority}" + callback, rejected: true},
		{name: "path relative without slash", redirect: "anyshare/oauth2/login/callback", rejected: true},
		{name: "userinfo", redirect: "https://fixture@{cloudAuthority}" + callback, rejected: true},
		{name: "fragment", redirect: callback + "#fixture", rejected: true},
		{name: "empty fragment", redirect: callback + "#", rejected: true},
		{name: "HTTP downgrade", redirect: "http://{cloudAuthority}" + callback, rejected: true},
		{name: "backslash", redirect: `/\{otherAuthority}` + callback, rejected: true},
		{name: "encoded slash", redirect: "/%2F" + callback, rejected: true},
		{name: "encoded backslash", redirect: "/%5c" + callback, rejected: true},
		{name: "double encoding", redirect: "/%252f" + callback, rejected: true},
		{name: "continuation to other origin", redirect: "/oauth2/auth", next: "{other}" + callback, rejected: true},
		{name: "continuation downgrade", redirect: "/oauth2/auth", next: "http://{cloudAuthority}" + callback, rejected: true},
		{name: "continuation network path", redirect: "/oauth2/auth", next: "//{cloudAuthority}" + callback, rejected: true},
		{name: "continuation encoded delimiter", redirect: "/oauth2/auth", next: "/%2F" + callback, rejected: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var otherHits, submissions, callbackHits, intermediateHits atomic.Int32
			other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				otherHits.Add(1)
				w.WriteHeader(500)
			}))
			t.Cleanup(other.Close)

			expand := func(raw string, r *http.Request) string {
				return strings.NewReplacer(
					"{cloud}", "https://"+r.Host,
					"{cloudAuthority}", r.Host,
					"{other}", other.URL,
					"{otherAuthority}", strings.TrimPrefix(other.URL, "https://"),
				).Replace(raw)
			}
			cloud := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.EscapedPath() {
				case "GET /anyshare/oauth2/login":
					http.Redirect(w, r, "/oauth2/signin?login_challenge=fixture", http.StatusFound)
				case "GET /oauth2/signin":
					fmt.Fprint(w, `<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"challenge":"fixture","csrftoken":"fixture","device":{"client_type":"web"},"authconfig":{}}}}</script>`)
				case "POST /oauth2/signin":
					submissions.Add(1)
					reply(w, map[string]string{"redirect": expand(tc.redirect, r)})
				case "GET /oauth2/auth":
					intermediateHits.Add(1)
					if !tc.rejected && r.URL.Query().Get("service") != "/anyshare" {
						t.Error("same-origin OAuth query changed")
					}
					w.Header().Set("Location", expand(tc.next, r))
					w.WriteHeader(http.StatusFound)
				case "GET " + callback:
					callbackHits.Add(1)
					if r.URL.Query().Get("code") != "part/part" {
						t.Error("OAuth callback query changed")
					}
					http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "fixture-token", Path: "/anyshare/", Secure: true})
				case "GET /api/efast/v1/owned-doc-lib":
					reply(w, []Library{{Type: "user_doc_lib", ID: "gns://root", Name: "fixture"}})
				case "POST /api/eacp/v1/user/get":
					reply(w, map[string]string{"type": "user", "userid": "fixture"})
				case "POST /api/efast/v1/dir/list":
					reply(w, map[string]any{"dirs": []any{}, "files": []any{}})
				case "GET /api/efast/v1/quota/user":
					reply(w, Quota{Allocated: 1024, Used: 256})
				default:
					t.Error("unexpected request in local OAuth flow")
					w.WriteHeader(500)
				}
			}))
			t.Cleanup(cloud.Close)
			c, err := New(Config{CloudURL: cloud.URL, Transport: cloud.Client().Transport, Timeout: time.Second})
			check(t, err)
			t.Cleanup(c.Close)
			err = c.LoginLocal(t.Context(), "fixture", "fixture-password")
			if submissions.Load() != 1 || otherHits.Load() != 0 {
				t.Fatalf("credential submissions=%d, requests to other origin=%d", submissions.Load(), otherHits.Load())
			}
			wantIntermediate := int32(0)
			if tc.next != "" {
				wantIntermediate = 1
			}
			if intermediateHits.Load() != wantIntermediate {
				t.Fatalf("intermediate requests=%d, want %d", intermediateHits.Load(), wantIntermediate)
			}
			if tc.rejected {
				var apiErr *Error
				if !errors.Is(err, ErrDestination) || !errors.As(err, &apiErr) || apiErr.Operation != "local-callback" {
					t.Fatalf("expected sanitized local destination error, got %v", err)
				}
				if tc.next != "" && apiErr.Status != http.StatusFound {
					t.Fatal("missing redirect response status")
				}
				if callbackHits.Load() != 0 {
					t.Fatal("rejected target reached the callback")
				}
				return
			}

			check(t, err)
			if callbackHits.Load() != 1 {
				t.Fatalf("callback requests=%d", callbackHits.Load())
			}
			identity, err := c.Identity(t.Context())
			check(t, err)
			if identity.ID != "fixture" {
				t.Fatal("authorized identity was not returned")
			}
			library, err := c.PersonalLibrary(t.Context())
			check(t, err)
			if _, err := c.List(t.Context(), library.ID); err != nil {
				t.Fatal(err)
			}
			quota, err := c.Quota(t.Context())
			check(t, err)
			if quota.Allocated != 1024 || quota.Used != 256 {
				t.Fatal("authorized quota was not returned")
			}
		})
	}
}
