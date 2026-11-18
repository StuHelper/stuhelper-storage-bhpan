package bhpan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestRefreshSessionLifecycle(t *testing.T) {
	mode := "rotate"
	c, s := malformedFixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/anyshare/oauth2/login/refreshToken":
			switch mode {
			case "rotate", "verify-503":
				http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "rotated-token", Path: "/"})
				fmt.Fprint(w, "ok")
			case "unchanged":
				fmt.Fprint(w, "ok")
			case "busy-503":
				w.WriteHeader(http.StatusServiceUnavailable)
			case "forbidden-403":
				w.WriteHeader(http.StatusForbidden)
			case "expired-401":
				w.WriteHeader(http.StatusUnauthorized)
			case "redirect-signin":
				http.Redirect(w, r, "/oauth2/signin?login_challenge=expired", http.StatusFound)
			case "cleared-cookie":
				http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "", Path: "/", MaxAge: -1})
				fmt.Fprint(w, "ok")
			case "verify-401":
				http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "rejected-token", Path: "/"})
				fmt.Fprint(w, "ok")
			}
		case "/oauth2/signin":
			fmt.Fprint(w, "signin")
		case "/api/efast/v1/owned-doc-lib":
			if mode == "verify-503" {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			if mode == "verify-401" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			wantAuth := "Bearer rotated-token"
			if r.Header.Get("Authorization") != wantAuth {
				t.Errorf("unexpected Authorization %q, want %q", r.Header.Get("Authorization"), wantAuth)
			}
			reply(w, []any{map[string]string{"id": "gns://root", "name": "Drive"}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := context.Background()

	// 1. Refresh without an established session fails with ErrSession.
	if err := c.RefreshSession(ctx); !errors.Is(err, ErrSession) {
		t.Fatalf("expected ErrSession before login, got %v", err)
	}

	// Seed active session.
	base, _ := url.Parse(s.URL)
	seed := func(tok string) {
		c.token = tok
		c.client.Jar.SetCookies(base, []*http.Cookie{{Name: "client.oauth2_token", Value: tok, Path: "/"}})
	}
	seed("initial-token")

	// 2. Refresh rotates token and verifies owned-doc-lib.
	check(t, c.RefreshSession(ctx))
	if c.token != "rotated-token" {
		t.Fatalf("expected rotated-token, got %q", c.token)
	}

	// 3. Refresh succeeds when provider keeps existing cookie unchanged.
	mode = "unchanged"
	check(t, c.RefreshSession(ctx))
	if c.token != "rotated-token" {
		t.Fatalf("expected unchanged rotated-token, got %q", c.token)
	}

	// 4. Transient 503 preserves original status classification and active session.
	mode = "busy-503"
	err := c.RefreshSession(ctx)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrUnavailable on 503, got %v", err)
	}
	if c.token != "rotated-token" {
		t.Fatal("transient failure should not wipe active token")
	}

	seed("before-rotation")
	mode = "verify-503"
	if err := c.RefreshSession(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected temporary verification failure, got %v", err)
	}
	mode = "unchanged"
	_, err = c.Libraries(ctx)
	check(t, err)

	// 5. Permission 403 preserves ErrPermission classification.
	mode = "forbidden-403"
	if err := c.RefreshSession(ctx); !errors.Is(err, ErrPermission) {
		t.Fatalf("expected ErrPermission on 403, got %v", err)
	}

	// 6. Expired session responses (401, signin redirect, cleared cookie, verify 401) clear session state.
	for _, expiredMode := range []string{"expired-401", "redirect-signin", "cleared-cookie", "verify-401"} {
		seed("active-token")
		mode = expiredMode
		if err := c.RefreshSession(ctx); !errors.Is(err, ErrSession) {
			t.Fatalf("mode %s: expected ErrSession, got %v", expiredMode, err)
		}
		if c.token != "" || len(c.client.Jar.Cookies(base)) != 0 {
			t.Fatalf("mode %s: expired session was not cleared", expiredMode)
		}
	}
}
