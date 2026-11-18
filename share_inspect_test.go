package bhpan

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func TestParseShareURLAndInspectShare(t *testing.T) {
	ctx := context.Background()

	// 1. Default and Client-scoped ParseShareURL validation.
	id, err := ParseShareURL("  https://bhpan.buaa.edu.cn:443/link/Share_ID-2026  ")
	check(t, err)
	if id != "Share_ID-2026" {
		t.Fatalf("unexpected share ID %q", id)
	}

	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("personal credentials leaked to public InspectShare endpoint")
		}
		switch r.URL.Path {
		case "/api/shared-link/v1/links/public-doc":
			reply(w, map[string]any{
				"password_required": false,
				"title":             "高等数学讲义.pdf",
				"expires_at":        "2026-12-31T23:59:59+08:00",
				"limited_times":     -1,
			})
		case "/api/shared-link/v1/links/protected-doc":
			reply(w, map[string]any{"password_required": true})
		case "/api/shared-link/v1/links/missing-doc":
			w.WriteHeader(http.StatusNotFound)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	c.token = "personal-token"
	base, _ := url.Parse(s.URL)
	c.client.Jar.SetCookies(base, []*http.Cookie{{Name: "personal", Value: "secret", Path: "/"}})

	parsedID, err := c.ParseShareURL(s.URL + "/link/public-doc")
	check(t, err)
	if parsedID != "public-doc" {
		t.Fatalf("unexpected client ParseShareURL result: %q", parsedID)
	}

	for _, raw := range []string{
		"http://bhpan.buaa.edu.cn/link/abc",
		"https://evil.example/link/abc",
		"https://user@bhpan.buaa.edu.cn/link/abc",
	} {
		if _, err := ParseShareURL(raw); !errors.Is(err, ErrDestination) {
			t.Fatalf("expected ErrDestination for %q, got %v", raw, err)
		}
	}
	for _, raw := range []string{
		"",
		"not-a-url",
		"https://bhpan.buaa.edu.cn/other/abc",
		"https://bhpan.buaa.edu.cn/link/",
		"https://bhpan.buaa.edu.cn/link/.",
		"https://bhpan.buaa.edu.cn/link/..",
		"https://bhpan.buaa.edu.cn/link/a/b",
		"https://bhpan.buaa.edu.cn/link/a%2Fb",
		"https://bhpan.buaa.edu.cn/link/abc?pwd=1234",
		"https://bhpan.buaa.edu.cn/link/abc#frag",
	} {
		if _, err := ParseShareURL(raw); !errors.Is(err, ErrInput) {
			t.Fatalf("expected ErrInput for %q, got %v", raw, err)
		}
	}

	// 2. InspectShare returns public metadata while isolating personal session.
	info, err := c.InspectShare(ctx, parsedID)
	check(t, err)
	if info.ID != "public-doc" || info.PasswordRequired || info.Title != "高等数学讲义.pdf" || info.ExpiresAt != "2026-12-31T23:59:59+08:00" || info.LimitedTimes != -1 {
		t.Fatalf("unexpected ShareInfo: %+v", info)
	}

	protectedInfo, err := c.InspectShare(ctx, "protected-doc")
	check(t, err)
	if !protectedInfo.PasswordRequired || protectedInfo.ID != "protected-doc" {
		t.Fatalf("unexpected protected ShareInfo: %+v", protectedInfo)
	}

	if _, err := c.InspectShare(ctx, "missing-doc"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing share, got %v", err)
	}
	for _, badID := range []string{"", ".", "..", "a/b", "a%2fb"} {
		if _, err := c.InspectShare(ctx, badID); !errors.Is(err, ErrInput) {
			t.Fatalf("expected ErrInput for bad share ID %q, got %v", badID, err)
		}
	}
}
