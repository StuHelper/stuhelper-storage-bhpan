package bhpan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestShareIDRejectsTraversalAndUnsafeCharacters(t *testing.T) {
	var hits atomic.Int32
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(204)
	})
	c.token = "fixture-token"
	ctx := context.Background()

	badIDs := []string{
		"",
		".",
		"..",
		"../anonymous",
		"a/b",
		"a\\b",
		"share?type=all",
		"share#frag",
		"share;cookie",
		"share space",
		"share\tname",
		strings.Repeat("s", 129),
	}
	for _, id := range badIDs {
		if _, err := c.ResolveShare(ctx, id, "code"); !errors.Is(err, ErrInput) {
			t.Fatalf("ResolveShare(%q): expected ErrInput, got %v", id, err)
		}
		in := Share{ID: id, Title: "doc", LimitedTimes: -1, Item: ShareItem{ID: "file", Type: "file", Allow: []string{"download"}}}
		if err := c.UpdateShare(ctx, in); !errors.Is(err, ErrInput) {
			t.Fatalf("UpdateShare(%q): expected ErrInput, got %v", id, err)
		}
		if err := c.DeleteShare(ctx, id); !errors.Is(err, ErrInput) {
			t.Fatalf("DeleteShare(%q): expected ErrInput, got %v", id, err)
		}
	}
	for _, docID := range []string{"", ".", ".."} {
		if _, err := c.Shares(ctx, docID); !errors.Is(err, ErrInput) {
			t.Fatalf("Shares(%q): expected ErrInput, got %v", docID, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("unsafe share IDs triggered %d provider requests", hits.Load())
	}
}

func TestSharePasswordRedactionAndValidation(t *testing.T) {
	var gotCreatePassword string
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/shared-link/v1/document/anonymous":
			var body map[string]any
			check(t, json.NewDecoder(r.Body).Decode(&body))
			gotCreatePassword, _ = body["password"].(string)
			reply(w, map[string]string{"id": "share-created"})
		case "/api/shared-link/v1/document/folder/file":
			reply(w, []any{map[string]any{
				"id":            "share-listed",
				"title":         "Course Notes",
				"expires_at":    "2026-12-31T00:00:00Z",
				"password":      "leaked-list-code",
				"limited_times": -1,
				"item":          map[string]any{"id": "file", "type": "file", "allow": []string{"download"}},
			}})
		case "/api/doc-share/v1/docs-shared-with-anyone":
			reply(w, map[string]any{
				"entries": []any{map[string]any{
					"doc": map[string]any{"id": "file", "type": "file", "allow": []string{"download"}},
					"link_configs": []any{map[string]any{
						"id":            "share-history",
						"title":         "History Notes",
						"expires_at":    "",
						"password":      "leaked-history-code",
						"limited_times": -1,
						"allow":         []string{"download"},
					}},
				}},
			})
		default:
			w.WriteHeader(404)
		}
	})
	c.token = "fixture-token"
	ctx := context.Background()

	input := Share{
		Title:        "Course Notes",
		ExpiresAt:    "2026-12-31T00:00:00Z",
		Password:     "create-secret",
		LimitedTimes: -1,
		Item:         ShareItem{ID: "file", Type: "file", Allow: []string{"download"}},
	}
	rawInput, err := json.Marshal(input)
	check(t, err)
	if bytes.Contains(rawInput, []byte("create-secret")) || bytes.Contains(rawInput, []byte(`"password"`)) {
		t.Fatalf("Share.Password leaked via json.Marshal on input: %s", rawInput)
	}

	created, err := c.CreateShare(ctx, input)
	check(t, err)
	if gotCreatePassword != "create-secret" {
		t.Fatalf("provider did not receive create password, got %q", gotCreatePassword)
	}
	rawCreated, err := json.Marshal(created)
	check(t, err)
	if !created.HasPassword || created.Password != "" || bytes.Contains(rawCreated, []byte("create-secret")) || bytes.Contains(rawCreated, []byte(`"password"`)) {
		t.Fatalf("CreateShare retained or serialized password: %+v %s", created, rawCreated)
	}

	listed, err := c.Shares(ctx, "file")
	check(t, err)
	rawListed, err := json.Marshal(listed)
	check(t, err)
	if len(listed) != 1 || !listed[0].HasPassword || listed[0].Password != "" || bytes.Contains(rawListed, []byte("leaked-list-code")) {
		t.Fatalf("Shares leaked password: %+v %s", listed, rawListed)
	}

	history, err := c.ShareHistory(ctx)
	check(t, err)
	rawHistory, err := json.Marshal(history)
	check(t, err)
	if len(history) != 1 || !history[0].HasPassword || history[0].Password != "" || bytes.Contains(rawHistory, []byte("leaked-history-code")) {
		t.Fatalf("ShareHistory leaked password: %+v %s", history, rawHistory)
	}

	// Input validation for control chars, length limits, dot IDs, and duplicate permissions.
	invalidInputs := []Share{
		{Title: "bad\r\ntitle", LimitedTimes: -1, Item: ShareItem{ID: "file", Type: "file", Allow: []string{"download"}}},
		{Title: strings.Repeat("t", 513), LimitedTimes: -1, Item: ShareItem{ID: "file", Type: "file", Allow: []string{"download"}}},
		{Title: "ok", ExpiresAt: "2026\x00", LimitedTimes: -1, Item: ShareItem{ID: "file", Type: "file", Allow: []string{"download"}}},
		{Title: "ok", ExpiresAt: "   ", LimitedTimes: -1, Item: ShareItem{ID: "file", Type: "file", Allow: []string{"download"}}},
		{Title: "ok", Password: "bad\npassword", LimitedTimes: -1, Item: ShareItem{ID: "file", Type: "file", Allow: []string{"download"}}},
		{Title: "ok", Password: strings.Repeat("p", 129), LimitedTimes: -1, Item: ShareItem{ID: "file", Type: "file", Allow: []string{"download"}}},
		{Title: "ok", LimitedTimes: -1, Item: ShareItem{ID: "..", Type: "file", Allow: []string{"download"}}},
		{Title: "ok", LimitedTimes: -1, Item: ShareItem{ID: "file", Type: "file", Allow: []string{"download", "download"}}},
	}
	for i, bad := range invalidInputs {
		if _, err := c.CreateShare(ctx, bad); !errors.Is(err, ErrInput) {
			t.Fatalf("invalid Share[%d] accepted: %v", i, err)
		}
	}

	// Malformed Shares elements must return ErrProtocol.
	for _, payload := range []any{
		[]any{map[string]any{}},
		[]any{map[string]any{"id": "..", "item": map[string]any{"id": "file", "type": "file", "allow": []string{"download"}}}},
		[]any{map[string]any{"id": "valid-id", "item": map[string]any{"id": "", "type": "file", "allow": []string{"download"}}}},
	} {
		mc, _ := malformedFixture(t, func(w http.ResponseWriter, r *http.Request) { reply(w, payload) })
		mc.token = "fixture-token"
		if _, err := mc.Shares(ctx, "file"); !errors.Is(err, ErrProtocol) {
			t.Fatalf("Shares accepted malformed payload %v: %v", payload, err)
		}
	}
}

func TestResolveShareCredentialsCookieAndDirectorySize(t *testing.T) {
	ctx := context.Background()

	// 1. Wrong password responses from POST /link map to ErrCredentials, preserving 404 and 429.
	for _, tc := range []struct {
		name   string
		status int
		want   error
	}{
		{"bad-request-wrong-code", 400, ErrCredentials},
		{"unauthorized-wrong-code", 401, ErrCredentials},
		{"forbidden-wrong-code", 403, ErrCredentials},
		{"html-reprompt-no-cookie", 200, ErrCredentials},
		{"deleted-share", 404, ErrNotFound},
		{"rate-limited", 429, ErrUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/shared-link/v1/links/share-1":
					reply(w, map[string]bool{"password_required": true})
				case "/link":
					w.WriteHeader(tc.status)
					_, _ = w.Write([]byte(`{}`))
				default:
					w.WriteHeader(404)
				}
			})
			_, err := c.ResolveShare(ctx, "share-1", "wrong")
			if !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, err)
			}
		})
	}

	// 2. Literal '+' in link_token cookie is preserved, clearing cookie is ignored, and explicit size=-1 directory works.
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/shared-link/v1/links/folder-share":
			reply(w, map[string]bool{"password_required": false})
		case "/link/folder-share":
			w.Header().Add("Set-Cookie", "link_token:folder-share=deleted; Max-Age=0; Path=/; Secure")
			w.Header().Add("Set-Cookie", "link_token:folder-share=raw+base64/token==; Path=/; Secure")
			http.Redirect(w, r, "/landing", 302)
		case "/api/efast/v1/entry-item":
			if got := r.Header.Get("Authorization"); got != "Bearer raw+base64/token==" {
				t.Errorf("corrupted bearer token: %q", got)
				w.WriteHeader(401)
				return
			}
			reply(w, []any{map[string]any{"id": "shared-folder", "name": "Materials", "size": -1}})
		case "/api/efast/v1/dir/list":
			reply(w, map[string]any{"dirs": []any{}, "files": []any{map[string]any{"docid": "f1", "name": "slide.pdf", "size": 128}}})
		default:
			w.WriteHeader(404)
		}
	})
	entry, err := c.ResolveShare(ctx, "folder-share", "")
	check(t, err)
	if entry.Size != -1 {
		t.Fatalf("expected directory size -1, got %d", entry.Size)
	}
	listing, err := c.ListShared(ctx, entry)
	check(t, err)
	if len(listing.Files) != 1 || listing.Files[0].Size != 128 {
		t.Fatalf("unexpected shared directory listing: %+v", listing)
	}

	// Clearing-only Set-Cookie (Max-Age=0) must not be treated as a valid token.
	clearedClient, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/shared-link/v1/links/cleared-share":
			reply(w, map[string]bool{"password_required": false})
		case "/link/cleared-share":
			w.Header().Add("Set-Cookie", "link_token:cleared-share=deleted; Max-Age=0; Path=/; Secure")
			w.WriteHeader(200)
		case "/api/efast/v1/entry-item":
			t.Error("cleared cookie must never authorize entry-item")
			w.WriteHeader(401)
		default:
			w.WriteHeader(404)
		}
	})
	if _, err := clearedClient.ResolveShare(ctx, "cleared-share", ""); !errors.Is(err, ErrSession) {
		t.Fatalf("expected ErrSession for cleared cookie, got %v", err)
	}

	// 3. Directory.Files must reject negative size (-1 directory sentinel on a file entry).
	badListClient, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"dirs": []any{}, "files": []any{map[string]any{"docid": "f1", "name": "bad.bin", "size": -1}}})
	})
	badListClient.token = "fixture-token"
	if _, err := badListClient.List(ctx, "root"); !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol for file with size -1, got %v", err)
	}
}
