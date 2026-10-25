package bhpan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
)

func TestMultipartProtocolAndCompletionFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			var base string
			finished := false
			c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/efast/v1/file/osoption":
					reply(w, map[string]int{"partminsize": 3, "partmaxsize": 8, "partmaxnum": 10})
				case "/api/efast/v1/file/osinitmultiupload":
					reply(w, map[string]string{"docid": "file", "rev": "rev", "uploadid": "upload"})
				case "/api/efast/v1/file/osuploadpart":
					var in map[string]any
					check(t, json.NewDecoder(r.Body).Decode(&in))
					if in["parts"] != "1-2" {
						t.Error("part range")
					}
					reply(w, map[string]any{"authrequests": map[string]any{"1": []string{"PUT", base + "/part", "Authorization: part-signature", "X-Amz-Date: fixture", "Content-Type: application/octet-stream"}, "2": []string{"PUT", base + "/part", "Authorization: part-signature", "X-Amz-Date: fixture", "Content-Type: application/octet-stream"}}})
				case "/part":
					if r.Header.Get("Authorization") != "part-signature" || r.Header.Get("Cookie") != "" {
						t.Error("multipart credential isolation")
					}
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("ETag", `"part-hash"`)
				case "/api/efast/v1/file/oscompleteupload":
					var in struct {
						Info map[string][]any `json:"partinfo"`
					}
					check(t, json.NewDecoder(r.Body).Decode(&in))
					if len(in.Info) != 2 || in.Info["1"][0] != "part-hash" || in.Info["1"][1] != float64(3) {
						t.Error("part info")
					}
					var b bytes.Buffer
					mw := multipart.NewWriter(&b)
					hdr := textproto.MIMEHeader{"Content-Type": []string{"application/json"}}
					p, e := mw.CreatePart(hdr)
					check(t, e)
					_ = json.NewEncoder(p).Encode(map[string]any{"authrequest": []string{"POST", base + "/complete", "Authorization: completion-signature", "X-Amz-Date: fixture", "Content-Type: application/xml"}})
					p, e = mw.CreatePart(textproto.MIMEHeader{"Content-Type": []string{"application/xml"}})
					check(t, e)
					_, _ = fmt.Fprint(p, "<CompleteMultipartUpload/>")
					check(t, mw.Close())
					w.Header().Set("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
					_, _ = w.Write(b.Bytes())
				case "/complete":
					if r.Header.Get("Authorization") != "completion-signature" || r.Header.Get("Cookie") != "" {
						t.Error("completion credentials")
					}
					if fail {
						fmt.Fprint(w, "<Error><Code>InvalidPart</Code></Error>")
					} else {
						fmt.Fprint(w, "<CompleteMultipartUploadResult/>")
					}
				case "/api/efast/v1/file/osendupload":
					finished = true
					w.WriteHeader(204)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
				}
			})
			base = s.URL
			c.token = "account-token"
			ctx := context.Background()
			_, e := c.MultipartOptions(ctx)
			check(t, e)
			u, e := c.BeginMultipart(ctx, "root", "file.bin", 4)
			check(t, e)
			gs, e := c.PartGrants(ctx, u, 1, 2)
			check(t, e)
			p1, e := c.WritePart(ctx, gs[0], strings.NewReader("abc"), 3)
			check(t, e)
			p2, e := c.WritePart(ctx, gs[1], strings.NewReader("d"), 1)
			check(t, e)
			e = c.CompleteMultipart(ctx, u, []Part{p1, p2})
			if fail {
				if e == nil || finished {
					t.Fatal("provider error finalized")
				}
			} else {
				check(t, e)
				if !finished {
					t.Fatal("not finalized")
				}
			}
			if e = c.CompleteMultipart(ctx, u, []Part{p2, p1}); e == nil {
				t.Fatal("unordered parts accepted")
			}
		})
	}
}

func TestShareTokenIsolationAndCRUD(t *testing.T) {
	var base string
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/shared-link/v1/document/anonymous":
			reply(w, map[string]string{"id": "fixture-share"})
		case "/api/shared-link/v1/document/anonymous/fixture-share":
			if r.Method != "PUT" && r.Method != "DELETE" {
				t.Error("method")
			}
			w.WriteHeader(204)
		case "/api/shared-link/v1/document/folder/file":
			reply(w, []Share{})
		case "/api/shared-link/v1/links/fixture-share":
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("account leaked to public share metadata")
			}
			reply(w, map[string]bool{"password_required": true})
		case "/link":
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("account leaked to share login")
			}
			var in map[string]any
			check(t, json.NewDecoder(r.Body).Decode(&in))
			if in["password"] != "fixture-password" {
				t.Error("password")
			}
			w.Header().Add("Set-Cookie", "link_token:fixture-share=share%2Btoken; Path=/; Secure")
			w.Header().Add("Set-Cookie", "INGRESSCOOKIE=share-affinity; Path=/; Secure")
			http.Redirect(w, r, "/share-landing", 302)
		case "/share-landing":
			t.Error("share token must be validated without visiting the editor UI")
			w.WriteHeader(503)
		case "/api/efast/v1/entry-item":
			if r.Header.Get("Authorization") != "Bearer share+token" || r.Header.Get("Cookie") != "INGRESSCOOKIE=share-affinity" {
				t.Error("share token isolation")
			}
			reply(w, []any{map[string]any{"id": "file", "name": "shared.bin", "size": 4}})
		case "/api/efast/v1/file/osdownload":
			if r.Header.Get("Authorization") != "Bearer share+token" {
				t.Error("wrong token")
			}
			reply(w, map[string]any{"authrequest": []string{"GET", base + "/object"}})
		case "/object":
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("share token leaked to object")
			}
			fmt.Fprint(w, "test")
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	base = s.URL
	c.token = "personal-token"
	ctx := context.Background()
	share, e := c.CreateShare(ctx, Share{Title: "test", LimitedTimes: -1, Item: ShareItem{ID: "file", Type: "file", Allow: []string{"download"}}})
	check(t, e)
	check(t, c.UpdateShare(ctx, share))
	_, e = c.Shares(ctx, "file")
	check(t, e)
	entry, e := c.ResolveShare(ctx, share.ID, "fixture-password")
	check(t, e)
	if c.token != "personal-token" {
		t.Fatal("share replaced personal account")
	}
	raw, _ := json.Marshal(entry)
	if bytes.Contains(raw, []byte("share+token")) {
		t.Fatal("share authority serialized")
	}
	var dst bytes.Buffer
	_, e = c.DownloadShared(ctx, entry, &dst)
	check(t, e)
	if dst.String() != "test" {
		t.Fatal("share download")
	}
	check(t, c.DeleteShare(ctx, share.ID))
}

func TestOptionalTransferOperations(t *testing.T) {
	var base string
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/efast/v1/file/predupload":
			reply(w, map[string]bool{"match": true})
		case "/api/efast/v1/file/dupload":
			reply(w, map[string]bool{"success": true})
		case "/api/efast/v1/file/batchdownload":
			reply(w, map[string]string{"url": base + "/archive"})
		case "/archive":
			fmt.Fprint(w, "zip-fixture")
		case "/api/doc-share/v1/docs-shared-with-anyone":
			reply(w, map[string]any{"entries": []any{map[string]any{"doc": map[string]string{"id": "file", "type": "file"}, "link_configs": []any{map[string]any{"id": "share", "title": "Test", "allow": []string{"download"}, "limited_times": -1}}}}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	base = s.URL
	c.token = "fixture-token"
	ctx := context.Background()
	match, e := c.FastUploadAvailable(ctx, 4, strings.Repeat("a", 32))
	check(t, e)
	if !match {
		t.Fatal("match")
	}
	check(t, c.FastUpload(ctx, "root", "fast.bin", 4, strings.Repeat("a", 32), "12345678"))
	var dst bytes.Buffer
	_, e = c.DownloadArchive(ctx, "files", nil, []string{"file"}, &dst)
	check(t, e)
	if dst.String() != "zip-fixture" {
		t.Fatal("archive")
	}
	shares, e := c.ShareHistory(ctx)
	check(t, e)
	if len(shares) != 1 || shares[0].Item.ID != "file" {
		t.Fatal("share history")
	}
}

func TestSharedDirectoryPreservesScopedChildren(t *testing.T) {
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer share-authority" || r.Header.Get("Cookie") != "" {
			t.Error("share scope lost")
		}
		reply(w, map[string]any{"dirs": []any{map[string]any{"docid": "folder", "name": "child", "size": -1}}, "files": []any{map[string]any{"docid": "file", "name": "sample", "size": 4}}})
	})
	c.token = "personal-token"
	result, err := c.ListShared(context.Background(), SharedEntry{ID: "root", Name: "Shared", Size: -1, token: "share-authority"})
	check(t, err)
	if len(result.Files) != 1 || result.Files[0].token != "share-authority" || len(result.Directories) != 1 || result.Directories[0].token != "share-authority" {
		t.Fatal("child authority missing")
	}
}
