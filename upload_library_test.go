package bhpan

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestPersonalLibraryUploadResultAndPartGrant(t *testing.T) {
	ctx := context.Background()

	// 1. PersonalLibrary strictly selects Type == "user_doc_lib".
	t.Run("personal-library", func(t *testing.T) {
		mode := "single"
		c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			switch mode {
			case "single":
				reply(w, []any{
					map[string]string{"id": "gns://dept", "name": "Department", "type": "department_doc_lib"},
					map[string]string{"id": "gns://personal", "name": "Personal", "type": "user_doc_lib", "rev": "r0"},
				})
			case "missing":
				reply(w, []any{map[string]string{"id": "gns://group", "name": "Group", "type": "group_doc_lib"}})
			case "duplicate":
				reply(w, []any{
					map[string]string{"id": "gns://p1", "name": "P1", "type": "user_doc_lib"},
					map[string]string{"id": "gns://p2", "name": "P2", "type": "user_doc_lib"},
				})
			}
		})
		c.token = "fixture-token"

		lib, err := c.PersonalLibrary(ctx)
		check(t, err)
		if lib.ID != "gns://personal" || lib.Type != "user_doc_lib" {
			t.Fatalf("unexpected library: %+v", lib)
		}

		mode = "missing"
		if _, err := c.PersonalLibrary(ctx); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound when user_doc_lib absent, got %v", err)
		}

		mode = "duplicate"
		if _, err := c.PersonalLibrary(ctx); !errors.Is(err, ErrProtocol) {
			t.Fatalf("expected ErrProtocol when multiple user_doc_lib returned, got %v", err)
		}
	})

	// 2. FastUpload and FinishUploadResult return DocumentID & Revision, and PartGrant exposes read-only Number & Deadline.
	t.Run("upload-result-and-part-grant", func(t *testing.T) {
		var base string
		finishMode := "json"
		fastMode := "ok"
		c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/efast/v1/file/dupload":
				switch fastMode {
				case "ok":
					reply(w, map[string]any{"success": true, "docid": "gns://personal/fast-doc", "rev": "rev-fast-2"})
				case "false":
					reply(w, map[string]any{"success": false})
				case "missing-id":
					reply(w, map[string]any{"success": true, "rev": "rev-only"})
				}
			case "/api/efast/v1/file/osendupload":
				switch finishMode {
				case "json":
					reply(w, map[string]string{"docid": "gns://personal/final-doc", "rev": "rev-final-3"})
				case "empty-204":
					w.WriteHeader(http.StatusNoContent)
				case "empty-json":
					reply(w, map[string]any{})
				case "bad-rev":
					reply(w, map[string]string{"docid": "gns://personal/final-doc", "rev": ""})
				}
			case "/api/efast/v1/file/osuploadpart":
				reply(w, map[string]any{"authrequests": map[string]any{
					"1": []string{"PUT", base + "/part1", "Authorization: sig1", "X-Amz-Date: d", "Content-Type: application/octet-stream"},
					"2": []string{"PUT", base + "/part2", "Authorization: sig2", "X-Amz-Date: d", "Content-Type: application/octet-stream"},
				}})
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
			}
		})
		base = s.URL
		c.token = "fixture-token"

		fastRes, err := c.FastUpload(ctx, "gns://personal", "paper.pdf", 128, strings.Repeat("b", 32), "89abcdef")
		check(t, err)
		if fastRes.DocumentID != "gns://personal/fast-doc" || fastRes.Revision != "rev-fast-2" {
			t.Fatalf("unexpected FastUpload result: %+v", fastRes)
		}

		fastMode = "false"
		if _, err := c.FastUpload(ctx, "gns://personal", "paper.pdf", 128, strings.Repeat("b", 32), "89abcdef"); !errors.Is(err, ErrRejected) {
			t.Fatalf("expected ErrRejected when success=false, got %v", err)
		}

		fastMode = "missing-id"
		if _, err := c.FastUpload(ctx, "gns://personal", "paper.pdf", 128, strings.Repeat("b", 32), "89abcdef"); !errors.Is(err, ErrProtocol) {
			t.Fatalf("expected ErrProtocol when docid missing, got %v", err)
		}

		finRes, err := c.FinishUploadResult(ctx, "gns://personal/init-doc", "rev-1")
		check(t, err)
		if finRes.DocumentID != "gns://personal/final-doc" || finRes.Revision != "rev-final-3" {
			t.Fatalf("unexpected FinishUploadResult JSON: %+v", finRes)
		}

		finishMode = "empty-204"
		finRes, err = c.FinishUploadResult(ctx, "gns://personal/init-doc", "rev-1")
		check(t, err)
		if finRes.DocumentID != "gns://personal/init-doc" || finRes.Revision != "rev-1" {
			t.Fatalf("unexpected FinishUploadResult 204 fallback: %+v", finRes)
		}

		finishMode = "empty-json"
		check(t, c.FinishUpload(ctx, "gns://personal/init-doc", "rev-1"))

		finishMode = "bad-rev"
		if _, err := c.FinishUploadResult(ctx, "gns://personal/init-doc", "rev-1"); !errors.Is(err, ErrProtocol) {
			t.Fatalf("expected ErrProtocol on empty rev field, got %v", err)
		}

		before := time.Now()
		grants, err := c.PartGrants(ctx, MultipartUpload{DocumentID: "gns://personal/m", Revision: "r1", UploadID: "u1"}, 1, 2)
		check(t, err)
		if len(grants) != 2 || grants[0].Number() != 1 || grants[1].Number() != 2 {
			t.Fatalf("unexpected PartGrant numbers: %d, %d", grants[0].Number(), grants[1].Number())
		}
		if !grants[0].Deadline().After(before.Add(9*time.Minute)) || grants[0].Deadline().After(time.Now().Add(11*time.Minute)) {
			t.Fatalf("unexpected PartGrant deadline: %v", grants[0].Deadline())
		}
	})
}
