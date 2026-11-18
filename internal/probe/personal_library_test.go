package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/StuHelper/stuhelper-storage-bhpan"
)

func startProbeFixture(t *testing.T, libs []bhpan.Library) (*httptest.Server, *atomic.Int32, func() []string) {
	t.Helper()
	var base string
	var deptTouches atomic.Int32
	var mu sync.Mutex
	var createdParents []string
	var storedPayload []byte
	var tempDirName string
	var currentMovedName string
	var recycledName string
	var inRecycle bool

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
		var body map[string]any
		if r.Method == "POST" && r.URL.Path != "/login" && r.URL.Path != "/object" {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		docID, _ := body["docid"].(string)
		if docID == "gns://dept-lib" {
			deptTouches.Add(1)
		}

		switch r.URL.Path {
		case "/login":
			if r.URL.Query().Get("service") != "" {
				http.Redirect(w, r, base+"/anyshare/oauth2/login/callback", 302)
				return
			}
			if r.Method == "GET" {
				fmt.Fprint(w, `<input type="hidden" name="execution" value="exec-1">`)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sso", Value: "ok", Path: "/"})
			http.Redirect(w, r, "http://uc.buaa.edu.cn/", 302)
		case "/anyshare/oauth2/login":
			http.Redirect(w, r, "/anyshare/oauth2/login/callback", 302)
		case "/anyshare/oauth2/login/callback":
			http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "probe-token", Path: "/"})
			fmt.Fprint(w, "ok")
		case "/anyshare/oauth2/login/refreshToken":
			fmt.Fprint(w, "ok")
		case "/api/eacp/v1/user/get":
			writeJSON(map[string]any{"type": "user", "userid": "u-1"})
		case "/api/efast/v1/owned-doc-lib":
			writeJSON(libs)
		case "/api/efast/v1/quota/user":
			writeJSON(map[string]int64{"allocated": 1024, "used": 128})
		case "/api/efast/v1/dir/list":
			writeJSON(map[string]any{"dirs": []any{}, "files": []any{}})
		case "/api/efast/v1/dir/create":
			name, _ := body["name"].(string)
			mu.Lock()
			createdParents = append(createdParents, docID)
			if docID == "gns://personal-lib" {
				tempDirName = name
			}
			mu.Unlock()
			if docID == "gns://personal-lib" {
				writeJSON(map[string]string{"docid": "gns://personal-lib/tempdir"})
				return
			}
			writeJSON(map[string]string{"docid": docID + "/" + name})
		case "/api/efast/v1/file/osbeginupload":
			writeJSON(map[string]any{
				"docid":       "gns://personal-lib/tempdir/obj_1",
				"rev":         "rev1",
				"authrequest": []string{"PUT", base + "/object", "Authorization: sig", "X-Amz-Date: now", "Content-Type: application/octet-stream"},
			})
		case "/object":
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			storedPayload = b
			mu.Unlock()
			w.Header().Set("ETag", `"e1"`)
		case "/api/efast/v1/file/osendupload":
			w.WriteHeader(204)
		case "/api/efast/v1/file/osdownload":
			writeJSON(map[string]any{"authrequest": []string{"GET", base + "/download"}})
		case "/download":
			mu.Lock()
			b := append([]byte(nil), storedPayload...)
			mu.Unlock()
			_, _ = w.Write(b)
		case "/api/efast/v1/dir/size":
			writeJSON(map[string]int64{"totalsize": 10, "filenum": 1, "dirnum": 0})
		case "/api/efast/v1/file/getsuggestname":
			writeJSON(map[string]string{"name": "probe(1).bin"})
		case "/api/efast/v1/dir/rename":
			name, _ := body["name"].(string)
			if docID == "gns://personal-lib/tempdir/moved_1" {
				mu.Lock()
				currentMovedName = name
				mu.Unlock()
			}
			w.WriteHeader(200)
		case "/api/efast/v1/dir/copy":
			writeJSON(map[string]string{"docid": "gns://personal-lib/tempdir/nested/copied_1"})
		case "/api/efast/v1/dir/move":
			writeJSON(map[string]string{"docid": "gns://personal-lib/tempdir/moved_1"})
		case "/api/efast/v1/file/delete":
			mu.Lock()
			if docID == "gns://personal-lib/tempdir" {
				recycledName = tempDirName
			} else {
				recycledName = currentMovedName
			}
			inRecycle = true
			mu.Unlock()
			w.WriteHeader(200)
		case "/api/efast/v1/recycle/list":
			if docID != "gns://personal-lib" {
				writeJSON(map[string]any{"dirs": []any{}, "files": []any{}})
				return
			}
			mu.Lock()
			name := recycledName
			recycled := inRecycle
			mu.Unlock()
			if !recycled {
				writeJSON(map[string]any{"dirs": []any{}, "files": []any{}})
				return
			}
			writeJSON(map[string]any{
				"dirs":  []any{},
				"files": []any{map[string]any{"docid": "gns://recycle/moved_1", "name": name, "size": 50}},
			})
		case "/api/efast/v2/items/moved_1/all":
			mu.Lock()
			recycled := inRecycle
			mu.Unlock()
			if !recycled {
				w.WriteHeader(404)
				return
			}
			writeJSON(map[string]any{
				"object_id": "moved_1",
				"doc_id":    "gns://recycle/moved_1",
				"name":      "restore.bin",
				"rev":       "rev1",
				"size":      50,
				"type":      "file",
				"doc_lib":   map[string]string{"id": "gns://personal-lib"},
			})
		case "/api/efast/v1/recycle/restore":
			mu.Lock()
			inRecycle = false
			mu.Unlock()
			writeJSON(map[string]string{"docid": "gns://personal-lib/tempdir/moved_1"})
		case "/api/efast/v1/recycle/delete":
			mu.Lock()
			inRecycle = false
			mu.Unlock()
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	base = server.URL
	return server, &deptTouches, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), createdParents...)
	}
}

func TestProbeSelectsPersonalLibraryAndRefusesSharedFallback(t *testing.T) {
	ctx := context.Background()

	// 1. Department library first, personal library second: probe must only list/write user_doc_lib.
	s1, deptTouches1, parents1 := startProbeFixture(t, []bhpan.Library{
		{ID: "gns://dept-lib", Name: "Department Shared", Type: "department_doc_lib"},
		{ID: "gns://personal-lib", Name: "Personal", Type: "user_doc_lib"},
	})
	cfg1 := bhpan.Config{CloudURL: s1.URL, SSOURL: s1.URL, Transport: s1.Client().Transport, Timeout: time.Second}
	res1, failed1 := probeAccount(ctx, cfg1, 1, Account{Username: "u", Password: "p", Mode: "sso"}, Input{Files: true})
	if failed1 || res1["file_lifecycle"] != true || res1["temporary_directory_removed"] != true {
		t.Fatalf("expected personal library probe to succeed, got failed=%v res=%v", failed1, res1)
	}
	if deptTouches1.Load() != 0 {
		t.Fatalf("probe touched non-personal department library (%d times)", deptTouches1.Load())
	}
	gotParents := parents1()
	if len(gotParents) == 0 || gotParents[0] != "gns://personal-lib" {
		t.Fatalf("expected root mkdir in gns://personal-lib, got %v", gotParents)
	}

	// 2. Files=true when no user_doc_lib exists must fail without creating any directory in libs[0].
	s2, deptTouches2, parents2 := startProbeFixture(t, []bhpan.Library{
		{ID: "gns://dept-lib", Name: "Department Shared", Type: "department_doc_lib"},
	})
	cfg2 := bhpan.Config{CloudURL: s2.URL, SSOURL: s2.URL, Transport: s2.Client().Transport, Timeout: time.Second}
	for _, writeFiles := range []bool{false, true} {
		res, failed := probeAccount(ctx, cfg2, 1, Account{Username: "u", Password: "p", Mode: "sso"}, Input{Files: writeFiles})
		if !failed || res["error"] != "probe: personal library not found" {
			t.Fatalf("files=%v: expected missing personal library error, got %v", writeFiles, res)
		}
	}
	if deptTouches2.Load() != 0 || len(parents2()) != 0 {
		t.Fatalf("probe created or listed resources in shared library: touches=%d parents=%v", deptTouches2.Load(), parents2())
	}

	// 3. Ambiguous multiple user_doc_lib entries must fail without writing.
	s3, _, parents3 := startProbeFixture(t, []bhpan.Library{
		{ID: "gns://personal-1", Name: "Personal 1", Type: "user_doc_lib"},
		{ID: "gns://personal-2", Name: "Personal 2", Type: "user_doc_lib"},
	})
	cfg3 := bhpan.Config{CloudURL: s3.URL, SSOURL: s3.URL, Transport: s3.Client().Transport, Timeout: time.Second}
	if _, failed3 := probeAccount(ctx, cfg3, 1, Account{Username: "u", Password: "p", Mode: "sso"}, Input{Files: true}); !failed3 || len(parents3()) != 0 {
		t.Fatalf("expected ambiguous personal libraries to fail without creating directories, parents=%v", parents3())
	}
	_ = parents1
}
