package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/StuHelper/stuhelper-storage-bhpan"
)

type storedItem struct {
	id, parent, name, rev string
	isDir, deleted        bool
	data                  []byte
}

type storedShare struct {
	id, itemID, itemType, password string
}

func TestProbeFullLifecycleWithOptionalCapabilities(t *testing.T) {
	var mu sync.Mutex
	items := map[string]*storedItem{}
	shares := map[string]*storedShare{}
	seq := 0
	nextID := func() string {
		seq++
		return fmt.Sprintf("obj_%04d", seq)
	}
	const rootID = "gns://probe_root"
	var base string

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		replyJSON := func(v any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(v)
		}
		var in map[string]any
		if r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/api/") && r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&in)
		}
		str := func(k string) string { s, _ := in[k].(string); return s }

		mu.Lock()
		defer mu.Unlock()

		switch r.URL.Path {
		case "/anyshare/oauth2/login":
			http.Redirect(w, r, "/oauth2/signin?login_challenge=fixture", http.StatusFound)
		case "/oauth2/signin":
			if r.Method == "GET" {
				fmt.Fprint(w, `<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"challenge":"fixture","csrftoken":"fixture","device":{},"authconfig":{}}}}</script>`)
			} else {
				fmt.Fprint(w, `{"redirect":"/anyshare/oauth2/login/callback"}`)
			}
		case "/anyshare/oauth2/login/callback":
			http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "probe-token", Path: "/"})
			fmt.Fprint(w, "ok")
		case "/api/eacp/v1/user/get":
			replyJSON(map[string]any{"type": "user", "userid": "probe-uid"})
		case "/api/efast/v1/owned-doc-lib":
			replyJSON([]any{map[string]string{"id": rootID, "name": "Personal", "type": "user_doc_lib"}})
		case "/api/efast/v1/quota/user":
			replyJSON(map[string]int64{"allocated": 1 << 30, "used": 1024})
		case "/api/efast/v1/dir/create":
			oid := nextID()
			docID := str("docid") + "/" + oid
			items[oid] = &storedItem{id: oid, parent: str("docid"), name: str("name"), rev: "r1", isDir: true}
			replyJSON(map[string]string{"docid": docID})
		case "/api/efast/v1/dir/list":
			target := str("docid")
			dirs, files := []any{}, []any{}
			for _, it := range items {
				if !it.deleted && it.parent == target {
					full := it.parent + "/" + it.id
					if it.isDir {
						dirs = append(dirs, map[string]any{"docid": full, "name": it.name, "size": -1})
					} else {
						files = append(files, map[string]any{"docid": full, "name": it.name, "size": len(it.data)})
					}
				}
			}
			replyJSON(map[string]any{"dirs": dirs, "files": files})
		case "/api/efast/v1/dir/size":
			replyJSON(map[string]int64{"totalsize": 64, "filenum": 1, "dirnum": 0})
		case "/api/efast/v1/file/getsuggestname":
			replyJSON(map[string]string{"name": str("name")})
		case "/api/efast/v1/dir/rename":
			oid := str("docid")[strings.LastIndex(str("docid"), "/")+1:]
			if it := items[oid]; it != nil {
				it.name = str("name")
			}
			w.WriteHeader(http.StatusOK)
		case "/api/efast/v1/dir/copy":
			srcOID := str("docid")[strings.LastIndex(str("docid"), "/")+1:]
			src := items[srcOID]
			oid := nextID()
			items[oid] = &storedItem{id: oid, parent: str("destparent"), name: src.name, rev: "r1", data: append([]byte(nil), src.data...)}
			replyJSON(map[string]string{"docid": str("destparent") + "/" + oid})
		case "/api/efast/v1/dir/move":
			oid := str("docid")[strings.LastIndex(str("docid"), "/")+1:]
			it := items[oid]
			it.parent = str("destparent")
			replyJSON(map[string]string{"docid": it.parent + "/" + oid})
		case "/api/efast/v1/file/delete":
			oid := str("docid")[strings.LastIndex(str("docid"), "/")+1:]
			if it := items[oid]; it != nil {
				it.deleted = true
			}
			w.WriteHeader(http.StatusOK)
		case "/api/efast/v1/recycle/list":
			dirs, files := []any{}, []any{}
			for _, it := range items {
				if it.deleted {
					recID := rootID + "/recycle/" + it.id
					if it.isDir {
						dirs = append(dirs, map[string]any{"docid": recID, "name": it.name, "size": -1})
					} else {
						files = append(files, map[string]any{"docid": recID, "name": it.name, "size": len(it.data)})
					}
				}
			}
			replyJSON(map[string]any{"dirs": dirs, "files": files})
		case "/api/efast/v1/recycle/restore":
			oid := str("docid")[strings.LastIndex(str("docid"), "/")+1:]
			it := items[oid]
			it.deleted = false
			replyJSON(map[string]string{"docid": it.parent + "/" + oid})
		case "/api/efast/v1/recycle/delete":
			oid := str("docid")[strings.LastIndex(str("docid"), "/")+1:]
			delete(items, oid)
			w.WriteHeader(http.StatusOK)
		case "/api/efast/v1/file/osbeginupload":
			oid := nextID()
			items[oid] = &storedItem{id: oid, parent: str("docid"), name: str("name"), rev: "r1"}
			replyJSON(map[string]any{"docid": str("docid") + "/" + oid, "rev": "r1", "authrequest": []string{"PUT", base + "/put/" + oid, "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/octet-stream"}})
		case "/api/efast/v1/file/osendupload":
			w.WriteHeader(http.StatusNoContent)
		case "/api/efast/v1/file/osdownload":
			oid := str("docid")[strings.LastIndex(str("docid"), "/")+1:]
			replyJSON(map[string]any{"authrequest": []string{"GET", base + "/get/" + oid}})
		case "/api/efast/v1/file/predupload":
			replyJSON(map[string]bool{"match": true})
		case "/api/efast/v1/file/dupload":
			oid := nextID()
			items[oid] = &storedItem{id: oid, parent: str("docid"), name: str("name"), rev: "r1"}
			replyJSON(map[string]any{"success": true, "docid": str("docid") + "/" + oid, "rev": "r1"})
		case "/api/efast/v1/file/batchdownload":
			replyJSON(map[string]string{"url": base + "/archive-zip"})
		case "/archive-zip":
			_, _ = w.Write([]byte("PK\x03\x04probe-archive"))
		case "/api/efast/v1/file/osoption":
			replyJSON(map[string]int64{"partminsize": 16, "partmaxsize": 1024, "partmaxnum": 10})
		case "/api/efast/v1/file/osinitmultiupload":
			oid := nextID()
			items[oid] = &storedItem{id: oid, parent: str("docid"), name: str("name"), rev: "r1"}
			replyJSON(map[string]string{"docid": str("docid") + "/" + oid, "rev": "r1", "uploadid": "mu1"})
		case "/api/efast/v1/file/osuploadpart":
			oid := str("docid")[strings.LastIndex(str("docid"), "/")+1:]
			replyJSON(map[string]any{"authrequests": map[string]any{
				"1": []string{"PUT", base + "/part/" + oid + "/1", "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/octet-stream"},
				"2": []string{"PUT", base + "/part/" + oid + "/2", "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/octet-stream"},
			}})
		case "/api/efast/v1/file/oscompleteupload":
			var b bytes.Buffer
			mw := multipart.NewWriter(&b)
			p, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": []string{"application/json"}})
			_ = json.NewEncoder(p).Encode(map[string]any{"authrequest": []string{"POST", base + "/complete", "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/xml"}})
			p, _ = mw.CreatePart(textproto.MIMEHeader{"Content-Type": []string{"application/xml"}})
			_, _ = fmt.Fprint(p, "<CompleteMultipartUpload/>")
			_ = mw.Close()
			w.Header().Set("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
			_, _ = w.Write(b.Bytes())
		case "/complete":
			fmt.Fprint(w, "<CompleteMultipartUploadResult/>")
		case "/api/shared-link/v1/document/anonymous":
			var sh bhpan.Share
			rawIn, _ := json.Marshal(in)
			_ = json.Unmarshal(rawIn, &sh)
			sid := nextID()
			shares[sid] = &storedShare{id: sid, itemID: sh.Item.ID, itemType: sh.Item.Type, password: str("password")}
			replyJSON(map[string]string{"id": sid})
		case "/api/doc-share/v1/docs-shared-with-anyone":
			replyJSON(map[string]any{"entries": []any{}})
		case "/link":
			var linkReq map[string]any
			_ = json.NewDecoder(r.Body).Decode(&linkReq)
			sid, _ := linkReq["id"].(string)
			if sh := shares[sid]; sh == nil || sh.password == "" || linkReq["password"] != sh.password {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Add("Set-Cookie", "link_token:"+sid+"=tok-"+sid+"; Path=/; Secure")
			http.Redirect(w, r, "/landing", http.StatusFound)
		case "/api/efast/v1/entry-item":
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer tok-")
			sh := shares[tok]
			oid := sh.itemID[strings.LastIndex(sh.itemID, "/")+1:]
			it := items[oid]
			if it.isDir {
				replyJSON([]any{map[string]any{"id": sh.itemID, "name": it.name}})
			} else {
				replyJSON([]any{map[string]any{"id": sh.itemID, "name": it.name, "size": len(it.data)}})
			}
		default:
			switch {
			case strings.HasPrefix(r.URL.Path, "/put/"):
				oid := strings.TrimPrefix(r.URL.Path, "/put/")
				mu.Unlock()
				data, _ := io.ReadAll(r.Body)
				mu.Lock()
				items[oid].data = data
				w.Header().Set("ETag", `"e1"`)
			case strings.HasPrefix(r.URL.Path, "/part/"):
				segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/part/"), "/")
				oid := segs[0]
				mu.Unlock()
				chunk, _ := io.ReadAll(r.Body)
				mu.Lock()
				if segs[1] == "1" {
					items[oid].data = append([]byte(nil), chunk...)
				} else {
					items[oid].data = append(items[oid].data, chunk...)
				}
				w.Header().Set("ETag", `"epart"`)
			case strings.HasPrefix(r.URL.Path, "/get/"):
				oid := strings.TrimPrefix(r.URL.Path, "/get/")
				_, _ = w.Write(items[oid].data)
			case strings.HasPrefix(r.URL.Path, "/api/efast/v2/items/") && strings.HasSuffix(r.URL.Path, "/all"):
				oid := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/efast/v2/items/"), "/all")
				it := items[oid]
				if it == nil {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				docID := it.parent + "/" + it.id
				if it.deleted {
					docID = rootID + "/recycle/" + it.id
				}
				replyJSON(map[string]any{"object_id": oid, "doc_id": docID, "name": it.name, "rev": it.rev, "size": len(it.data), "type": "file", "doc_lib": map[string]string{"id": rootID}})
			case strings.HasPrefix(r.URL.Path, "/api/shared-link/v1/document/anonymous/"):
				sid := strings.TrimPrefix(r.URL.Path, "/api/shared-link/v1/document/anonymous/")
				if r.Method == http.MethodDelete {
					delete(shares, sid)
				}
				w.WriteHeader(http.StatusNoContent)
			case strings.HasPrefix(r.URL.Path, "/api/shared-link/v1/document/folder/"):
				replyJSON([]any{})
			case strings.HasPrefix(r.URL.Path, "/api/shared-link/v1/links/"):
				replyJSON(map[string]bool{"password_required": true})
			default:
				t.Errorf("unhandled probe route: %s %s", r.Method, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		}
	}))
	t.Cleanup(srv.Close)
	base = srv.URL

	cfg := bhpan.Config{CloudURL: base, Transport: srv.Client().Transport, Timeout: 5 * time.Second}
	stdinJSON, _ := json.Marshal(Input{
		Accounts:        []Account{{Username: "probe-secret-user", Password: "probe-secret-password"}},
		Files:           true,
		Multipart:       true,
		Shares:          true,
		FastUpload:      true,
		Archive:         true,
		SharedDirectory: true,
	})
	var stdout bytes.Buffer
	if err := Run(context.Background(), cfg, bytes.NewReader(stdinJSON), &stdout); err != nil {
		t.Fatalf("probe.Run failed: %v\noutput: %s", err, stdout.String())
	}
	outStr := stdout.String()
	if strings.Contains(outStr, "probe-secret-user") || strings.Contains(outStr, "probe-secret-password") {
		t.Fatalf("credentials leaked in probe output: %s", outStr)
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	for _, flag := range []string{
		"login", "identity_valid", "quota_valid", "root_list_valid",
		"temporary_directory_created", "temporary_directory_removed",
		"upload_download_checksum", "recycle_object_id_preserved", "permanent_absence_verified",
		"fast_upload_preflight", "fast_upload_created", "archive_download_valid",
		"multipart_checksum", "protected_share_checksum", "share_history_valid", "shared_directory_checksum",
	} {
		if report[flag] != true {
			t.Errorf("expected %s=true, got %v", flag, report[flag])
		}
	}

	// Input validation errors.
	if err := Run(context.Background(), cfg, strings.NewReader(`{}`), &bytes.Buffer{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
	if err := Run(context.Background(), cfg, strings.NewReader(`{"Accounts":[{"Username":"u","Password":"p","Mode":"bad"}]}`), &bytes.Buffer{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("expected ErrInvalidInput, got %v", err)
	}
}
