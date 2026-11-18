package bhpan

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
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingResponseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	body        bytes.Buffer
}

func (r *recordingResponseWriter) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recordingResponseWriter) Write(p []byte) (int, error) {
	if !r.wroteHeader {
		r.status = http.StatusOK
		r.wroteHeader = true
	}
	_, _ = r.body.Write(p)
	return r.ResponseWriter.Write(p)
}

func isContractRoute(r *http.Request) bool {
	escaped := r.URL.EscapedPath()
	if strings.HasPrefix(escaped, "/api/") {
		return true
	}
	if escaped == "/link" || strings.HasPrefix(escaped, "/link/") {
		return true
	}
	if escaped == "/oauth2/signin" && r.Method == http.MethodPost {
		return true
	}
	return false
}

// contractMiddleware validates every contract-governed HTTP request and, when
// checkResponse is true, every fixture HTTP status code and response payload
// against contracts/bhpan.openapi.json.
func contractMiddleware(t *testing.T, checkResponse bool, seen map[string]bool, mu *sync.Mutex, next http.Handler) http.Handler {
	t.Helper()
	raw, err := os.ReadFile("contracts/bhpan.openapi.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(map[string]any)
	schemas := doc["components"].(map[string]any)["schemas"].(map[string]any)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Helper()
		if !isContractRoute(r) {
			next.ServeHTTP(w, r)
			return
		}
		escaped := r.URL.EscapedPath()
		var methods map[string]any
		for pattern, candidate := range paths {
			if pathMatches(pattern, escaped) {
				methods = candidate.(map[string]any)
				break
			}
		}
		if methods == nil {
			t.Errorf("request path is absent from provider contract: %s", escaped)
			next.ServeHTTP(w, r)
			return
		}
		operation, ok := methods[strings.ToLower(r.Method)].(map[string]any)
		if !ok {
			t.Errorf("request method is absent from contract: %s %s", r.Method, escaped)
			next.ServeHTTP(w, r)
			return
		}
		opID, _ := operation["operationId"].(string)
		if seen != nil && mu != nil && opID != "" {
			mu.Lock()
			seen[opID] = true
			mu.Unlock()
		}
		if requestBody, ok := operation["requestBody"].(map[string]any); ok {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error("cannot inspect fixture request")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var value any
			if json.Unmarshal(body, &value) != nil {
				t.Errorf("contract %s requires JSON request body", opID)
				return
			}
			schema := requestBody["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
			if !conforms(schema, value, schemas) {
				t.Errorf("request does not conform to %s", opID)
			}
		}
		rec := &recordingResponseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		if !checkResponse {
			return
		}
		responses, _ := operation["responses"].(map[string]any)
		respSpec, ok := responses[strconv.Itoa(rec.status)].(map[string]any)
		if !ok {
			t.Errorf("response status %d is absent from contract %s (%s %s)", rec.status, opID, r.Method, escaped)
			return
		}
		content, _ := respSpec["content"].(map[string]any)
		if jsonMedia, ok := content["application/json"].(map[string]any); ok {
			respSchema, _ := jsonMedia["schema"].(map[string]any)
			var respVal any
			if json.Unmarshal(rec.body.Bytes(), &respVal) != nil {
				t.Errorf("response for %s (HTTP %d) is not valid JSON", opID, rec.status)
				return
			}
			if !conforms(respSchema, respVal, schemas) {
				t.Errorf("response for %s does not conform to contract schema: %s", opID, rec.body.String())
			}
		}
		if _, ok := content["multipart/mixed"].(map[string]any); ok {
			if !strings.HasPrefix(rec.Header().Get("Content-Type"), "multipart/") {
				t.Errorf("response for %s must be multipart/*, got %q", opID, rec.Header().Get("Content-Type"))
			}
		}
	})
}

func contractValidator(t *testing.T) func(*http.Request) {
	t.Helper()
	handler := contractMiddleware(t, false, nil, nil, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	return func(r *http.Request) { handler.ServeHTTP(httptest.NewRecorder(), r) }
}

func pathMatches(pattern, escapedPath string) bool {
	left, right := strings.Split(pattern, "/"), strings.Split(escapedPath, "/")
	if len(left) != len(right) {
		return false
	}
	for i, part := range left {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			if right[i] == "" || right[i] == "." || right[i] == ".." {
				return false
			}
			continue
		}
		if part != right[i] {
			return false
		}
	}
	return true
}

func conforms(schema map[string]any, value any, definitions map[string]any) bool {
	if ref, ok := schema["$ref"].(string); ok {
		return conforms(definitions[strings.TrimPrefix(ref, "#/components/schemas/")].(map[string]any), value, definitions)
	}
	if choices, ok := schema["oneOf"].([]any); ok {
		for _, choice := range choices {
			if conforms(choice.(map[string]any), value, definitions) {
				return true
			}
		}
		return false
	}
	switch schema["type"] {
	case "string":
		s, ok := value.(string)
		if !ok {
			return false
		}
		if minLen, ok := schema["minLength"].(float64); ok && len(s) < int(minLen) {
			return false
		}
		if maxLen, ok := schema["maxLength"].(float64); ok && len(s) > int(maxLen) {
			return false
		}
		if pat, ok := schema["pattern"].(string); ok {
			re, err := regexp.Compile(pat)
			if err != nil || !re.MatchString(s) {
				return false
			}
		}
		if enumVals, ok := schema["enum"].([]any); ok {
			matched := slices.ContainsFunc(enumVals, func(item any) bool {
				es, ok := item.(string)
				return ok && es == s
			})
			if !matched {
				return false
			}
		}
		return true
	case "integer":
		v, ok := value.(float64)
		if !ok || v != float64(int64(v)) {
			return false
		}
		if minVal, ok := schema["minimum"].(float64); ok && v < minVal {
			return false
		}
		if maxVal, ok := schema["maximum"].(float64); ok && v > maxVal {
			return false
		}
		return true
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "array":
		a, ok := value.([]any)
		if !ok {
			return false
		}
		if n, ok := schema["minItems"].(float64); ok && len(a) < int(n) {
			return false
		}
		if n, ok := schema["maxItems"].(float64); ok && len(a) > int(n) {
			return false
		}
		for _, v := range a {
			if !conforms(schema["items"].(map[string]any), v, definitions) {
				return false
			}
		}
		return true
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		if required, ok := schema["required"].([]any); ok {
			for _, field := range required {
				if _, exists := object[field.(string)]; !exists {
					return false
				}
			}
		}
		props, _ := schema["properties"].(map[string]any)
		disallowExtra := false
		if allow, ok := schema["additionalProperties"].(bool); ok && !allow {
			disallowExtra = true
		}
		for key, v := range object {
			if child, ok := props[key].(map[string]any); ok {
				if !conforms(child, v, definitions) {
					return false
				}
			} else if disallowExtra {
				return false
			} else if child, ok := schema["additionalProperties"].(map[string]any); ok {
				if !conforms(child, v, definitions) {
					return false
				}
			} else if allowed, ok := schema["additionalProperties"].(bool); ok && !allowed {
				return false
			}
		}
		return true
	}
	return false
}

func TestAllContractOperationsAndPublicShare(t *testing.T) {
	raw, err := os.ReadFile("contracts/bhpan.openapi.json")
	check(t, err)
	var doc map[string]any
	check(t, json.Unmarshal(raw, &doc))
	wantOps := map[string]bool{}
	for _, methods := range doc["paths"].(map[string]any) {
		for _, op := range methods.(map[string]any) {
			wantOps[op.(map[string]any)["operationId"].(string)] = true
		}
	}

	var mu sync.Mutex
	seenOps := map[string]bool{}
	var base string
	const rootGNS = "gns://lib_root_01"
	const docGNS = "gns://lib_root_01/doc_item_01"

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/anyshare/oauth2/login":
			http.Redirect(w, r, "/oauth2/signin?login_challenge=ch-35", http.StatusFound)
		case "/oauth2/signin":
			if r.Method == http.MethodGet {
				fmt.Fprint(w, `<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"challenge":"ch-35","csrftoken":"csrf-35","device":{"client_type":"web"},"authconfig":{}}}}</script>`)
				return
			}
			reply(w, map[string]string{"redirect": base + "/anyshare/oauth2/login/callback"})
		case "/anyshare/oauth2/login/callback":
			http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "tok-35", Path: "/"})
			fmt.Fprint(w, "ok")
		case "/api/eacp/v1/user/get":
			reply(w, map[string]any{"type": "user", "userid": "uid-35"})
		case "/api/efast/v2/items/doc_item_01/all":
			reply(w, map[string]any{"object_id": "doc_item_01", "doc_id": docGNS, "name": "book.pdf", "rev": "r1", "size": 5, "type": "file", "doc_lib": map[string]string{"id": rootGNS}})
		case "/api/efast/v1/owned-doc-lib":
			reply(w, []any{map[string]string{"id": rootGNS, "name": "Personal", "type": "user_doc_lib", "rev": "r0"}})
		case "/api/efast/v1/quota/user":
			reply(w, map[string]int64{"allocated": 1024, "used": 128})
		case "/api/efast/v1/dir/list", "/api/efast/v1/recycle/list":
			reply(w, map[string]any{"dirs": []any{}, "files": []any{map[string]any{"docid": docGNS, "name": "book.pdf", "size": 5}}})
		case "/api/efast/v1/dir/size":
			reply(w, map[string]int64{"totalsize": 5, "dirnum": 0, "filenum": 1})
		case "/api/efast/v1/file/getsuggestname":
			reply(w, map[string]string{"name": "book(1).pdf"})
		case "/api/efast/v1/dir/create", "/api/efast/v1/dir/copy", "/api/efast/v1/dir/move", "/api/efast/v1/recycle/restore":
			reply(w, map[string]string{"docid": docGNS})
		case "/api/efast/v1/dir/rename", "/api/efast/v1/file/delete", "/api/efast/v1/recycle/delete":
			w.WriteHeader(http.StatusOK)
		case "/api/efast/v1/file/osbeginupload":
			reply(w, map[string]any{"docid": docGNS, "rev": "r1", "authrequest": []string{"PUT", base + "/data-put", "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/octet-stream"}})
		case "/api/efast/v1/file/osendupload":
			w.WriteHeader(http.StatusNoContent)
		case "/api/efast/v1/file/osoption":
			reply(w, map[string]int64{"partminsize": 4, "partmaxsize": 16, "partmaxnum": 10})
		case "/api/efast/v1/file/osinitmultiupload":
			reply(w, map[string]string{"docid": docGNS, "rev": "r2", "uploadid": "up-1"})
		case "/api/efast/v1/file/osuploadpart":
			reply(w, map[string]any{"authrequests": map[string]any{"1": []string{"PUT", base + "/data-put", "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/octet-stream"}}})
		case "/api/efast/v1/file/oscompleteupload":
			var b bytes.Buffer
			mw := multipart.NewWriter(&b)
			p, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": []string{"application/json"}})
			_ = json.NewEncoder(p).Encode(map[string]any{"authrequest": []string{"POST", base + "/data-complete", "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/xml"}})
			p, _ = mw.CreatePart(textproto.MIMEHeader{"Content-Type": []string{"application/xml"}})
			_, _ = fmt.Fprint(p, "<CompleteMultipartUpload/>")
			_ = mw.Close()
			w.Header().Set("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
			_, _ = w.Write(b.Bytes())
		case "/api/efast/v1/file/osdownload":
			reply(w, map[string]any{"authrequest": []string{"GET", base + "/data-get"}})
		case "/api/efast/v1/file/predupload":
			reply(w, map[string]bool{"match": true})
		case "/api/efast/v1/file/dupload":
			reply(w, map[string]bool{"success": true})
		case "/api/efast/v1/file/batchdownload":
			reply(w, map[string]string{"url": base + "/data-get"})
		case "/api/shared-link/v1/document/anonymous":
			reply(w, map[string]string{"id": "pub-share-01"})
		case "/api/shared-link/v1/document/anonymous/pub-share-01":
			w.WriteHeader(http.StatusNoContent)
		case "/api/shared-link/v1/document/folder/" + docGNS:
			reply(w, []shareResponse{{ID: "pub-share-01", Title: "Public", ExpiresAt: "2026-12-31T00:00:00Z", Password: "", LimitedTimes: -1, Item: ShareItem{ID: docGNS, Type: "file", Allow: []string{"download"}}}})
		case "/api/doc-share/v1/docs-shared-with-anyone":
			reply(w, map[string]any{"entries": []any{map[string]any{"doc": map[string]any{"id": docGNS, "type": "file", "allow": []string{"download"}}, "link_configs": []any{map[string]any{"id": "pub-share-01", "title": "Public", "allow": []string{"download"}, "limited_times": -1}}}}})
		case "/api/shared-link/v1/links/pub-share-01":
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("personal credentials leaked to public share metadata")
			}
			reply(w, map[string]bool{"password_required": false})
		case "/link/pub-share-01":
			if r.Method != http.MethodGet || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("invalid unprotected share token request")
			}
			w.Header().Add("Set-Cookie", "link_token:pub-share-01=public-share-token; Path=/; Secure")
			w.Header().Add("Set-Cookie", "INGRESSCOOKIE=public-route; Path=/; Secure")
			http.Redirect(w, r, "/share-ui", http.StatusFound)
		case "/api/shared-link/v1/links/prot-share-01":
			reply(w, map[string]bool{"password_required": true})
		case "/link":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			if in["password"] != "correct-code" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Add("Set-Cookie", "link_token:prot-share-01=prot-share-token; Path=/; Secure")
			http.Redirect(w, r, "/share-ui", http.StatusFound)
		case "/api/efast/v1/entry-item":
			reply(w, []any{map[string]any{"id": docGNS, "name": "book.pdf", "size": 5}})
		case "/data-put":
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("ETag", `"etag-35"`)
		case "/data-complete":
			_, _ = io.Copy(io.Discard, r.Body)
			fmt.Fprint(w, "<CompleteMultipartUploadResult/>")
		case "/data-get":
			fmt.Fprint(w, "hello")
		default:
			t.Errorf("unexpected path %s (escaped %s)", r.URL.Path, r.URL.EscapedPath())
			w.WriteHeader(http.StatusNotFound)
		}
	})

	server := httptest.NewTLSServer(contractMiddleware(t, true, seenOps, &mu, handler))
	t.Cleanup(server.Close)
	base = server.URL
	c, err := New(Config{CloudURL: base, SSOURL: base, Transport: server.Client().Transport, Timeout: 2 * time.Second})
	check(t, err)
	t.Cleanup(c.Close)
	ctx := context.Background()

	check(t, c.LoginLocal(ctx, "student", "secret-password"))
	_, err = c.Identity(ctx)
	check(t, err)
	_, err = c.FileInfo(ctx, "doc_item_01")
	check(t, err)
	_, err = c.Libraries(ctx)
	check(t, err)
	_, err = c.Quota(ctx)
	check(t, err)
	_, err = c.List(ctx, rootGNS)
	check(t, err)
	_, err = c.DirectorySize(ctx, rootGNS)
	check(t, err)
	_, err = c.SuggestedName(ctx, rootGNS, "book.pdf")
	check(t, err)
	_, err = c.CreateDirectory(ctx, rootGNS, "sub")
	check(t, err)
	check(t, c.Rename(ctx, docGNS, "renamed.pdf"))
	_, err = c.Copy(ctx, docGNS, rootGNS)
	check(t, err)
	_, err = c.Move(ctx, docGNS, rootGNS)
	check(t, err)
	check(t, c.Delete(ctx, docGNS))
	_, err = c.RecycleBin(ctx, rootGNS, 0, 50)
	check(t, err)
	_, err = c.Restore(ctx, docGNS)
	check(t, err)
	check(t, c.Purge(ctx, docGNS))

	up, err := c.BeginUpload(ctx, rootGNS, "book.pdf", 5)
	check(t, err)
	_, err = c.WriteUpload(ctx, up, strings.NewReader("hello"))
	check(t, err)
	check(t, c.FinishUpload(ctx, up.DocumentID, up.Revision))

	_, err = c.MultipartOptions(ctx)
	check(t, err)
	muState, err := c.BeginMultipart(ctx, rootGNS, "book.pdf", 5)
	check(t, err)
	grants, err := c.PartGrants(ctx, muState, 1, 1)
	check(t, err)
	part, err := c.WritePart(ctx, grants[0], strings.NewReader("hello"), 5)
	check(t, err)
	check(t, c.CompleteMultipart(ctx, muState, []Part{part}))

	_, err = c.Download(ctx, docGNS, &bytes.Buffer{})
	check(t, err)
	_, err = c.FastUploadAvailable(ctx, 5, strings.Repeat("a", 32))
	check(t, err)
	check(t, c.FastUpload(ctx, rootGNS, "book.pdf", 5, strings.Repeat("a", 32), "12345678"))
	_, err = c.DownloadArchive(ctx, "bundle", nil, []string{docGNS}, &bytes.Buffer{})
	check(t, err)

	sh, err := c.CreateShare(ctx, Share{Title: "Public", ExpiresAt: "2026-12-31T00:00:00Z", LimitedTimes: -1, Item: ShareItem{ID: docGNS, Type: "file", Allow: []string{"download"}}})
	check(t, err)
	check(t, c.UpdateShare(ctx, sh))
	_, err = c.Shares(ctx, docGNS)
	check(t, err)
	_, err = c.ShareHistory(ctx)
	check(t, err)

	// Unprotected public share resolution (GET /link/{shareID}) and download.
	pubEntry, err := c.ResolveShare(ctx, "pub-share-01", "")
	check(t, err)
	var pubBuf bytes.Buffer
	_, err = c.DownloadShared(ctx, pubEntry, &pubBuf)
	check(t, err)
	if pubBuf.String() != "hello" {
		t.Fatalf("unexpected public share content: %q", pubBuf.String())
	}

	// Empty and wrong extraction passwords on protected share.
	if _, err := c.ResolveShare(ctx, "prot-share-01", ""); !errors.Is(err, ErrCredentials) {
		t.Fatalf("expected ErrCredentials for empty password, got %v", err)
	}
	if _, err := c.ResolveShare(ctx, "prot-share-01", "wrong-code"); err == nil {
		t.Fatal("expected error for wrong share extraction password")
	}
	_, err = c.ResolveShare(ctx, "prot-share-01", "correct-code")
	check(t, err)
	check(t, c.DeleteShare(ctx, sh.ID))

	for opID := range wantOps {
		if !seenOps[opID] {
			t.Errorf("contract operation %s was not exercised", opID)
		}
	}
}
