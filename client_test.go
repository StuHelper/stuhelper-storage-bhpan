package bhpan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	validate := contractValidator(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { validate(r); h(w, r) }))
	t.Cleanup(server.Close)
	c, e := New(Config{CloudURL: server.URL, SSOURL: server.URL, Transport: server.Client().Transport, Timeout: time.Second})
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(c.Close)
	return c, server
}
func reply(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
func check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func TestSSOLoginAndSessionReset(t *testing.T) {
	var cloud string
	reject := false
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			if r.URL.Query().Get("service") != "" {
				http.Redirect(w, r, cloud+"/anyshare/oauth2/login/callback", 302)
				return
			}
			if r.Method == "GET" {
				fmt.Fprint(w, `<input value='ticket&amp;value' type='hidden' name='execution'>`)
				return
			}
			if e := r.ParseForm(); e != nil {
				t.Error(e)
			}
			if r.Form.Get("execution") != "ticket&value" || r.Form.Get("type") != "username_password" || r.Form.Get("_eventId") != "submit" {
				t.Error("incorrect CAS fields")
			}
			if reject {
				w.WriteHeader(401)
				fmt.Fprint(w, `<input name="execution" value="again">`)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sso", Value: "test-session", Path: "/"})
			http.Redirect(w, r, "http://uc.buaa.edu.cn/", 302)
		case "/anyshare/oauth2/login":
			http.Redirect(w, r, "/oauth2/signin?login_challenge=fixture", 302)
		case "/oauth2/signin":
			fmt.Fprint(w, "sign in")
		case "/anyshare/oauth2/login/callback":
			if _, e := r.Cookie("login_challenge"); e != nil {
				t.Error("missing login challenge cookie")
			}
			http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "fixture-token", Path: "/"})
			fmt.Fprint(w, "callback")
		case "/api/efast/v1/owned-doc-lib":
			if r.Header.Get("Authorization") != "Bearer fixture-token" {
				t.Error("missing bearer")
			}
			reply(w, []any{map[string]any{"id": "root", "name": "Test"}})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(404)
		}
	})
	cloud = s.URL
	check(t, c.Login(context.Background(), "fixture", "fixture-password"))
	if c.token != "fixture-token" {
		t.Fatal("session not established")
	}
	reject = true
	if e := c.Login(context.Background(), "fixture", "wrong"); !errors.Is(e, ErrCredentials) {
		t.Fatal(e)
	}
	if _, e := c.Libraries(context.Background()); !errors.Is(e, ErrSession) {
		t.Fatal("failed login retained session", e)
	}
	base, _ := url.Parse(cloud)
	if len(c.client.Jar.Cookies(base)) != 0 {
		t.Fatal("failed login retained cookies")
	}
}

func TestLoginRiskAndUntrustedRedirect(t *testing.T) {
	for _, kind := range []string{"risk", "redirect", "no-token"} {
		t.Run(kind, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" && r.Method == "GET" {
					fmt.Fprint(w, `<input name="execution" value="fixture">`)
					return
				}
				if r.Method == "POST" {
					switch kind {
					case "risk":
						fmt.Fprint(w, `<form id="continueForm"><input name="execution" value="fixture"></form>`)
					case "redirect":
						http.Redirect(w, r, "https://untrusted.example/login", 307)
					default:
						fmt.Fprint(w, "ok")
					}
					return
				}
				http.Redirect(w, r, "/anyshare/oauth2/login/callback", 302)
			})
			err := c.Login(context.Background(), "fixture", "private-password")
			expected := ErrSession
			if kind == "risk" {
				expected = ErrChallenge
			}
			if kind == "redirect" {
				expected = ErrDestination
			}
			if err == nil {
				t.Fatal("unexpected login success")
			}
			if kind != "no-token" && !errors.Is(err, expected) {
				t.Fatalf("%v", err)
			}
			if strings.Contains(err.Error(), "private-password") {
				t.Fatal("credential leaked")
			}
		})
	}
}

func TestLocalLoginEncryptsCredentials(t *testing.T) {
	var base string
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/anyshare/oauth2/login":
			http.Redirect(w, r, "/oauth2/signin?login_challenge=fixture-challenge", 302)
		case "/oauth2/signin":
			if r.Method == "GET" {
				fmt.Fprint(w, `<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"challenge":"fixture-challenge","csrftoken":"fixture-csrf","device":{"client_type":"web"},"authconfig":{}}}}</script>`)
				return
			}
			var in map[string]any
			check(t, json.NewDecoder(r.Body).Decode(&in))
			encrypted, e := base64.StdEncoding.DecodeString(fmt.Sprint(in["password"]))
			if e != nil || len(encrypted) != 256 || bytes.Contains(encrypted, []byte("private-password")) {
				t.Error("password not RSA encrypted")
			}
			if in["_csrf"] != "fixture-csrf" || in["challenge"] != "fixture-challenge" || in["remember"] != false {
				t.Error("incorrect local auth fields")
			}
			reply(w, map[string]string{"redirect": base + "/anyshare/oauth2/login/callback"})
		case "/anyshare/oauth2/login/callback":
			http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "local-token", Path: "/"})
		case "/api/efast/v1/owned-doc-lib":
			reply(w, []any{map[string]string{"id": "root"}})
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
		}
	})
	base = s.URL
	check(t, c.LoginLocal(context.Background(), "fixture", "private-password"))
	c.Close()
	if c.token != "" {
		t.Fatal("close retained token")
	}
	u, _ := url.Parse(base)
	if len(c.client.Jar.Cookies(u)) != 0 {
		t.Fatal("close retained cookie")
	}
}

func TestMetadataAndFileOperations(t *testing.T) {
	paths := map[string]map[string]any{}
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing auth")
		}
		var in map[string]any
		if r.Method == "POST" {
			check(t, json.NewDecoder(r.Body).Decode(&in))
		}
		paths[r.URL.Path] = in
		switch r.URL.Path {
		case "/api/efast/v1/owned-doc-lib":
			reply(w, []any{map[string]string{"id": "root", "name": "Drive"}})
		case "/api/efast/v1/quota/user":
			reply(w, map[string]int{"allocated": 10, "used": 12})
		case "/api/efast/v1/dir/list", "/api/efast/v1/recycle/list":
			reply(w, map[string]any{"dirs": []any{}, "files": []any{map[string]any{"docid": "file", "name": "sample", "size": 4}}})
		case "/api/efast/v1/dir/size":
			reply(w, map[string]int{"totalsize": 4, "filenum": 1, "dirnum": 0})
		case "/api/efast/v1/file/getsuggestname":
			reply(w, map[string]string{"name": "next.bin"})
		default:
			reply(w, map[string]string{"docid": "changed"})
		}
	})
	c.token = "fixture-token"
	ctx := context.Background()
	libs, e := c.Libraries(ctx)
	check(t, e)
	if len(libs) != 1 {
		t.Fatal("libraries")
	}
	quota, e := c.Quota(ctx)
	check(t, e)
	if quota.Available() != 0 {
		t.Fatal("over quota")
	}
	d, e := c.List(ctx, "root")
	check(t, e)
	if len(d.Files) != 1 {
		t.Fatal("list")
	}
	_, e = c.DirectorySize(ctx, "root")
	check(t, e)
	_, e = c.SuggestedName(ctx, "root", "sample")
	check(t, e)
	_, e = c.CreateDirectory(ctx, "root", "new")
	check(t, e)
	check(t, c.Rename(ctx, "file", "renamed"))
	_, e = c.Copy(ctx, "file", "target")
	check(t, e)
	_, e = c.Move(ctx, "file", "target")
	check(t, e)
	check(t, c.Delete(ctx, "file"))
	_, e = c.Restore(ctx, "file")
	check(t, e)
	check(t, c.Purge(ctx, "file"))
	_, e = c.RecycleBin(ctx, "root", 10, 20)
	check(t, e)
	if paths["/api/efast/v1/dir/create"]["ondup"] != float64(1) || paths["/api/efast/v1/recycle/list"]["start"] != float64(10) {
		t.Fatal("wire contract")
	}
	if _, e = c.CreateDirectory(ctx, "root", "../unsafe"); !errors.Is(e, ErrInput) {
		t.Fatal(e)
	}
}

func TestResponseBoundsAndSafeErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
		want       error
	}{
		{"unauthorized", "sensitive provider payload", 401, ErrSession}, {"busy", "sensitive provider payload", 429, ErrUnavailable},
		{"html", "<html>login</html>", 200, ErrProtocol}, {"null", "null", 200, ErrProtocol}, {"missing", "{}", 200, ErrProtocol}, {"large", strings.Repeat("x", metadataLimit+1), 200, ErrProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) })
			c.token = "secret-token"
			_, e := c.Quota(context.Background())
			if !errors.Is(e, tc.want) {
				t.Fatal(e)
			}
			if strings.Contains(e.Error(), "sensitive") || strings.Contains(e.Error(), "secret-token") {
				t.Fatal("unsafe error")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { t.Error("canceled request reached provider") })
	c.token = "fixture"
	_, e := c.Libraries(ctx)
	if !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
}

func TestTransferCredentialsAndRedirectIsolation(t *testing.T) {
	var base string
	var uploaded atomic.Bool
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/efast/v1/file/osbeginupload":
			reply(w, map[string]any{"docid": "file", "rev": "rev", "authrequest": []string{"PUT", base + "/object", "Authorization: signed-fixture", "X-Amz-Date: fixture-date", "Content-Type: application/octet-stream"}})
		case "/api/efast/v1/file/osdownload":
			reply(w, map[string]any{"authrequest": []string{"GET", base + "/download?signature=fixture"}})
		case "/object":
			if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "signed-fixture" {
				t.Error("account credentials reached object store")
			}
			b, _ := io.ReadAll(r.Body)
			if string(b) != "test" {
				t.Error("bad upload")
			}
			uploaded.Store(true)
			w.Header().Set("ETag", `"etag"`)
		case "/download":
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("credential leak")
			}
			fmt.Fprint(w, "test")
		case "/redirect":
			http.Redirect(w, r, "https://untrusted.example/object?secret=fixture", 307)
		case "/api/efast/v1/file/osendupload":
			if !uploaded.Load() {
				t.Error("finish preceded object upload")
			}
			w.WriteHeader(204)
		default:
			t.Error("unexpected request")
		}
	})
	base = s.URL
	c.token = "account-token"
	u, _ := url.Parse(base)
	c.client.Jar.SetCookies(u, []*http.Cookie{{Name: "account", Value: "private", Path: "/"}})
	ctx := context.Background()
	upload, e := c.BeginUpload(ctx, "root", "file.bin", 4)
	check(t, e)
	encoded, _ := json.Marshal(upload)
	if bytes.Contains(encoded, []byte("signed-fixture")) {
		t.Fatal("grant serialized")
	}
	_, e = c.WriteUpload(ctx, upload, strings.NewReader("test"))
	check(t, e)
	check(t, c.FinishUpload(ctx, upload.DocumentID, upload.Revision))
	var dst bytes.Buffer
	n, e := c.Download(ctx, "file", &dst)
	check(t, e)
	if n != 4 || dst.String() != "test" {
		t.Fatal("download")
	}
	upload.grant.target = base + "/redirect"
	_, e = c.WriteUpload(ctx, upload, strings.NewReader("test"))
	if e == nil {
		t.Fatal("redirect accepted")
	}
	upload.grant.target = "https://untrusted.example/object"
	_, e = c.WriteUpload(ctx, upload, strings.NewReader("test"))
	if !errors.Is(e, ErrDestination) {
		t.Fatal(e)
	}
}

func TestOriginAndGrantValidation(t *testing.T) {
	c, e := New(Config{})
	check(t, e)
	for _, raw := range []string{"http://bhpan.buaa.edu.cn/a", "https://bhpan.buaa.edu.cn.evil.example/a", "https://user@bhpan.buaa.edu.cn/a", "https://bhpan.buaa.edu.cn:444/a", "https://bhpan.buaa.edu.cn/a#fragment"} {
		if !errors.Is(c.trustedData(raw), ErrDestination) {
			t.Fatalf("accepted %s", raw)
		}
	}
	check(t, c.trustedData("https://bhpan.buaa.edu.cn:443/a"))
	ipv6, e := New(Config{CloudURL: "https://[::1]"})
	check(t, e)
	check(t, ipv6.trustedData("https://[::1]:443/a"))
	for _, headers := range [][]string{{"Cookie: private"}, {"Authorization: first", "Authorization: second"}, {"Authorization: first\r\nCookie: injected"}, {"Authorization: only"}} {
		_, e := c.decodeGrant(append([]string{"PUT", "https://bhpan.buaa.edu.cn/a"}, headers...), "PUT")
		if e == nil {
			t.Fatal("bad headers accepted")
		}
	}
}

func TestMalformedMetadataNeverBecomesEmptySuccess(t *testing.T) {
	for _, body := range []string{`{}`, `{"dirs":null,"files":[]}`, `{"dirs":[],"files":[{"docid":"id","name":"file"}]}`} {
		c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		c.token = "fixture"
		if _, e := c.List(context.Background(), "root"); !errors.Is(e, ErrProtocol) {
			t.Fatal("invalid list accepted", e)
		}
	}
	for _, body := range []string{`<html>login</html>`, `false`, `{"error_code":42,"message":"private-provider-detail"}`} {
		c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) })
		c.token = "fixture"
		if e := c.Delete(context.Background(), "file"); e == nil || strings.Contains(e.Error(), "private-provider-detail") {
			t.Fatal("invalid mutation response", e)
		}
	}
}
