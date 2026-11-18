package bhpan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLocalPublicKeyOverrideAndScriptOrder(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	check(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	check(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	var base string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/anyshare/oauth2/login":
			http.Redirect(w, r, "/oauth2/signin?login_challenge=ch-key", http.StatusFound)
		case "/oauth2/signin":
			if r.Method == http.MethodGet {
				// Attribute order places type and crossorigin before single-quoted id='__NEXT_DATA__'.
				fmt.Fprint(w, `<script type="application/json">{"ignored":true}</script><script type="application/json" crossorigin="anonymous" id='__NEXT_DATA__'>{"props":{"pageProps":{"challenge":"ch-key","csrftoken":"csrf-key","device":{"client_type":"web"},"authconfig":{}}}}</script>`)
				return
			}
			var in map[string]any
			check(t, json.NewDecoder(r.Body).Decode(&in))
			cipherBytes, err := base64.StdEncoding.DecodeString(fmt.Sprint(in["password"]))
			if err != nil {
				t.Fatalf("invalid base64 password: %v", err)
			}
			plain, err := rsa.DecryptPKCS1v15(rand.Reader, privKey, cipherBytes)
			if err != nil || string(plain) != "rotated-key-password" {
				t.Fatalf("failed to decrypt with overridden RSA key: plain=%q err=%v", plain, err)
			}
			reply(w, map[string]string{"redirect": base + "/anyshare/oauth2/login/callback"})
		case "/anyshare/oauth2/login/callback":
			http.SetCookie(w, &http.Cookie{Name: "client.oauth2_token", Value: "override-token", Path: "/"})
			fmt.Fprint(w, "ok")
		case "/api/efast/v1/owned-doc-lib":
			reply(w, []any{map[string]string{"id": "gns://root", "name": "Drive"}})
		default:
			t.Errorf("unexpected route %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	base = server.URL

	c, err := New(Config{
		CloudURL:          base,
		SSOURL:            base,
		Transport:         server.Client().Transport,
		Timeout:           2 * time.Second,
		LocalPublicKeyPEM: pubPEM,
	})
	check(t, err)
	t.Cleanup(c.Close)
	check(t, c.LoginLocal(context.Background(), "local-user", "rotated-key-password"))

	// Reject malformed PEM, trailing data, non-RSA keys, and undersized RSA keys.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(t, err)
	ecDER, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	check(t, err)
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecDER}))

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	check(t, err)
	weakDER, err := x509.MarshalPKIXPublicKey(&weakRSA.PublicKey)
	check(t, err)
	weakPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: weakDER}))

	for _, badPEM := range []string{"not-pem", pubPEM + "\nextra-trailing-data", ecPEM, weakPEM} {
		if _, err := New(Config{LocalPublicKeyPEM: badPEM}); !errors.Is(err, ErrInput) {
			t.Fatalf("expected ErrInput for invalid LocalPublicKeyPEM, got %v", err)
		}
	}
}
