package bhpan

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestStableIdentityAndMalformedProfile(t *testing.T) {
	for _, test := range []struct {
		name, kind, id string
		status         int
		want           error
	}{
		{"valid", "user", "fixture-user-id", 200, nil},
		{"missing-id", "user", "", 200, ErrProtocol},
		{"application-is-not-user", "app", "fixture-app-id", 200, ErrProtocol},
		{"expired", "user", "fixture-user-id", 401, ErrSession},
		{"denied", "user", "fixture-user-id", 403, ErrPermission},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "POST" || r.URL.Path != "/api/eacp/v1/user/get" || r.Header.Get("Authorization") != "Bearer fixture-token" {
					t.Error("invalid identity request")
				}
				w.WriteHeader(test.status)
				reply(w, map[string]any{"type": test.kind, "userid": test.id, "name": "discarded-profile-name", "mail": "discarded@example.invalid"})
			})
			c.token = "fixture-token"
			identity, err := c.Identity(context.Background())
			if !errors.Is(err, test.want) {
				t.Fatalf("error %v", err)
			}
			if err == nil && identity.ID != test.id {
				t.Fatal("stable ID lost")
			}
			if err != nil && identity.ID != "" {
				t.Fatal("invalid identity escaped")
			}
		})
	}
}
