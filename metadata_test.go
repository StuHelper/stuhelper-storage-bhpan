package bhpan

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

func TestFileMetadataIdentityAndMissingObject(t *testing.T) {
	for _, test := range []struct {
		name, id string
		size     any
		status   int
		want     error
	}{
		{"valid", "fixture_object", 12, 200, nil},
		{"swapped-identity", "different_object", 12, 200, ErrProtocol},
		{"missing-size", "fixture_object", nil, 200, ErrProtocol},
		{"negative-size", "fixture_object", -1, 200, ErrProtocol},
		{"missing", "fixture_object", 12, 404, ErrNotFound},
		{"denied", "fixture_object", 12, 403, ErrPermission},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/efast/v2/items/fixture_object/all" {
					t.Error("wrong metadata request")
				}
				w.WriteHeader(test.status)
				reply(w, map[string]any{"object_id": test.id, "doc_id": "gns://fixture-root/fixture_object", "name": "owned.bin", "rev": "fixture-revision", "size": test.size, "type": "file", "doc_lib": map[string]string{"id": "gns://fixture-root"}})
			})
			c.token = "fixture-token"
			got, err := c.FileInfo(context.Background(), "fixture_object")
			if !errors.Is(err, test.want) {
				t.Fatal(err)
			}
			if err == nil && got.ObjectID != test.id {
				t.Fatal("wrong object")
			}
		})
	}
}
