package bhpan

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

// The provider fixture validates every API request against the checked-in
// contract, in addition to operation-specific behavior assertions.
func contractValidator(t *testing.T) func(*http.Request) {
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
	return func(r *http.Request) {
		t.Helper()
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			return
		}
		var methods map[string]any
		for pattern, raw := range paths {
			if pathMatches(pattern, r.URL.Path) {
				methods = raw.(map[string]any)
				break
			}
		}
		if methods == nil {
			t.Errorf("request path is absent from provider contract: %s", r.URL.Path)
			return
		}
		operation, ok := methods[strings.ToLower(r.Method)].(map[string]any)
		if !ok {
			t.Errorf("request method is absent from contract: %s %s", r.Method, r.URL.Path)
			return
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
				t.Error("contract requires JSON body")
				return
			}
			schema := requestBody["content"].(map[string]any)["application/json"].(map[string]any)["schema"].(map[string]any)
			if !conforms(schema, value, schemas) {
				t.Errorf("request does not conform to %s", operation["operationId"])
			}
		}
	}
}
func pathMatches(pattern, path string) bool {
	left, right := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(left) != len(right) {
		return false
	}
	for i, part := range left {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
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
		_, ok := value.(string)
		return ok
	case "integer":
		v, ok := value.(float64)
		return ok && v == float64(int64(v))
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
		for key, v := range object {
			if child, ok := props[key].(map[string]any); ok {
				if !conforms(child, v, definitions) {
					return false
				}
			} else if child, ok := schema["additionalProperties"].(map[string]any); ok {
				if !conforms(child, v, definitions) {
					return false
				}
			}
		}
		return true
	}
	return false
}
