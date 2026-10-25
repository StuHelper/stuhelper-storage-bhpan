package bhpan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
)

type ShareItem struct {
	ID    string   `json:"id"`
	Type  string   `json:"type"`
	Allow []string `json:"allow"`
}
type Share struct {
	ID           string    `json:"id,omitempty"`
	Title        string    `json:"title"`
	ExpiresAt    string    `json:"expires_at"`
	Password     string    `json:"password"`
	LimitedTimes int64     `json:"limited_times"`
	Item         ShareItem `json:"item"`
}

// SharedEntry carries isolated, non-serializable share authority.
type SharedEntry struct {
	ID, Name string
	Size     int64
	token    string
}

func (s Share) valid() bool {
	if !textOK(s.Item.ID) || (s.Item.Type != "file" && s.Item.Type != "folder") || s.LimitedTimes < -1 || len(s.Item.Allow) == 0 {
		return false
	}
	for _, permission := range s.Item.Allow {
		switch permission {
		case "display", "preview", "download":
		default:
			return false
		}
	}
	return true
}
func (c *Client) CreateShare(ctx context.Context, in Share) (Share, error) {
	if !in.valid() {
		return Share{}, ErrInput
	}
	var out struct {
		ID string `json:"id"`
	}
	err := c.api(ctx, "share-create", "POST", "/api/shared-link/v1/document/anonymous", in, &out)
	if err == nil && !textOK(out.ID) {
		err = ErrProtocol
	}
	in.ID = out.ID
	return in, err
}
func (c *Client) UpdateShare(ctx context.Context, in Share) error {
	if !in.valid() || !textOK(in.ID) {
		return ErrInput
	}
	return c.api(ctx, "share-update", "PUT", "/api/shared-link/v1/document/anonymous/"+url.PathEscape(in.ID), in, nil)
}
func (c *Client) DeleteShare(ctx context.Context, id string) error {
	if !textOK(id) {
		return ErrInput
	}
	return c.api(ctx, "share-delete", "DELETE", "/api/shared-link/v1/document/anonymous/"+url.PathEscape(id), nil, nil)
}
func (c *Client) Shares(ctx context.Context, id string) ([]Share, error) {
	if !textOK(id) {
		return nil, ErrInput
	}
	var out []Share
	err := c.api(ctx, "shares", "GET", "/api/shared-link/v1/document/folder/"+strings.ReplaceAll(url.PathEscape(id), ":", "%3A")+"?type=anonymous", nil, &out)
	return out, err
}

// ResolveShare does not attach the personal account's token or cookies. Password
// protected shares require an explicit password and never fall back to login.
func (c *Client) ResolveShare(ctx context.Context, id, password string) (SharedEntry, error) {
	if !textOK(id) || len(id) > 512 || strings.ContainsAny(id, "/\\;=\" \t") {
		return SharedEntry{}, ErrInput
	}
	jar, _ := cookiejar.New(nil)
	hc := &http.Client{Transport: c.transport, Timeout: c.timeout, Jar: jar}
	var info struct {
		Protected *bool `json:"password_required"`
	}
	if err := c.json(ctx, hc, "", "share-info", "GET", "/api/shared-link/v1/links/"+url.PathEscape(id), nil, &info); err != nil {
		return SharedEntry{}, err
	}
	var token string
	capture := func(headers http.Header) {
		for _, value := range headers.Values("Set-Cookie") {
			field, _, _ := strings.Cut(value, ";")
			name, value, ok := strings.Cut(field, "=")
			if ok && name == "link_token:"+id {
				decoded, e := url.QueryUnescape(value)
				if e == nil {
					token = decoded
				}
			}
		}
	}
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 || req.URL.User != nil || req.URL.Fragment != "" || originOf(req.URL) != c.cloud {
			return ErrDestination
		}
		if req.Response != nil {
			capture(req.Response.Header)
		}
		if token != "" {
			return http.ErrUseLastResponse
		}
		return nil
	}
	method, path := "GET", "/link/"+url.PathEscape(id)
	var body io.Reader
	if info.Protected == nil {
		return SharedEntry{}, ErrProtocol
	}
	if *info.Protected {
		if password == "" {
			return SharedEntry{}, ErrCredentials
		}
		encoded, _ := json.Marshal(map[string]any{"id": id, "type": "anonymous", "password_required": true, "password": password})
		method, path, body = "POST", "/link", bytes.NewReader(encoded)
	}
	_, headers, _, status, err := request(ctx, hc, "share-token", method, c.cloud+path, "application/json", "", body)
	if err != nil {
		return SharedEntry{}, err
	}
	capture(headers)
	if !(status >= 300 && status < 400 && token != "") {
		if err = statusError("share-token", status); err != nil {
			return SharedEntry{}, err
		}
	}
	if !textOK(token) {
		return SharedEntry{}, ErrSession
	}
	var entries []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Size *int64 `json:"size"`
	}
	if err = c.json(ctx, hc, token, "share-entry", "GET", "/api/efast/v1/entry-item", nil, &entries); err != nil {
		return SharedEntry{}, err
	}
	if len(entries) != 1 || !textOK(entries[0].ID) || !textOK(entries[0].Name) {
		return SharedEntry{}, ErrProtocol
	}
	size := int64(-1)
	if entries[0].Size != nil {
		size = *entries[0].Size
		if size < 0 {
			return SharedEntry{}, ErrProtocol
		}
	}
	return SharedEntry{entries[0].ID, entries[0].Name, size, token}, nil
}
func (c *Client) DownloadShared(ctx context.Context, e SharedEntry, dst io.Writer) (int64, error) {
	if !textOK(e.token) {
		return 0, ErrSession
	}
	return c.download(ctx, e.ID, e.token, dst)
}

func (c *Client) anonymousClient() *http.Client {
	return &http.Client{Transport: c.transport, Timeout: c.timeout}
}
