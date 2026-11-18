package bhpan

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var shareIdentity = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`)

func shareIDOK(id string) bool { return shareIdentity.MatchString(id) }

func cleanText(s string, maxLen int) bool {
	if len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

type ShareItem struct {
	ID    string   `json:"id"`
	Type  string   `json:"type"`
	Allow []string `json:"allow"`
}

// Share represents an anonymous share configuration or query result. Password is
// write-only input and is never retained in query outputs or serialized to JSON.
type Share struct {
	ID           string    `json:"id,omitempty"`
	Title        string    `json:"title"`
	ExpiresAt    string    `json:"expires_at"`
	Password     string    `json:"-"`
	HasPassword  bool      `json:"has_password,omitempty"`
	LimitedTimes int64     `json:"limited_times"`
	Item         ShareItem `json:"item"`
}

type shareRequest struct {
	ID           string    `json:"id,omitempty"`
	Title        string    `json:"title"`
	ExpiresAt    string    `json:"expires_at"`
	Password     string    `json:"password"`
	LimitedTimes int64     `json:"limited_times"`
	Item         ShareItem `json:"item"`
}

type shareResponse struct {
	ID               string    `json:"id"`
	Title            string    `json:"title"`
	ExpiresAt        string    `json:"expires_at"`
	Password         string    `json:"password"`
	PasswordRequired bool      `json:"password_required"`
	LimitedTimes     int64     `json:"limited_times"`
	Item             ShareItem `json:"item"`
}

// SharedEntry carries isolated, non-serializable share authority.
type SharedEntry struct {
	ID, Name string
	Size     int64
	token    string
	jar      http.CookieJar
}

func (s Share) valid() bool {
	if !textOK(s.Item.ID) || s.Item.ID == "." || s.Item.ID == ".." || (s.Item.Type != "file" && s.Item.Type != "folder") || s.LimitedTimes < -1 || len(s.Item.Allow) == 0 {
		return false
	}
	if !cleanText(s.Title, 512) || !cleanText(s.ExpiresAt, 128) || !cleanText(s.Password, 128) {
		return false
	}
	if s.ExpiresAt != "" && strings.TrimSpace(s.ExpiresAt) == "" {
		return false
	}
	seen := make(map[string]bool, len(s.Item.Allow))
	for _, permission := range s.Item.Allow {
		switch permission {
		case "display", "preview", "download":
			if seen[permission] {
				return false
			}
			seen[permission] = true
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
	req := shareRequest{
		Title:        in.Title,
		ExpiresAt:    in.ExpiresAt,
		Password:     in.Password,
		LimitedTimes: in.LimitedTimes,
		Item:         in.Item,
	}
	var out struct {
		ID string `json:"id"`
	}
	err := c.api(ctx, "share-create", "POST", "/api/shared-link/v1/document/anonymous", req, &out)
	if err != nil {
		return Share{}, err
	}
	if !shareIDOK(out.ID) {
		return Share{}, ErrProtocol
	}
	return Share{
		ID:           out.ID,
		Title:        in.Title,
		ExpiresAt:    in.ExpiresAt,
		HasPassword:  in.Password != "",
		LimitedTimes: in.LimitedTimes,
		Item:         in.Item,
	}, nil
}

func (c *Client) UpdateShare(ctx context.Context, in Share) error {
	if !in.valid() || !shareIDOK(in.ID) {
		return ErrInput
	}
	req := shareRequest{
		ID:           in.ID,
		Title:        in.Title,
		ExpiresAt:    in.ExpiresAt,
		Password:     in.Password,
		LimitedTimes: in.LimitedTimes,
		Item:         in.Item,
	}
	return c.api(ctx, "share-update", "PUT", "/api/shared-link/v1/document/anonymous/"+url.PathEscape(in.ID), req, nil)
}

func (c *Client) DeleteShare(ctx context.Context, id string) error {
	if !shareIDOK(id) {
		return ErrInput
	}
	return c.api(ctx, "share-delete", "DELETE", "/api/shared-link/v1/document/anonymous/"+url.PathEscape(id), nil, nil)
}

func (c *Client) Shares(ctx context.Context, id string) ([]Share, error) {
	if !textOK(id) || id == "." || id == ".." {
		return nil, ErrInput
	}
	var raw []shareResponse
	err := c.api(ctx, "shares", "GET", "/api/shared-link/v1/document/folder/"+strings.ReplaceAll(url.PathEscape(id), ":", "%3A")+"?type=anonymous", nil, &raw)
	if err != nil {
		return nil, err
	}
	out := make([]Share, 0, len(raw))
	for _, v := range raw {
		if !shareIDOK(v.ID) || !textOK(v.Item.ID) || v.Item.ID == "." || v.Item.ID == ".." || (v.Item.Type != "file" && v.Item.Type != "folder") {
			return nil, ErrProtocol
		}
		out = append(out, Share{
			ID:           v.ID,
			Title:        v.Title,
			ExpiresAt:    v.ExpiresAt,
			HasPassword:  v.Password != "" || v.PasswordRequired,
			LimitedTimes: v.LimitedTimes,
			Item:         v.Item,
		})
	}
	return out, nil
}

func parseLinkTokenCookie(headers http.Header, cookieName, current string) string {
	for _, raw := range headers.Values("Set-Cookie") {
		parts := strings.Split(raw, ";")
		name, val, ok := strings.Cut(strings.TrimSpace(parts[0]), "=")
		if !ok || name != cookieName {
			continue
		}
		cleared := false
		for _, attr := range parts[1:] {
			ak, av, _ := strings.Cut(strings.TrimSpace(attr), "=")
			if strings.EqualFold(strings.TrimSpace(ak), "Max-Age") {
				if n, err := strconv.Atoi(strings.TrimSpace(av)); err == nil && n <= 0 {
					cleared = true
				}
			}
		}
		val = strings.Trim(strings.TrimSpace(val), `"`)
		if cleared || val == "" {
			current = ""
			continue
		}
		if decoded, err := url.PathUnescape(val); err == nil {
			current = decoded
		}
	}
	return current
}

// ResolveShare does not attach the personal account's token or cookies. Password
// protected shares require an explicit password and never fall back to login.
func (c *Client) ResolveShare(ctx context.Context, id, password string) (SharedEntry, error) {
	if !shareIDOK(id) || !cleanText(password, 1024) {
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
	cookieName := "link_token:" + id
	capture := func(headers http.Header) {
		token = parseLinkTokenCookie(headers, cookieName, token)
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
			return SharedEntry{}, &Error{Operation: "share-token", Status: 0, Kind: ErrCredentials}
		}
		encoded, _ := json.Marshal(map[string]any{"id": id, "type": "anonymous", "password_required": true, "password": password})
		method, path, body = "POST", "/link", bytes.NewReader(encoded)
	}
	tokenBody, headers, _, status, err := request(ctx, hc, "share-token", method, c.cloud+path, "application/json", "", body)
	if err != nil {
		return SharedEntry{}, err
	}
	capture(headers)
	if !(status >= 300 && status < 400 && textOK(token)) {
		if *info.Protected && (status == 400 || status == 401 || status == 403 || (status >= 200 && status < 300 && !textOK(token))) {
			return SharedEntry{}, &Error{Operation: "share-token", Status: status, Kind: ErrCredentials}
		}
		if err = responseError("share-token", status, headers, tokenBody); err != nil {
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
		if size < -1 {
			return SharedEntry{}, ErrProtocol
		}
	}
	return SharedEntry{ID: entries[0].ID, Name: entries[0].Name, Size: size, token: token, jar: jar}, nil
}

func (c *Client) DownloadShared(ctx context.Context, e SharedEntry, dst io.Writer) (int64, error) {
	if !textOK(e.token) {
		return 0, ErrSession
	}
	return c.download(ctx, e.ID, e.token, e.jar, dst)
}

func (c *Client) anonymousClient(jar http.CookieJar) *http.Client {
	return &http.Client{Transport: c.transport, Timeout: c.timeout, Jar: jar}
}
