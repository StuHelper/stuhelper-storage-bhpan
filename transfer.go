package bhpan

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Grants remain private process-local capabilities. They cannot be serialized
// with an upload state or accidentally included in a JSON log.
type grant struct {
	method, target string
	headers        http.Header
	deadline       time.Time
}
type Upload struct {
	DocumentID, Revision string
	grant                grant
	length               int64
}
type MultipartUpload struct{ DocumentID, Revision, UploadID string }
type Part struct {
	Number int
	ETag   string
	Size   int64
}
type PartGrant struct {
	grant  grant
	number int
}
type MultipartOptions struct {
	MinimumSize  int64 `json:"partminsize"`
	MaximumSize  int64 `json:"partmaxsize"`
	MaximumParts int64 `json:"partmaxnum"`
}

func (c *Client) trustedData(raw string) error {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Fragment != "" || !c.origins[originOf(u)] {
		return ErrDestination
	}
	return nil
}
func (c *Client) decodeGrant(raw []string, method string) (grant, error) {
	g := grant{}
	if len(raw) < 2 || raw[0] != method {
		return g, ErrProtocol
	}
	if err := c.trustedData(raw[1]); err != nil {
		return g, err
	}
	g = grant{method: method, target: raw[1], headers: make(http.Header), deadline: time.Now().Add(10 * time.Minute)}
	for _, line := range raw[2:] {
		key, value, ok := strings.Cut(line, ":")
		key = http.CanonicalHeaderKey(key)
		value = strings.TrimSpace(value)
		if !ok || strings.ContainsAny(line, "\r\n") || g.headers.Get(key) != "" {
			return grant{}, ErrProtocol
		}
		switch key {
		case "Authorization", "Content-Type", "X-Amz-Date":
		default:
			return grant{}, ErrProtocol
		}
		g.headers.Set(key, value)
	}
	if method != "GET" && (g.headers.Get("Authorization") == "" || g.headers.Get("X-Amz-Date") == "" || g.headers.Get("Content-Type") == "") {
		return grant{}, ErrProtocol
	}
	return g, nil
}
func (c *Client) data(ctx context.Context, g grant, body io.Reader, length int64) (*http.Response, error) {
	if !g.deadline.After(time.Now()) {
		return nil, ErrSession
	}
	if e := c.trustedData(g.target); e != nil {
		return nil, e
	}
	req, e := http.NewRequestWithContext(ctx, g.method, g.target, body)
	if e != nil {
		return nil, ErrInput
	}
	req.Header = g.headers.Clone()
	if body != nil {
		req.ContentLength = length
	}
	hc := &http.Client{Transport: c.transport, Timeout: c.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := hc.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{"transfer", 0, ErrUnavailable}
	}
	if e = statusError("transfer", resp.StatusCode); e != nil {
		resp.Body.Close()
		return nil, e
	}
	return resp, nil
}
func (c *Client) BeginUpload(ctx context.Context, parent, name string, length int64) (Upload, error) {
	if !textOK(parent) || !nameOK(name) || length < 0 {
		return Upload{}, ErrInput
	}
	var out struct {
		ID   string   `json:"docid"`
		Rev  string   `json:"rev"`
		Auth []string `json:"authrequest"`
	}
	err := c.api(ctx, "upload-begin", "POST", "/api/efast/v1/file/osbeginupload", map[string]any{"docid": parent, "name": name, "length": length, "ondup": 1, "client_mtime": time.Now().UnixMilli()}, &out)
	state := Upload{DocumentID: out.ID, Revision: out.Rev, length: length}
	if err != nil {
		return state, err
	}
	if !textOK(out.ID) || !textOK(out.Rev) {
		return state, ErrProtocol
	}
	state.grant, err = c.decodeGrant(out.Auth, "PUT")
	return state, err
}
func (c *Client) WriteUpload(ctx context.Context, u Upload, src io.Reader) (string, error) {
	return c.write(ctx, u.grant, src, u.length)
}
func (c *Client) write(ctx context.Context, g grant, src io.Reader, length int64) (string, error) {
	if src == nil || length < 0 || length == int64(^uint64(0)>>1) || g.method != "PUT" {
		return "", ErrInput
	}
	resp, e := c.data(ctx, g, io.LimitReader(src, length+1), length)
	if e != nil {
		return "", e
	}
	defer resp.Body.Close()
	if _, e = limitedRead(resp.Body); e != nil {
		return "", e
	}
	etag := strings.Trim(resp.Header.Get("ETag"), "\"")
	if strings.ContainsAny(etag, "\r\n\x00\"") {
		return "", ErrProtocol
	}
	return etag, nil
}
func (c *Client) FinishUpload(ctx context.Context, id, revision string) error {
	if !textOK(id) || !textOK(revision) {
		return ErrInput
	}
	return c.api(ctx, "upload-finish", "POST", "/api/efast/v1/file/osendupload", map[string]any{"docid": id, "rev": revision}, nil)
}
func (c *Client) MultipartOptions(ctx context.Context) (MultipartOptions, error) {
	var out MultipartOptions
	err := c.api(ctx, "multipart-options", "POST", "/api/efast/v1/file/osoption", nil, &out)
	if err == nil && (out.MinimumSize <= 0 || out.MaximumSize < out.MinimumSize || out.MaximumParts <= 0) {
		err = ErrProtocol
	}
	return out, err
}
func (c *Client) BeginMultipart(ctx context.Context, parent, name string, length int64) (MultipartUpload, error) {
	if !textOK(parent) || !nameOK(name) || length <= 0 {
		return MultipartUpload{}, ErrInput
	}
	var out struct {
		ID       string `json:"docid"`
		Rev      string `json:"rev"`
		UploadID string `json:"uploadid"`
	}
	err := c.api(ctx, "multipart-begin", "POST", "/api/efast/v1/file/osinitmultiupload", map[string]any{"docid": parent, "name": name, "length": length, "ondup": 1}, &out)
	u := MultipartUpload{out.ID, out.Rev, out.UploadID}
	if err == nil && !u.valid() {
		err = ErrProtocol
	}
	return u, err
}
func (u MultipartUpload) valid() bool {
	return textOK(u.DocumentID) && textOK(u.Revision) && textOK(u.UploadID)
}
func (u MultipartUpload) fields() map[string]any {
	return map[string]any{"docid": u.DocumentID, "rev": u.Revision, "uploadid": u.UploadID}
}
func (c *Client) PartGrants(ctx context.Context, u MultipartUpload, first, last int) ([]PartGrant, error) {
	if !u.valid() || first < 1 || last < first || last-first >= 10000 {
		return nil, ErrInput
	}
	in := u.fields()
	in["parts"] = fmt.Sprintf("%d-%d", first, last)
	var out struct {
		Auth map[string][]string `json:"authrequests"`
	}
	if err := c.api(ctx, "multipart-grants", "POST", "/api/efast/v1/file/osuploadpart", in, &out); err != nil {
		return nil, err
	}
	if len(out.Auth) != last-first+1 {
		return nil, ErrProtocol
	}
	grants := make([]PartGrant, 0, len(out.Auth))
	for number := first; number <= last; number++ {
		g, e := c.decodeGrant(out.Auth[strconv.Itoa(number)], "PUT")
		if e != nil {
			return nil, e
		}
		grants = append(grants, PartGrant{g, number})
	}
	return grants, nil
}
func (c *Client) WritePart(ctx context.Context, g PartGrant, src io.Reader, length int64) (Part, error) {
	if length <= 0 || g.number < 1 {
		return Part{}, ErrInput
	}
	etag, err := c.write(ctx, g.grant, src, length)
	if err == nil && !textOK(etag) {
		err = ErrProtocol
	}
	return Part{g.number, etag, length}, err
}

// CompleteMultipart commits object-store parts, then finalizes the file. The
// metadata finalize request is never issued if the object store fails.
func (c *Client) CompleteMultipart(ctx context.Context, u MultipartUpload, parts []Part) error {
	if !u.valid() || len(parts) == 0 || len(parts) > 10000 {
		return ErrInput
	}
	info := map[string]any{}
	for i, p := range parts {
		if p.Number != i+1 || p.Size <= 0 || !textOK(p.ETag) || strings.ContainsRune(p.ETag, '"') {
			return ErrInput
		}
		info[strconv.Itoa(p.Number)] = []any{p.ETag, p.Size}
	}
	in := u.fields()
	in["partinfo"] = info
	encoded, _ := json.Marshal(in)
	c.mu.RLock()
	if c.token == "" {
		c.mu.RUnlock()
		return ErrSession
	}
	hc := *c.client
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	raw, headers, _, status, err := request(ctx, &hc, "multipart-prepare", "POST", c.cloud+"/api/efast/v1/file/oscompleteupload", "application/json", c.token, bytes.NewReader(encoded))
	c.mu.RUnlock()
	if err != nil {
		return err
	}
	if err = statusError("multipart-prepare", status); err != nil {
		return err
	}
	kind, params, err := mime.ParseMediaType(headers.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(kind, "multipart/") || params["boundary"] == "" {
		return ErrProtocol
	}
	reader := multipart.NewReader(bytes.NewReader(raw), params["boundary"])
	var auth []string
	var payload []byte
	for count := 0; ; count++ {
		p, e := reader.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil || count >= 2 {
			return ErrProtocol
		}
		b, e := limitedRead(p)
		p.Close()
		if e != nil {
			return e
		}
		if bytes.HasPrefix(bytes.TrimSpace(b), []byte("<")) {
			if payload != nil {
				return ErrProtocol
			}
			payload = b
		} else {
			if auth != nil {
				return ErrProtocol
			}
			var v struct {
				Auth []string `json:"authrequest"`
			}
			if json.Unmarshal(b, &v) != nil {
				return ErrProtocol
			}
			auth = v.Auth
		}
	}
	if len(payload) == 0 {
		return ErrProtocol
	}
	g, err := c.decodeGrant(auth, "POST")
	if err != nil {
		return err
	}
	resp, err := c.data(ctx, g, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return err
	}
	b, err := limitedRead(resp.Body)
	resp.Body.Close()
	if err != nil {
		return err
	}
	var result struct{ XMLName xml.Name }
	if xml.Unmarshal(b, &result) != nil || result.XMLName.Local != "CompleteMultipartUploadResult" {
		return ErrProtocol
	}
	return c.FinishUpload(ctx, u.DocumentID, u.Revision)
}
func (c *Client) Download(ctx context.Context, id string, dst io.Writer) (int64, error) {
	return c.download(ctx, id, "", dst)
}
func (c *Client) download(ctx context.Context, id, token string, dst io.Writer) (int64, error) {
	if !textOK(id) || dst == nil {
		return 0, ErrInput
	}
	var out struct {
		Auth []string `json:"authrequest"`
	}
	in := map[string]any{"docid": id, "authtype": "QUERY_STRING"}
	var err error
	if token == "" {
		err = c.api(ctx, "download", "POST", "/api/efast/v1/file/osdownload", in, &out)
	} else {
		hc := &http.Client{Transport: c.transport, Timeout: c.timeout}
		err = c.json(ctx, hc, token, "share-download", "POST", "/api/efast/v1/file/osdownload", in, &out)
	}
	if err != nil {
		return 0, err
	}
	g, err := c.decodeGrant(out.Auth, "GET")
	if err != nil {
		return 0, err
	}
	resp, err := c.data(ctx, g, nil, 0)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	n, err := io.Copy(dst, resp.Body)
	if err != nil {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		return n, &Error{"download-body", resp.StatusCode, ErrUnavailable}
	}
	return n, nil
}
