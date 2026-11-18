package bhpan

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
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

var errStreamIdle = errors.New("bhpan: stream idle timeout")

type activityTimer struct {
	mu      sync.Mutex
	timeout time.Duration
	timer   *time.Timer
	stopped bool
}

func newActivityTimer(d time.Duration, onTimeout func()) *activityTimer {
	a := &activityTimer{timeout: d}
	a.timer = time.AfterFunc(d, onTimeout)
	return a
}

func (a *activityTimer) touch() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.stopped {
		a.timer.Reset(a.timeout)
	}
}

func (a *activityTimer) pause() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.stopped {
		a.timer.Stop()
	}
}

func (a *activityTimer) stop() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.stopped {
		a.stopped = true
		a.timer.Stop()
	}
}

type activityReader struct {
	src   io.Reader
	watch *activityTimer
}

func (r *activityReader) Read(p []byte) (int, error) {
	r.watch.touch()
	n, err := r.src.Read(p)
	if n > 0 || err == io.EOF {
		r.watch.touch()
	}
	return n, err
}

type idleResponseBody struct {
	body   io.ReadCloser
	watch  *activityTimer
	cancel context.CancelCauseFunc
}

func (b *idleResponseBody) Read(p []byte) (int, error) {
	b.watch.touch()
	n, err := b.body.Read(p)
	b.watch.pause()
	return n, err
}

func (b *idleResponseBody) Close() error {
	b.watch.stop()
	err := b.body.Close()
	b.cancel(nil)
	return err
}

func (c *Client) data(ctx context.Context, g grant, body io.Reader, length int64) (*http.Response, error) {
	if !g.deadline.After(time.Now()) {
		return nil, ErrSession
	}
	if e := c.trustedData(g.target); e != nil {
		return nil, e
	}
	reqCtx, cancel := context.WithCancelCause(ctx)
	watch := newActivityTimer(c.timeout, func() { cancel(errStreamIdle) })
	reqBody := body
	if body != nil && body != http.NoBody {
		reqBody = &activityReader{src: body, watch: watch}
	}
	req, e := http.NewRequestWithContext(reqCtx, g.method, g.target, reqBody)
	if e != nil {
		watch.stop()
		cancel(nil)
		return nil, ErrInput
	}
	req.Header = g.headers.Clone()
	if body != nil {
		req.ContentLength = length
	}
	// Do not apply fixed total-request Timeout to object streams; watch enforces
	// header and per-read/write idle timeouts while ctx bounds total duration.
	hc := &http.Client{Transport: c.transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := hc.Do(req)
	if e != nil {
		watch.stop()
		cancel(nil)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &Error{"transfer", 0, ErrUnavailable}
	}
	watch.pause()
	if e = statusError("transfer", resp.StatusCode); e != nil {
		watch.stop()
		resp.Body.Close()
		cancel(nil)
		return nil, e
	}
	resp.Body = &idleResponseBody{body: resp.Body, watch: watch, cancel: cancel}
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

// WriteUpload streams exactly u.length bytes to the signed object URL. Callers
// must never invoke FinishUpload if WriteUpload returns an error.
func (c *Client) WriteUpload(ctx context.Context, u Upload, src io.Reader) (string, error) {
	return c.write(ctx, u.grant, src, u.length)
}

func checkKnownLength(src io.Reader, length int64) error {
	if sr, ok := src.(interface{ Len() int }); ok {
		if int64(sr.Len()) != length {
			return ErrInput
		}
		return nil
	}
	seeker, ok := src.(io.Seeker)
	if !ok {
		return nil
	}
	if st, ok := src.(interface{ Stat() (os.FileInfo, error) }); ok {
		info, err := st.Stat()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		cur, err := seeker.Seek(0, io.SeekCurrent)
		if err == nil && info.Size()-cur != length {
			return ErrInput
		}
		return nil
	}
	cur, err := seeker.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil
	}
	end, endErr := seeker.Seek(0, io.SeekEnd)
	if _, restoreErr := seeker.Seek(cur, io.SeekStart); restoreErr != nil {
		return restoreErr
	}
	if endErr == nil && end-cur != length {
		return ErrInput
	}
	return nil
}

// uploadBody tracks caller source errors and probes one byte past length before
// releasing the final chunk so overlong HTTP/1.1 streams never commit truncated data.
type uploadBody struct {
	src  io.Reader
	rem  int64
	mu   sync.Mutex
	err  error
	done bool
}

func (u *uploadBody) recordErr(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.err == nil {
		u.err = err
	}
}

func (u *uploadBody) failure() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.err
}

func (u *uploadBody) completed() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.done && u.err == nil
}

func (u *uploadBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	u.mu.Lock()
	if u.err != nil {
		err := u.err
		u.mu.Unlock()
		return 0, err
	}
	if u.done {
		u.mu.Unlock()
		return 0, io.EOF
	}
	rem := u.rem
	u.mu.Unlock()

	if int64(len(p)) > rem {
		p = p[:int(rem)]
	}
	n, err := u.src.Read(p)
	rem -= int64(n)
	u.mu.Lock()
	u.rem = rem
	u.mu.Unlock()

	if err != nil && err != io.EOF {
		u.recordErr(err)
		return 0, err
	}
	if rem > 0 {
		if err == io.EOF {
			u.recordErr(ErrInput)
			return 0, ErrInput
		}
		return n, nil
	}
	if err == nil {
		var extra [1]byte
		m, probeErr := io.ReadFull(u.src, extra[:])
		if m > 0 {
			u.recordErr(ErrInput)
			return 0, ErrInput
		}
		if probeErr != io.EOF && probeErr != io.ErrUnexpectedEOF {
			u.recordErr(probeErr)
			return 0, probeErr
		}
	}
	u.mu.Lock()
	u.done = true
	u.mu.Unlock()
	return n, io.EOF
}

func (c *Client) write(ctx context.Context, g grant, src io.Reader, length int64) (string, error) {
	if src == nil || length < 0 || length == int64(^uint64(0)>>1) || g.method != "PUT" {
		return "", ErrInput
	}
	if err := checkKnownLength(src, length); err != nil {
		return "", err
	}
	var body io.Reader = http.NoBody
	var tracker *uploadBody
	if length == 0 {
		var probe [1]byte
		n, err := io.ReadFull(src, probe[:])
		if n != 0 {
			return "", ErrInput
		}
		if err != io.EOF {
			return "", err
		}
	} else {
		tracker = &uploadBody{src: src, rem: length}
		body = tracker
	}
	resp, e := c.data(ctx, g, body, length)
	if e != nil {
		if tracker != nil {
			if srcErr := tracker.failure(); srcErr != nil {
				return "", srcErr
			}
		}
		return "", e
	}
	defer resp.Body.Close()
	if tracker != nil && !tracker.completed() {
		if srcErr := tracker.failure(); srcErr != nil {
			return "", srcErr
		}
		return "", ErrInput
	}
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

type writerTracker struct {
	dst io.Writer
	err error
}

func (w *writerTracker) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if err != nil {
		if w.err == nil {
			w.err = err
		}
		return n, err
	}
	if n != len(p) {
		if w.err == nil {
			w.err = io.ErrShortWrite
		}
		return n, io.ErrShortWrite
	}
	return n, nil
}

func copyStream(ctx context.Context, op string, status int, dst io.Writer, src io.Reader) (int64, error) {
	tracker := &writerTracker{dst: dst}
	n, err := io.Copy(tracker, src)
	if err != nil {
		if tracker.err != nil {
			return n, tracker.err
		}
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		return n, &Error{op, status, ErrUnavailable}
	}
	return n, nil
}

func (c *Client) Download(ctx context.Context, id string, dst io.Writer) (int64, error) {
	return c.download(ctx, id, "", nil, dst)
}
func (c *Client) download(ctx context.Context, id, token string, jar http.CookieJar, dst io.Writer) (int64, error) {
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
		hc := c.anonymousClient(jar)
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
	return copyStream(ctx, "download-body", resp.StatusCode, dst, resp.Body)
}
