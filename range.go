package bhpan

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DownloadInfo reports the copied byte count and object metadata returned by
// a ranged download response.
type DownloadInfo struct {
	Written     int64
	TotalSize   int64
	ContentType string
	ETag        string
}

// DownloadRange reads a byte range starting at offset into dst. Pass length > 0
// for an explicit byte count, or length == -1 to read from offset to the end of
// the object. Object responses must return 206 Partial Content with a matching
// Content-Range header.
func (c *Client) DownloadRange(ctx context.Context, id string, offset, length int64, dst io.Writer) (DownloadInfo, error) {
	return c.downloadRange(ctx, id, "", nil, offset, length, dst)
}

// DownloadSharedRange reads a byte range from an isolated anonymous share entry
// without attaching personal account credentials or cookies to the object store.
func (c *Client) DownloadSharedRange(ctx context.Context, e SharedEntry, offset, length int64, dst io.Writer) (DownloadInfo, error) {
	if !textOK(e.token) {
		return DownloadInfo{}, ErrSession
	}
	return c.downloadRange(ctx, e.ID, e.token, e.jar, offset, length, dst)
}

func formatByteRange(offset, length int64) (string, error) {
	if offset < 0 || length == 0 || length < -1 {
		return "", ErrInput
	}
	if length == -1 {
		return fmt.Sprintf("bytes=%d-", offset), nil
	}
	if offset > math.MaxInt64-(length-1) {
		return "", ErrInput
	}
	return fmt.Sprintf("bytes=%d-%d", offset, offset+length-1), nil
}

func parseNonNegativeInt64(raw string) (int64, bool) {
	if raw == "" || strings.HasPrefix(raw, "+") {
		return 0, false
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

func parseContentRange(raw string, offset, length int64) (expected, total int64, err error) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 7 || !strings.EqualFold(raw[:6], "bytes ") {
		return 0, 0, ErrProtocol
	}
	spec := strings.TrimSpace(raw[6:])
	span, totalStr, ok := strings.Cut(spec, "/")
	if !ok {
		return 0, 0, ErrProtocol
	}
	startStr, endStr, ok := strings.Cut(span, "-")
	if !ok {
		return 0, 0, ErrProtocol
	}
	start, okStart := parseNonNegativeInt64(startStr)
	end, okEnd := parseNonNegativeInt64(endStr)
	total, okTotal := parseNonNegativeInt64(totalStr)
	if !okStart || !okEnd || !okTotal || start != offset || end < start || total <= end {
		return 0, 0, ErrProtocol
	}
	wantEnd := total - 1
	if length > 0 && offset+length-1 < wantEnd {
		wantEnd = offset + length - 1
	}
	if end != wantEnd {
		return 0, 0, ErrProtocol
	}
	return end - start + 1, total, nil
}

func (c *Client) downloadRange(ctx context.Context, id, token string, jar http.CookieJar, offset, length int64, dst io.Writer) (DownloadInfo, error) {
	if !textOK(id) || dst == nil {
		return DownloadInfo{}, ErrInput
	}
	rangeHeader, err := formatByteRange(offset, length)
	if err != nil {
		return DownloadInfo{}, err
	}
	var out struct {
		Auth []string `json:"authrequest"`
	}
	in := map[string]any{"docid": id, "authtype": "QUERY_STRING"}
	if token == "" {
		err = c.api(ctx, "download", "POST", "/api/efast/v1/file/osdownload", in, &out)
	} else {
		hc := c.anonymousClient(jar)
		err = c.json(ctx, hc, token, "share-download", "POST", "/api/efast/v1/file/osdownload", in, &out)
	}
	if err != nil {
		return DownloadInfo{}, err
	}
	g, err := c.decodeGrant(out.Auth, "GET")
	if err != nil {
		return DownloadInfo{}, err
	}
	if !g.deadline.After(time.Now()) {
		return DownloadInfo{}, ErrSession
	}
	if err = c.trustedData(g.target); err != nil {
		return DownloadInfo{}, err
	}
	req, err := http.NewRequestWithContext(ctx, g.method, g.target, nil)
	if err != nil {
		return DownloadInfo{}, ErrInput
	}
	req.Header = g.headers.Clone()
	req.Header.Set("Range", rangeHeader)
	hc := &http.Client{Transport: c.transport, Timeout: c.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return DownloadInfo{}, ctx.Err()
		}
		return DownloadInfo{}, &Error{"transfer", 0, ErrUnavailable}
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusRequestedRangeNotSatisfiable {
		return DownloadInfo{}, &Error{"transfer", resp.StatusCode, ErrRejected}
	}
	if resp.StatusCode != http.StatusPartialContent {
		if e := statusError("transfer", resp.StatusCode); e != nil {
			return DownloadInfo{}, e
		}
		return DownloadInfo{}, &Error{"transfer", resp.StatusCode, ErrProtocol}
	}
	expected, total, err := parseContentRange(resp.Header.Get("Content-Range"), offset, length)
	if err != nil {
		return DownloadInfo{}, &Error{"transfer", resp.StatusCode, err}
	}
	etag := strings.Trim(resp.Header.Get("ETag"), "\"")
	contentType := strings.TrimSpace(resp.Header.Get("Content-Type"))
	if strings.ContainsAny(etag, "\r\n\x00\"") || strings.ContainsAny(contentType, "\r\n\x00") {
		return DownloadInfo{}, &Error{"transfer", resp.StatusCode, ErrProtocol}
	}
	n, err := io.Copy(dst, io.LimitReader(resp.Body, expected+1))
	info := DownloadInfo{Written: n, TotalSize: total, ContentType: contentType, ETag: etag}
	if err != nil {
		if ctx.Err() != nil {
			return info, ctx.Err()
		}
		return info, &Error{"download-body", resp.StatusCode, ErrUnavailable}
	}
	if n != expected {
		return info, &Error{"download-body", resp.StatusCode, ErrProtocol}
	}
	return info, nil
}
