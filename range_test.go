package bhpan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
)

func TestDownloadRangeAndSharedRange(t *testing.T) {
	const content = "0123456789abcdef"
	var base string
	mode := "valid"
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/efast/v1/file/osdownload":
			if r.Header.Get("Authorization") == "Bearer share-token" {
				if r.Header.Get("Cookie") != "INGRESSCOOKIE=share-route" {
					t.Error("missing share route cookie on osdownload")
				}
			} else if r.Header.Get("Authorization") != "Bearer account-token" {
				t.Error("unexpected authorization on osdownload")
			}
			reply(w, map[string]any{"authrequest": []string{"GET", base + "/object?sig=1"}})
		case "/object":
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				t.Error("credentials leaked to object store")
			}
			switch mode {
			case "ignore-range-200":
				w.Header().Set("Content-Type", "application/pdf")
				w.WriteHeader(http.StatusOK)
				_, _ = io.WriteString(w, content)
				return
			case "unsatisfiable-416":
				w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", len(content)))
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			case "mismatch-range":
				w.Header().Set("Content-Range", "bytes 0-3/16")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = io.WriteString(w, content[:4])
				return
			case "short-body":
				w.Header().Set("Content-Range", "bytes 4-7/16")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = io.WriteString(w, "45")
				return
			case "long-body":
				w.Header().Set("Content-Range", "bytes 4-7/16")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = io.WriteString(w, "456789")
				return
			}
			rng := r.Header.Get("Range")
			switch rng {
			case "bytes=4-7":
				w.Header().Set("Content-Type", "application/pdf")
				w.Header().Set("ETag", `"pdf-etag-v1"`)
				w.Header().Set("Content-Range", "bytes 4-7/16")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = io.WriteString(w, content[4:8])
			case "bytes=12-21":
				// Request extends past EOF; compliant servers clamp end to total-1.
				w.Header().Set("Content-Type", "application/pdf")
				w.Header().Set("ETag", `"pdf-etag-v1"`)
				w.Header().Set("Content-Range", "bytes 12-15/16")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = io.WriteString(w, content[12:16])
			case "bytes=10-":
				w.Header().Set("Content-Type", "video/mp4")
				w.Header().Set("ETag", `"mp4-etag"`)
				w.Header().Set("Content-Range", "bytes 10-15/16")
				w.WriteHeader(http.StatusPartialContent)
				_, _ = io.WriteString(w, content[10:16])
			default:
				t.Errorf("unexpected Range header %q", rng)
				w.WriteHeader(http.StatusBadRequest)
			}
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	base = s.URL
	c.token = "account-token"
	u, _ := url.Parse(base)
	c.client.Jar.SetCookies(u, []*http.Cookie{{Name: "personal", Value: "secret", Path: "/"}})
	ctx := context.Background()

	// 1. Standard bounded range download with stream metadata.
	var dst bytes.Buffer
	info, err := c.DownloadRange(ctx, "gns://root/doc", 4, 4, &dst)
	check(t, err)
	if dst.String() != "4567" || info.Written != 4 || info.TotalSize != 16 || info.ETag != "pdf-etag-v1" || info.ContentType != "application/pdf" {
		t.Fatalf("unexpected DownloadInfo: %+v body=%q", info, dst.String())
	}

	// 2. Range clamped at object end.
	dst.Reset()
	info, err = c.DownloadRange(ctx, "gns://root/doc", 12, 10, &dst)
	check(t, err)
	if dst.String() != "cdef" || info.Written != 4 || info.TotalSize != 16 {
		t.Fatalf("unexpected clamped range: %+v body=%q", info, dst.String())
	}

	// 3. Shared range download with isolated cookie jar and open-ended length (-1).
	shareJar, _ := cookiejar.New(nil)
	shareJar.SetCookies(u, []*http.Cookie{{Name: "INGRESSCOOKIE", Value: "share-route", Path: "/"}})
	shared := SharedEntry{ID: "gns://shared/video", Name: "lecture.mp4", Size: 16, token: "share-token", jar: shareJar}
	dst.Reset()
	info, err = c.DownloadSharedRange(ctx, shared, 10, -1, &dst)
	check(t, err)
	if dst.String() != "abcdef" || info.Written != 6 || info.TotalSize != 16 || info.ETag != "mp4-etag" || info.ContentType != "video/mp4" {
		t.Fatalf("unexpected shared range: %+v body=%q", info, dst.String())
	}

	// 4. Input boundary validation.
	for _, tc := range []struct {
		id             string
		offset, length int64
		nilWriter      bool
	}{
		{"", 0, 4, false},
		{"gns://root/doc", -1, 4, false},
		{"gns://root/doc", 0, 0, false},
		{"gns://root/doc", 0, -2, false},
		{"gns://root/doc", math.MaxInt64 - 2, 5, false},
		{"gns://root/doc", 0, 4, true},
	} {
		var w io.Writer = &bytes.Buffer{}
		if tc.nilWriter {
			w = nil
		}
		if _, err := c.DownloadRange(ctx, tc.id, tc.offset, tc.length, w); !errors.Is(err, ErrInput) {
			t.Fatalf("expected ErrInput for %+v, got %v", tc, err)
		}
	}
	if _, err := c.DownloadSharedRange(ctx, SharedEntry{ID: "gns://shared/video"}, 0, 4, &bytes.Buffer{}); !errors.Is(err, ErrSession) {
		t.Fatalf("expected ErrSession for empty share token, got %v", err)
	}

	// 5. Protocol and range rejection cases.
	for _, tc := range []struct {
		mode string
		want error
	}{
		{"ignore-range-200", ErrProtocol},
		{"unsatisfiable-416", ErrRejected},
		{"mismatch-range", ErrProtocol},
		{"short-body", ErrProtocol},
		{"long-body", ErrProtocol},
	} {
		mode = tc.mode
		dst.Reset()
		if _, err := c.DownloadRange(ctx, "gns://root/doc", 4, 4, &dst); !errors.Is(err, tc.want) {
			t.Fatalf("mode %s: expected %v, got %v", tc.mode, tc.want, err)
		}
	}
}
