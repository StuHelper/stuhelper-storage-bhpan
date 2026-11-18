package bhpan

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func TestErrorProviderCodeRetryAfterAndOperations(t *testing.T) {
	ctx := context.Background()

	// 1. Numeric ProviderCode and Retry-After seconds on 403 / 429 API responses,
	// while stripping all provider diagnostic strings.
	t.Run("api-subcode-and-retry-after", func(t *testing.T) {
		step := 0
		c, _ := malformedFixture(t, func(w http.ResponseWriter, r *http.Request) {
			step++
			switch step {
			case 1:
				w.WriteHeader(http.StatusForbidden)
				reply(w, map[string]any{"code": 403002039, "message": "secret-duplicate-file-name-detail", "cause": "internal-path"})
			case 2:
				w.Header().Set("Retry-After", "45")
				w.WriteHeader(http.StatusTooManyRequests)
				reply(w, map[string]any{"error_code": 429001, "message": "secret-rate-limit-account"})
			case 3:
				w.Header().Set("Retry-After", "17")
				// HTTP 200 envelope with numeric code vs string code.
				reply(w, map[string]any{"code": 50012, "message": "secret-envelope-msg"})
			default:
				reply(w, map[string]any{"code": "string-must-not-leak", "message": "secret-msg"})
			}
		})
		c.token = "fixture-token"

		_, err := c.CreateDirectory(ctx, "gns://root", "courseware")
		var apiErr *Error
		if !errors.Is(err, ErrPermission) || !errors.As(err, &apiErr) || apiErr.ProviderCode != 403002039 || apiErr.RetryAfter != 0 {
			t.Fatalf("unexpected 403 error: %+v (%v)", apiErr, err)
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "internal-path") {
			t.Fatalf("provider message leaked in Error(): %s", err.Error())
		}

		_, err = c.Quota(ctx)
		apiErr = nil
		if !errors.Is(err, ErrUnavailable) || !errors.As(err, &apiErr) || apiErr.ProviderCode != 429001 || apiErr.RetryAfter != 45*time.Second {
			t.Fatalf("unexpected 429 error: %+v (%v)", apiErr, err)
		}
		if strings.Contains(err.Error(), "secret") {
			t.Fatalf("provider message leaked in 429 Error(): %s", err.Error())
		}

		err = c.Delete(ctx, "gns://root/file")
		apiErr = nil
		if !errors.Is(err, ErrRejected) || !errors.As(err, &apiErr) || apiErr.ProviderCode != 50012 || apiErr.RetryAfter != 17*time.Second {
			t.Fatalf("unexpected 200 envelope error: %+v (%v)", apiErr, err)
		}

		err = c.Delete(ctx, "gns://root/file")
		apiErr = nil
		if !errors.Is(err, ErrRejected) || !errors.As(err, &apiErr) || apiErr.ProviderCode != 0 || strings.Contains(err.Error(), "string-must-not-leak") {
			t.Fatalf("string code must not populate ProviderCode: %+v (%v)", apiErr, err)
		}
	})

	// 2. HTTP-date Retry-After parsing.
	t.Run("retry-after-http-date", func(t *testing.T) {
		now := time.Date(2026, 11, 18, 8, 0, 0, 0, time.UTC)
		hdr := http.Header{"Retry-After": []string{now.Add(90 * time.Second).Format(http.TimeFormat)}}
		if got := parseRetryAfterAt(hdr, now); got != 90*time.Second {
			t.Fatalf("expected 90s from HTTP-date Retry-After, got %v", got)
		}
		past := http.Header{"Retry-After": []string{now.Add(-10 * time.Second).Format(http.TimeFormat)}}
		if got := parseRetryAfterAt(past, now); got != 0 {
			t.Fatalf("expected 0 for past HTTP-date Retry-After, got %v", got)
		}
	})

	// 3. Distinct data() Operation names across all 5 object-transfer entrypoints.
	t.Run("distinct-transfer-operations", func(t *testing.T) {
		var base string
		c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/efast/v1/file/osbeginupload":
				reply(w, map[string]any{"docid": "gns://root/f", "rev": "r1", "authrequest": []string{"PUT", base + "/obj-fail", "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/octet-stream"}})
			case "/api/efast/v1/file/osinitmultiupload":
				reply(w, map[string]string{"docid": "gns://root/f", "rev": "r1", "uploadid": "u1"})
			case "/api/efast/v1/file/osuploadpart":
				reply(w, map[string]any{"authrequests": map[string]any{"1": []string{"PUT", base + "/obj-fail", "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/octet-stream"}}})
			case "/api/efast/v1/file/oscompleteupload":
				var b bytes.Buffer
				mw := multipart.NewWriter(&b)
				p, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": []string{"application/json"}})
				_ = json.NewEncoder(p).Encode(map[string]any{"authrequest": []string{"POST", base + "/obj-fail", "Authorization: sig", "X-Amz-Date: d", "Content-Type: application/xml"}})
				p, _ = mw.CreatePart(textproto.MIMEHeader{"Content-Type": []string{"application/xml"}})
				_, _ = fmt.Fprint(p, "<CompleteMultipartUpload/>")
				_ = mw.Close()
				w.Header().Set("Content-Type", "multipart/mixed; boundary="+mw.Boundary())
				_, _ = w.Write(b.Bytes())
			case "/api/efast/v1/file/osdownload":
				reply(w, map[string]any{"authrequest": []string{"GET", base + "/obj-fail"}})
			case "/api/efast/v1/file/batchdownload":
				reply(w, map[string]string{"url": base + "/obj-fail"})
			case "/obj-fail":
				w.Header().Set("Retry-After", "12")
				w.WriteHeader(http.StatusTooManyRequests)
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
			}
		})
		base = s.URL
		c.token = "fixture-token"

		assertOp := func(err error, wantOp string) {
			t.Helper()
			var apiErr *Error
			if !errors.As(err, &apiErr) || apiErr.Operation != wantOp || apiErr.RetryAfter != 12*time.Second || !errors.Is(err, ErrUnavailable) {
				t.Fatalf("want op=%q retry=12s, got %+v (%v)", wantOp, apiErr, err)
			}
		}

		up, err := c.BeginUpload(ctx, "gns://root", "a.bin", 3)
		check(t, err)
		_, err = c.WriteUpload(ctx, up, strings.NewReader("abc"))
		assertOp(err, "upload-write")

		mu, err := c.BeginMultipart(ctx, "gns://root", "b.bin", 3)
		check(t, err)
		grants, err := c.PartGrants(ctx, mu, 1, 1)
		check(t, err)
		_, err = c.WritePart(ctx, grants[0], strings.NewReader("abc"), 3)
		assertOp(err, "part-write")

		err = c.CompleteMultipart(ctx, mu, []Part{{Number: 1, ETag: "etag", Size: 3}})
		assertOp(err, "multipart-complete")

		_, err = c.Download(ctx, "gns://root/f", &bytes.Buffer{})
		assertOp(err, "download-data")

		_, err = c.DownloadArchive(ctx, "pack", nil, []string{"gns://root/f"}, &bytes.Buffer{})
		assertOp(err, "archive-data")
	})
}
