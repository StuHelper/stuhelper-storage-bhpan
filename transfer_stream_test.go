package bhpan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

type pacedReader struct {
	chunks [][]byte
	delay  time.Duration
	index  int
}

func (r *pacedReader) Read(p []byte) (int, error) {
	if r.index >= len(r.chunks) {
		return 0, io.EOF
	}
	if r.index > 0 && r.delay > 0 {
		time.Sleep(r.delay)
	}
	n := copy(p, r.chunks[r.index])
	r.chunks[r.index] = r.chunks[r.index][n:]
	if len(r.chunks[r.index]) == 0 {
		r.index++
	}
	return n, nil
}

type failingReader struct {
	prefix []byte
	err    error
}

func (r *failingReader) Read(p []byte) (int, error) {
	if len(r.prefix) > 0 {
		n := copy(p, r.prefix)
		r.prefix = r.prefix[n:]
		return n, nil
	}
	return 0, r.err
}

type failingWriter struct {
	limit   int
	written int
	err     error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.written >= w.limit {
		return 0, w.err
	}
	allow := min(len(p), w.limit-w.written)
	w.written += allow
	if allow < len(p) {
		return allow, w.err
	}
	return allow, nil
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestStreamTransfersOutliveRequestTimeoutAndAbortStalls(t *testing.T) {
	var base string
	var mode atomic.Value
	mode.Store("active")
	var uploaded bytes.Buffer

	validate := contractValidator(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		validate(r)
		switch r.URL.Path {
		case "/api/efast/v1/file/osbeginupload":
			reply(w, map[string]any{"docid": "file", "rev": "rev", "authrequest": []string{"PUT", base + "/object", "Authorization: signed", "X-Amz-Date: date", "Content-Type: application/octet-stream"}})
		case "/api/efast/v1/file/osuploadpart":
			reply(w, map[string]any{"authrequests": map[string]any{"1": []string{"PUT", base + "/object", "Authorization: signed", "X-Amz-Date: date", "Content-Type: application/octet-stream"}}})
		case "/api/efast/v1/file/osdownload":
			reply(w, map[string]any{"authrequest": []string{"GET", base + "/download"}})
		case "/api/efast/v1/file/batchdownload":
			reply(w, map[string]string{"url": base + "/archive"})
		case "/object":
			if mode.Load() == "stall-header" {
				time.Sleep(250 * time.Millisecond)
			}
			b, err := io.ReadAll(r.Body)
			if err != nil {
				return
			}
			uploaded.Reset()
			uploaded.Write(b)
			w.Header().Set("ETag", `"stream-etag"`)
		case "/download", "/archive":
			switch mode.Load() {
			case "stall-header":
				time.Sleep(250 * time.Millisecond)
				return
			case "stall-body":
				flusher := w.(http.Flusher)
				_, _ = w.Write([]byte("head"))
				flusher.Flush()
				time.Sleep(250 * time.Millisecond)
				_, _ = w.Write([]byte("tail"))
				return
			default:
				flusher := w.(http.Flusher)
				for i := 0; i < 6; i++ {
					if i > 0 {
						time.Sleep(25 * time.Millisecond)
					}
					_, _ = fmt.Fprintf(w, "chunk-%d;", i)
					flusher.Flush()
				}
			}
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	base = server.URL

	c, err := New(Config{CloudURL: base, SSOURL: base, Transport: server.Client().Transport, Timeout: 80 * time.Millisecond})
	check(t, err)
	t.Cleanup(c.Close)
	c.token = "fixture-token"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Active upload exceeding per-request Timeout (6 chunks * 25ms = 125ms > 80ms) must succeed.
	u, err := c.BeginUpload(ctx, "root", "video.mp4", 24)
	check(t, err)
	src := &pacedReader{
		chunks: [][]byte{[]byte("0001"), []byte("0002"), []byte("0003"), []byte("0004"), []byte("0005"), []byte("0006")},
		delay:  25 * time.Millisecond,
	}
	etag, err := c.WriteUpload(ctx, u, src)
	check(t, err)
	if etag != "stream-etag" || uploaded.String() != "000100020003000400050006" {
		t.Fatalf("unexpected upload result: etag=%q body=%q", etag, uploaded.String())
	}

	// Active multipart part upload exceeding Timeout must also succeed.
	grants, err := c.PartGrants(ctx, MultipartUpload{DocumentID: "file", Revision: "rev", UploadID: "up"}, 1, 1)
	check(t, err)
	partSrc := &pacedReader{
		chunks: [][]byte{[]byte("part"), []byte("-one"), []byte("-two"), []byte("-end"), []byte("1234"), []byte("5678")},
		delay:  25 * time.Millisecond,
	}
	part, err := c.WritePart(ctx, grants[0], partSrc, 24)
	check(t, err)
	if part.ETag != "stream-etag" || uploaded.String() != "part-one-two-end12345678" {
		t.Fatalf("unexpected part upload: %+v %q", part, uploaded.String())
	}

	// Active Download and DownloadArchive exceeding Timeout must succeed.
	var dl bytes.Buffer
	n, err := c.Download(ctx, "file", &dl)
	check(t, err)
	wantStream := "chunk-0;chunk-1;chunk-2;chunk-3;chunk-4;chunk-5;"
	if n != int64(len(wantStream)) || dl.String() != wantStream {
		t.Fatalf("unexpected download: n=%d body=%q", n, dl.String())
	}

	dl.Reset()
	n, err = c.DownloadArchive(ctx, "bundle", nil, []string{"file"}, &dl)
	check(t, err)
	if n != int64(len(wantStream)) || dl.String() != wantStream {
		t.Fatalf("unexpected archive download: n=%d body=%q", n, dl.String())
	}

	// Stalled response header or mid-body stall must still abort within idle Timeout as ErrUnavailable.
	for _, stall := range []string{"stall-header", "stall-body"} {
		mode.Store(stall)
		start := time.Now()
		dl.Reset()
		_, err = c.Download(ctx, "file", &dl)
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("%s: expected ErrUnavailable, got %v", stall, err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("%s: did not abort promptly on idle timeout (%v)", stall, elapsed)
		}
	}

	// Caller context deadline still governs total wall-clock transfer duration.
	mode.Store("active")
	shortCtx, shortCancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer shortCancel()
	dl.Reset()
	_, err = c.Download(shortCtx, "file", &dl)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
}

func TestUploadStreamLengthAndSourceErrors(t *testing.T) {
	var base string
	var objectHits atomic.Int32
	var committedObjects atomic.Int32

	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/efast/v1/file/osbeginupload":
			reply(w, map[string]any{"docid": "file", "rev": "rev", "authrequest": []string{"PUT", base + "/object", "Authorization: signed", "X-Amz-Date: date", "Content-Type: application/octet-stream"}})
		case "/api/efast/v1/file/osuploadpart":
			reply(w, map[string]any{"authrequests": map[string]any{"1": []string{"PUT", base + "/object", "Authorization: signed", "X-Amz-Date: date", "Content-Type: application/octet-stream"}}})
		case "/object":
			objectHits.Add(1)
			b, err := io.ReadAll(r.Body)
			if err == nil && int64(len(b)) == r.ContentLength {
				committedObjects.Add(1)
			}
			w.Header().Set("ETag", `"etag"`)
		default:
			w.WriteHeader(404)
		}
	})
	base = s.URL
	c.token = "fixture-token"
	ctx := context.Background()

	u, err := c.BeginUpload(ctx, "root", "data.bin", 4)
	check(t, err)
	grants, err := c.PartGrants(ctx, MultipartUpload{DocumentID: "file", Revision: "rev", UploadID: "up"}, 1, 1)
	check(t, err)

	// 1. Seekable / Len()-aware inputs mismatching length fail before network I/O.
	tmpFile, err := os.CreateTemp(t.TempDir(), "upload-*.bin")
	check(t, err)
	_, err = tmpFile.WriteString("12345")
	check(t, err)
	_, err = tmpFile.Seek(0, io.SeekStart)
	check(t, err)
	t.Cleanup(func() { _ = tmpFile.Close() })

	for _, reader := range []io.Reader{
		strings.NewReader("123"),
		strings.NewReader("12345"),
		bytes.NewBufferString("123"),
		bytes.NewBufferString("12345"),
		tmpFile,
	} {
		_, err = c.WriteUpload(ctx, u, reader)
		if !errors.Is(err, ErrInput) || errors.Is(err, ErrUnavailable) {
			t.Fatalf("expected ErrInput for known-length mismatch, got %v", err)
		}
	}
	if objectHits.Load() != 0 {
		t.Fatalf("known-length mismatch sent %d object requests", objectHits.Load())
	}

	// 2. Non-seekable short and overlong streams (including multi-chunk 1-byte reads) return ErrInput
	// and never allow the object store to commit a complete Content-Length truncated payload.
	for _, tc := range []struct {
		name string
		src  io.Reader
	}{
		{"nonseekable-short", io.NopCloser(strings.NewReader("abc"))},
		{"nonseekable-overlong-single", io.NopCloser(strings.NewReader("abcde"))},
		{"nonseekable-overlong-chunked", iotest.OneByteReader(strings.NewReader("abcde"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.WriteUpload(ctx, u, tc.src)
			if !errors.Is(err, ErrInput) || errors.Is(err, ErrUnavailable) {
				t.Fatalf("expected ErrInput, got %v", err)
			}
			if committedObjects.Load() != 0 {
				t.Fatalf("truncated or mismatched object was committed on server (%d)", committedObjects.Load())
			}
		})
	}
	_, err = c.WritePart(ctx, grants[0], iotest.OneByteReader(strings.NewReader("abcde")), 4)
	if !errors.Is(err, ErrInput) || committedObjects.Load() != 0 {
		t.Fatalf("WritePart overlong stream failed to return ErrInput safely: err=%v committed=%d", err, committedObjects.Load())
	}

	// 3. Local source Read I/O errors are preserved instead of misreporting ErrUnavailable.
	errDiskRead := errors.New("local disk read failure")
	_, err = c.WriteUpload(ctx, u, &failingReader{prefix: []byte("ab"), err: errDiskRead})
	if !errors.Is(err, errDiskRead) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("WriteUpload swallowed local read error: %v", err)
	}
	_, err = c.WritePart(ctx, grants[0], &failingReader{prefix: []byte("ab"), err: errDiskRead}, 4)
	if !errors.Is(err, errDiskRead) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("WritePart swallowed local read error: %v", err)
	}
}

func TestDownloadPreservesDestinationWriteErrors(t *testing.T) {
	var base string
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/efast/v1/file/osdownload":
			reply(w, map[string]any{"authrequest": []string{"GET", base + "/download"}})
		case "/api/efast/v1/file/batchdownload":
			reply(w, map[string]string{"url": base + "/archive"})
		case "/download", "/archive":
			_, _ = w.Write([]byte("abcdef"))
		default:
			w.WriteHeader(404)
		}
	})
	base = s.URL
	c.token = "fixture-token"
	ctx := context.Background()

	errDiskFull := errors.New("no space left on device")

	fw := &failingWriter{limit: 2, err: errDiskFull}
	n, err := c.Download(ctx, "file", fw)
	if !errors.Is(err, errDiskFull) || errors.Is(err, ErrUnavailable) || n != 2 {
		t.Fatalf("Download: n=%d err=%v", n, err)
	}

	fw = &failingWriter{limit: 3, err: errDiskFull}
	n, err = c.DownloadShared(ctx, SharedEntry{ID: "file", Name: "shared.bin", Size: 6, token: "share-token"}, fw)
	if !errors.Is(err, errDiskFull) || errors.Is(err, ErrUnavailable) || n != 3 {
		t.Fatalf("DownloadShared: n=%d err=%v", n, err)
	}

	fw = &failingWriter{limit: 4, err: errDiskFull}
	n, err = c.DownloadArchive(ctx, "archive", nil, []string{"file"}, fw)
	if !errors.Is(err, errDiskFull) || errors.Is(err, ErrUnavailable) || n != 4 {
		t.Fatalf("DownloadArchive: n=%d err=%v", n, err)
	}

	_, err = c.Download(ctx, "file", shortWriter{})
	if !errors.Is(err, io.ErrShortWrite) || errors.Is(err, ErrUnavailable) {
		t.Fatalf("short writer: expected ErrShortWrite, got %v", err)
	}
}

func TestDownloadArchiveRejectsExcessiveEntries(t *testing.T) {
	var base string
	var calls atomic.Int32
	c, s := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		switch r.URL.Path {
		case "/api/efast/v1/file/batchdownload":
			reply(w, map[string]string{"url": base + "/archive"})
		case "/archive":
			_, _ = w.Write([]byte("pk"))
		default:
			w.WriteHeader(404)
		}
	})
	base = s.URL
	c.token = "fixture-token"
	ctx := context.Background()

	tooMany := make([]string, 1001)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("file-%d", i)
	}
	var dst bytes.Buffer
	if _, err := c.DownloadArchive(ctx, "bundle", nil, tooMany, &dst); !errors.Is(err, ErrInput) {
		t.Fatalf("expected ErrInput for 1001 files, got %v", err)
	}
	if _, err := c.DownloadArchive(ctx, "bundle", tooMany[:500], tooMany[500:], &dst); !errors.Is(err, ErrInput) {
		t.Fatalf("expected ErrInput for 500 dirs + 501 files, got %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("over-limit archive sent %d requests", calls.Load())
	}

	if _, err := c.DownloadArchive(ctx, "bundle", tooMany[:500], tooMany[500:1000], &dst); err != nil {
		t.Fatalf("expected 1000 total entries to succeed, got %v", err)
	}
}
