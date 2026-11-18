package bhpan

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type interruptedBody struct {
	prefix []byte
	err    error
}

func (b *interruptedBody) Read(p []byte) (int, error) {
	if len(b.prefix) > 0 {
		n := copy(p, b.prefix)
		b.prefix = b.prefix[n:]
		return n, nil
	}
	return 0, b.err
}

func (b *interruptedBody) Close() error { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestResponseBodyInterruptionAndContextCancellation(t *testing.T) {
	// 1. Mid-body network interruption after HTTP 200 header must report ErrUnavailable, not ErrProtocol.
	c, err := New(Config{
		CloudURL: "https://bhpan.buaa.edu.cn",
		SSOURL:   "https://sso.buaa.edu.cn",
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       &interruptedBody{prefix: []byte(`{"allocated":`), err: io.ErrUnexpectedEOF},
				Request:    r,
			}, nil
		}),
		Timeout: time.Second,
	})
	check(t, err)
	c.token = "fixture-token"

	_, err = c.Quota(context.Background())
	var bhErr *Error
	if !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrProtocol) || !errors.As(err, &bhErr) {
		t.Fatalf("expected *Error wrapping ErrUnavailable on truncated response body, got %v", err)
	}

	// 2. Context cancellation while reading upload response body must report context.Canceled, not bare ErrProtocol.
	ctx, cancel := context.WithCancel(context.Background())
	c2, err := New(Config{
		CloudURL: "https://bhpan.buaa.edu.cn",
		SSOURL:   "https://sso.buaa.edu.cn",
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/api/efast/v1/file/osbeginupload" {
				body := `{"docid":"f1","rev":"r1","authrequest":["PUT","https://bhpan.buaa.edu.cn/object","Authorization: sig","X-Amz-Date: now","Content-Type: application/octet-stream"]}`
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
			}
			if _, err := io.Copy(io.Discard, r.Body); err != nil {
				return nil, err
			}
			if err := r.Body.Close(); err != nil {
				return nil, err
			}
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"ETag": []string{`"e1"`}},
				Body: io.NopCloser(roundTripReader(func(p []byte) (int, error) {
					cancel()
					return 0, context.Canceled
				})),
				Request: r,
			}, nil
		}),
		Timeout: time.Second,
	})
	check(t, err)
	c2.token = "fixture-token"
	u, err := c2.BeginUpload(ctx, "root", "file.bin", 4)
	check(t, err)
	_, err = c2.WriteUpload(ctx, u, strings.NewReader("abcd"))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled during upload response read, got %v", err)
	}
}

type roundTripReader func([]byte) (int, error)

func (f roundTripReader) Read(p []byte) (int, error) { return f(p) }

func TestCloseDoesNotBlockOnSlowAPIRequest(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	c, err := New(Config{
		CloudURL: "https://bhpan.buaa.edu.cn",
		SSOURL:   "https://sso.buaa.edu.cn",
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			close(entered)
			<-release
			return &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
				Body:       io.NopCloser(strings.NewReader(`[]`)),
				Request:    r,
			}, nil
		}),
		Timeout: 5 * time.Second,
	})
	check(t, err)
	c.token = "fixture-token"

	apiDone := make(chan struct{})
	go func() {
		defer close(apiDone)
		_, _ = c.Libraries(context.Background())
	}()

	<-entered
	closeDone := make(chan struct{})
	go func() {
		c.Close()
		close(closeDone)
	}()

	select {
	case <-closeDone:
	case <-time.After(150 * time.Millisecond):
		close(release)
		t.Fatal("c.Close() blocked on in-flight c.api() network request")
	}
	close(release)
	<-apiDone
}

func TestGrantHeaderStrictnessAndExpirationDistinctFromSession(t *testing.T) {
	c, err := New(Config{})
	check(t, err)

	// Empty header followed by duplicate header must be rejected.
	if _, err := c.decodeGrant([]string{
		"PUT", "https://bhpan.buaa.edu.cn/object",
		"Authorization: ",
		"Authorization: second",
		"X-Amz-Date: now",
		"Content-Type: application/octet-stream",
	}, "PUT"); !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol for empty+duplicate Authorization header, got %v", err)
	}

	// GET grant must not accept upload signature headers.
	if _, err := c.decodeGrant([]string{
		"GET", "https://bhpan.buaa.edu.cn/download?sig=1",
		"Authorization: unexpected",
	}, "GET"); !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol for GET grant with extra headers, got %v", err)
	}

	// Expired local grant must NOT return ErrSession (which triggers account session logout).
	g, err := c.decodeGrant([]string{
		"PUT", "https://bhpan.buaa.edu.cn/object",
		"Authorization: sig",
		"X-Amz-Date: now",
		"Content-Type: application/octet-stream",
	}, "PUT")
	check(t, err)
	g.deadline = time.Now().Add(-time.Second)
	_, err = c.data(context.Background(), g, bytes.NewReader([]byte("x")), 1)
	if !errors.Is(err, ErrGrantExpired) || errors.Is(err, ErrSession) {
		t.Fatalf("expired local grant must report ErrGrantExpired and not ErrSession, got %v", err)
	}
}

func TestContractValidatorCoversEscapedGNSNonAPIAndAdditionalProps(t *testing.T) {
	// 1. Escaped GNS ID containing '%2F' in Shares path must pass contractValidator.
	c, _ := fixture(t, func(w http.ResponseWriter, r *http.Request) {
		reply(w, []Share{})
	})
	c.token = "fixture-token"
	if _, err := c.Shares(context.Background(), "gns://root-bucket/file-1"); err != nil {
		t.Fatalf("Shares with GNS ID failed: %v", err)
	}

	// 2. Boolean additionalProperties: false must reject extra fields in conforms.
	rawSchema := map[string]any{"type": "object", "additionalProperties": false}
	if conforms(rawSchema, map[string]any{"unexpected": "field"}, map[string]any{}) {
		t.Fatal("conforms accepted extra field despite additionalProperties: false")
	}

	// 3. Non-/api/ contract endpoints (/link POST) must be validated by contractValidator.
	probeT := &testing.T{}
	validate := contractValidator(probeT)
	badReq := httptest.NewRequest("POST", "https://bhpan.buaa.edu.cn/link", strings.NewReader(`{"wrong":"body"}`))
	validate(badReq)
	if !probeT.Failed() {
		t.Fatal("contractValidator skipped invalid POST /link request")
	}
}
