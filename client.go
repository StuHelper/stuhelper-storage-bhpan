package bhpan

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"
)

const metadataLimit = 4 << 20

// Config accepts trusted operator configuration. Credentials are supplied only
// to LoginLocal, and are not retained by the adapter.
type Config struct {
	CloudURL string

	Transport         http.RoundTripper
	Timeout           time.Duration
	DataOrigins       []string
	LocalPublicKeyPEM string
}

type Client struct {
	mu        sync.RWMutex
	cloud     string
	client    *http.Client
	transport http.RoundTripper
	timeout   time.Duration
	origins   map[string]bool
	localKey  *rsa.PublicKey
	token     string
}

func New(cfg Config) (*Client, error) {
	if cfg.CloudURL == "" {
		cfg.CloudURL = "https://bhpan.buaa.edu.cn"
	}
	cloud, err := parseOrigin(cfg.CloudURL)
	if err != nil {
		return nil, err
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Timeout < 0 {
		return nil, ErrInput
	}
	localKey, err := resolveLocalPublicKey(cfg.LocalPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	c := &Client{cloud: cloud, timeout: cfg.Timeout, transport: cfg.Transport, origins: map[string]bool{cloud: true}, localKey: localKey}
	for _, raw := range cfg.DataOrigins {
		origin, err := parseOrigin(raw)
		if err != nil {
			return nil, err
		}
		c.origins[origin] = true
	}
	c.reset()
	return c, nil
}

func parseOrigin(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", ErrInput
	}
	return originOf(u), nil
}

func originOf(u *url.URL) string {
	host := strings.ToLower(u.Host)
	if u.Scheme == "https" && u.Port() == "443" {
		host = strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			host = "[" + host + "]"
		}
	}
	return u.Scheme + "://" + host
}

func (c *Client) reset() {
	jar, _ := cookiejar.New(nil)
	c.token = ""
	c.client = &http.Client{Transport: c.transport, Timeout: c.timeout, Jar: jar, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return ErrProtocol
		}
		if req.URL.User != nil || req.URL.Fragment != "" {
			return ErrDestination
		}
		if originOf(req.URL) != c.cloud {
			return ErrDestination
		}
		return nil
	}}
}

// Close invalidates the entire session, including cloud cookies.
func (c *Client) Close() { c.mu.Lock(); defer c.mu.Unlock(); c.reset() }

func readResponseBody(ctx context.Context, op string, status int, r io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, metadataLimit+1))
	if e != nil {
		if ctx.Err() != nil {
			return nil, &Error{Operation: op, Status: status, Kind: ctx.Err()}
		}
		return nil, &Error{Operation: op, Status: status, Kind: ErrUnavailable}
	}
	if len(b) > metadataLimit {
		return nil, &Error{Operation: op, Status: status, Kind: ErrProtocol}
	}
	return b, nil
}

func limitedRead(r io.Reader) ([]byte, error) {
	b, e := io.ReadAll(io.LimitReader(r, metadataLimit+1))
	if e != nil || len(b) > metadataLimit {
		return nil, ErrProtocol
	}
	return b, nil
}

func request(ctx context.Context, hc *http.Client, operation, method, target, contentType, token string, body io.Reader) ([]byte, http.Header, *url.URL, int, error) {
	req, e := http.NewRequestWithContext(ctx, method, target, body)
	if e != nil {
		return nil, nil, nil, 0, &Error{Operation: operation, Status: 0, Kind: ErrInput}
	}
	req.Header.Set("User-Agent", "StuHelper-Next-BHpan/0.1")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, e := hc.Do(req)
	if e != nil {
		kind := ErrUnavailable
		if ctx.Err() != nil {
			kind = ctx.Err()
		} else if errors.Is(e, ErrDestination) {
			kind = ErrDestination
		} else if errors.Is(e, ErrProtocol) {
			kind = ErrProtocol
		}
		// net/http returns the preceding response with its body already closed
		// when CheckRedirect rejects a hop. Keep only its HTTP status.
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return nil, nil, nil, status, &Error{Operation: operation, Status: status, Kind: kind}
	}
	defer resp.Body.Close()
	data, e := readResponseBody(ctx, operation, resp.StatusCode, resp.Body)
	if e != nil {
		return nil, nil, nil, resp.StatusCode, e
	}
	return data, resp.Header, resp.Request.URL, resp.StatusCode, nil
}

func statusError(op string, status int) error {
	return responseError(op, status, nil, nil)
}

func responseError(op string, status int, headers http.Header, body []byte) error {
	if status >= 200 && status < 300 {
		return nil
	}
	return providerFailure(op, status, headers, body)
}

func providerFailure(op string, status int, headers http.Header, body []byte) *Error {
	kind := ErrUnavailable
	switch status {
	case 401:
		kind = ErrSession
	case 403:
		kind = ErrPermission
	case 404:
		kind = ErrNotFound
	case 409:
		kind = ErrConflict
	case 400, 422:
		kind = ErrRejected
	}
	return &Error{
		Operation:    op,
		Status:       status,
		Kind:         kind,
		ProviderCode: extractProviderCode(body),
		RetryAfter:   parseRetryAfterAt(headers, time.Now()),
	}
}

func (c *Client) sessionClient(op string) (*http.Client, string, error) {
	c.mu.RLock()
	token := c.token
	var hc http.Client
	if c.client != nil {
		hc = *c.client
	}
	c.mu.RUnlock()
	if token == "" {
		return nil, "", &Error{Operation: op, Status: 0, Kind: ErrSession}
	}
	return &hc, token, nil
}

func (c *Client) api(ctx context.Context, op, method, path string, in, out any) error {
	hc, token, err := c.sessionClient(op)
	if err != nil {
		return err
	}
	return c.json(ctx, hc, token, op, method, path, in, out)
}

func (c *Client) json(ctx context.Context, hc *http.Client, token, op, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, e := json.Marshal(in)
		if e != nil {
			return ErrInput
		}
		body = bytes.NewReader(b)
	}
	// API calls must never turn a redirect/login HTML page into an apparent success.
	local := *hc
	local.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	b, headers, _, status, e := request(ctx, &local, op, method, c.cloud+path, "application/json", token, body)
	if e != nil {
		return e
	}
	if e = responseError(op, status, headers, b); e != nil {
		return e
	}
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) > 0 {
		if !json.Valid(trimmed) || bytes.Equal(trimmed, []byte("false")) {
			return &Error{Operation: op, Status: status, Kind: ErrProtocol}
		}
		var envelope map[string]json.RawMessage
		if json.Unmarshal(trimmed, &envelope) == nil {
			for _, key := range []string{"code", "error_code", "error"} {
				value := bytes.TrimSpace(envelope[key])
				if len(value) > 0 && !bytes.Equal(value, []byte("0")) && !bytes.Equal(value, []byte("null")) && !bytes.Equal(value, []byte(`""`)) {
					return &Error{Operation: op, Status: status, Kind: ErrRejected, ProviderCode: extractProviderCode(trimmed), RetryAfter: parseRetryAfterAt(headers, time.Now())}
				}
			}
		}
	}
	if out != nil {
		if len(bytes.TrimSpace(b)) == 0 || bytes.Equal(bytes.TrimSpace(b), []byte("null")) || json.Unmarshal(b, out) != nil {
			return &Error{Operation: op, Status: status, Kind: ErrProtocol}
		}
	}
	return nil
}

func textOK(s string) bool {
	return strings.TrimSpace(s) != "" && len(s) <= 4096 && !strings.ContainsAny(s, "\r\n\x00")
}
func nameOK(s string) bool {
	return textOK(s) && s != "." && s != ".." && !strings.ContainsAny(s, "/\\")
}
