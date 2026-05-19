// SPDX-License-Identifier: AGPL-3.0-or-later
// Package httpc — minimal HTTP client for talking to a fabric transport
// (nakli-hub or nakli-cf-worker). Per the M1 wire-protocol audit
// (docs/wire-protocol-audit.md §3), fabric-sdk-go has no top-level
// Transport/Client type; the daemon brings its own thin wrapper.
//
// M1 scope: `GET /fabric/v1/health` only (unauthenticated). M2 adds
// `POST /v1/pairing/redeem` (unauthenticated POST JSON). M3 piece 5 adds
// macaroon-bearing object methods (`PutObject`, `GetObject`, `HeadObject`,
// `DeleteObject`, `ListObjects`) that talk to the Hub's bucket-proxy
// (private-mesh@dbec7e8). All authenticated methods carry an
// `X-Fabric-Grant: <base64 macaroon>` header.

package httpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client speaks HTTP to a fabric transport. Construct via New.
type Client struct {
	endpoint string
	http     *http.Client
}

// New builds a client whose requests are issued against `endpoint`
// (e.g. "http://127.0.0.1:7842"). Trailing slashes are stripped so
// callers can use clean path concatenation.
func New(endpoint string) *Client {
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		http: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Envelope matches the response shape from fabric-spec-001 §"Response
// envelope": every endpoint returns `{ok, data?, error?}`. The Hub's
// `/health` returns `{ok: true, data: {…}}`; the daemon only cares
// about `ok` at M1.
type Envelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error *EnvelopeError  `json:"error,omitempty"`
}

// EnvelopeError is the `error` slot of an envelope when `ok: false`.
type EnvelopeError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response wraps a parsed envelope alongside the raw HTTP status.
//
// ETag + ContentLength are populated for object-proxy calls (PUT/GET/HEAD);
// envelope-style endpoints leave them zero. Body is populated by methods
// that need the raw bytes (e.g. ListObjects' XML response, GetObject).
type Response struct {
	Status        int
	Envelope      Envelope
	ETag          string
	ContentLength int64
	Body          []byte
}

// Health hits `GET /fabric/v1/health`. The endpoint is unauthenticated
// per nakli-hub's middleware (no `X-Fabric-Grant` header required).
// Returns (resp, nil) when the request completes, even on 4xx/5xx —
// callers decide what to do based on `resp.Status` and `resp.Envelope.OK`.
// Returns (nil, err) on transport-level failures (DNS, timeout, etc.).
func (c *Client) Health(ctx context.Context) (*Response, error) {
	return c.get(ctx, "/fabric/v1/health")
}

func (c *Client) get(ctx context.Context, path string) (*Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path, nil)
	if err != nil {
		return nil, fmt.Errorf("httpc: build request %s: %w", path, err)
	}
	return c.do(req, path)
}

// PostJSON marshals `body` as JSON and POSTs to `path`. Same envelope-
// parsing semantics as `Health`: returns (resp, nil) for any completed
// HTTP exchange, (nil, err) only for transport-level failures.
func (c *Client) PostJSON(ctx context.Context, path string, body interface{}) (*Response, error) {
	return c.postJSON(ctx, path, body, "")
}

// PostJSONAuth is PostJSON + an X-Fabric-Grant header carrying the daemon's
// capability. Used by /v1/capability/refresh (M3 piece 6) — the refresh
// request authenticates with the CURRENT capability before the Hub mints
// a fresh one.
func (c *Client) PostJSONAuth(ctx context.Context, path string, body interface{}, capability string) (*Response, error) {
	return c.postJSON(ctx, path, body, capability)
}

func (c *Client) postJSON(ctx context.Context, path string, body interface{}, capability string) (*Response, error) {
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("httpc: marshal %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("httpc: build request %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if capability != "" {
		req.Header.Set("X-Fabric-Grant", capability)
	}
	return c.do(req, path)
}

func (c *Client) do(req *http.Request, path string) (*Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpc: do %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpc: read body %s: %w", path, err)
	}

	out := &Response{Status: resp.StatusCode, ETag: resp.Header.Get("ETag"), ContentLength: resp.ContentLength}
	// Empty body is acceptable for some statuses; ignore decode errors so
	// callers can still inspect `Status`.
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out.Envelope)
	}
	return out, nil
}

// --- Hub bucket-proxy methods (M3 piece 5) ----------------------------------

// PutObject streams `body` to the Hub's bucket-proxy at
// PUT /v1/crate/object/{bucketID}/{remotePath}, authenticating with the
// daemon's capability (base64 macaroon) via the X-Fabric-Grant header.
// contentLength must be set so the upstream sees a known-length body
// (chunked transfer is possible but R2 prefers Content-Length).
// contentType may be "" — defaults to application/octet-stream.
//
// Returns the parsed response. On 2xx the ETag header is populated and
// the body is the Hub's envelope (currently empty for PUT proxy).
func (c *Client) PutObject(
	ctx context.Context,
	bucketID, remotePath string,
	body io.Reader,
	contentLength int64,
	contentType string,
	capability string,
) (*Response, error) {
	path := "/v1/crate/object/" + url.PathEscape(bucketID) + "/" + escapeObjectPath(remotePath)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.endpoint+path, body)
	if err != nil {
		return nil, fmt.Errorf("httpc: build PUT %s: %w", path, err)
	}
	req.ContentLength = contentLength
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Fabric-Grant", capability)
	return c.do(req, path)
}

// DeleteObject removes an object from the bucket via
// DELETE /v1/crate/object/{bucketID}/{remotePath}.
func (c *Client) DeleteObject(
	ctx context.Context,
	bucketID, remotePath string,
	capability string,
) (*Response, error) {
	path := "/v1/crate/object/" + url.PathEscape(bucketID) + "/" + escapeObjectPath(remotePath)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.endpoint+path, nil)
	if err != nil {
		return nil, fmt.Errorf("httpc: build DELETE %s: %w", path, err)
	}
	req.Header.Set("X-Fabric-Grant", capability)
	return c.do(req, path)
}

// HeadObject returns metadata (ETag, ContentLength) for an object via
// HEAD /v1/crate/object/{bucketID}/{remotePath}. Useful for pre-upload
// ETag comparison.
func (c *Client) HeadObject(
	ctx context.Context,
	bucketID, remotePath string,
	capability string,
) (*Response, error) {
	path := "/v1/crate/object/" + url.PathEscape(bucketID) + "/" + escapeObjectPath(remotePath)
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.endpoint+path, nil)
	if err != nil {
		return nil, fmt.Errorf("httpc: build HEAD %s: %w", path, err)
	}
	req.Header.Set("X-Fabric-Grant", capability)
	return c.do(req, path)
}

// GetObject reads an object's full body via
// GET /v1/crate/object/{bucketID}/{remotePath}.
// On 2xx, resp.Body contains the bytes and resp.ETag is the upstream ETag.
// Large objects are buffered fully — fine for v1.0 where the average crate
// file is small; streaming Get lands at M4 (folder UI) when large files
// become the common case.
func (c *Client) GetObject(
	ctx context.Context,
	bucketID, remotePath string,
	capability string,
) (*Response, error) {
	path := "/v1/crate/object/" + url.PathEscape(bucketID) + "/" + escapeObjectPath(remotePath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path, nil)
	if err != nil {
		return nil, fmt.Errorf("httpc: build GET %s: %w", path, err)
	}
	req.Header.Set("X-Fabric-Grant", capability)
	return c.doWithBody(req, path)
}

// ListObjects calls GET /v1/crate/list/{bucketID}?prefix=&continuation_token=
// and returns the raw S3 XML body for the caller to parse. The Hub proxies
// the upstream LIST response verbatim. (No envelope; this endpoint returns
// XML directly.)
func (c *Client) ListObjects(
	ctx context.Context,
	bucketID, prefix, continuationToken string,
	capability string,
) (*Response, error) {
	path := "/v1/crate/list/" + url.PathEscape(bucketID)
	q := url.Values{}
	if prefix != "" {
		q.Set("prefix", prefix)
	}
	if continuationToken != "" {
		q.Set("continuation_token", continuationToken)
	}
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+path, nil)
	if err != nil {
		return nil, fmt.Errorf("httpc: build LIST %s: %w", path, err)
	}
	req.Header.Set("X-Fabric-Grant", capability)
	return c.doWithBody(req, path)
}

// doWithBody is like `do` but preserves the raw body in resp.Body for
// callers that need it (GetObject, ListObjects). Still parses the envelope
// best-effort in case the Hub returned a JSON error.
func (c *Client) doWithBody(req *http.Request, path string) (*Response, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("httpc: do %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpc: read body %s: %w", path, err)
	}
	out := &Response{
		Status:        resp.StatusCode,
		ETag:          resp.Header.Get("ETag"),
		ContentLength: resp.ContentLength,
		Body:          body,
	}
	// Only attempt JSON parse when the response declares JSON OR when we
	// got an error status (envelope errors are JSON). Avoids spurious
	// "envelope" being filled from arbitrary XML/binary bodies.
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") || resp.StatusCode >= 400 {
		_ = json.Unmarshal(body, &out.Envelope)
	}
	return out, nil
}

// escapeObjectPath URL-encodes path segments individually so slashes in
// the remote path survive untouched.
func escapeObjectPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
