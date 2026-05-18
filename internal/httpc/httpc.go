// SPDX-License-Identifier: AGPL-3.0-or-later
// Package httpc — minimal HTTP client for talking to a fabric transport
// (nakli-hub or nakli-cf-worker). Per the M1 wire-protocol audit
// (docs/wire-protocol-audit.md §3), fabric-sdk-go has no top-level
// Transport/Client type; the daemon brings its own thin wrapper.
//
// M1 scope: `GET /fabric/v1/health` only (unauthenticated). M2 adds
// `POST /v1/pairing/redeem` (unauthenticated POST JSON). M3+ will add
// macaroon-bearing methods via `X-Fabric-Grant`.

package httpc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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
type Response struct {
	Status   int
	Envelope Envelope
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
	buf, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("httpc: marshal %s: %w", path, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+path, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("httpc: build request %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/json")
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

	out := &Response{Status: resp.StatusCode}
	// Empty body is acceptable for some statuses; ignore decode errors so
	// callers can still inspect `Status`.
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out.Envelope)
	}
	return out, nil
}
