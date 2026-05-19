// SPDX-License-Identifier: AGPL-3.0-or-later
// Package cratejson handles the .crate/crate.json metadata blob the browser
// writes to the bucket on first paired-folder setup. The browser is the
// authority for this file; daemons read it.
//
// Schema per crate-browser-handoff-v1.0.md §"Persistence rules". v1.0:
//
//   {
//     "v": 1,
//     "version": "1.0",                            // crate format version
//     "salt": "<base64>",                          // 16 bytes — canonical KDF salt
//     "identity": { "pubkey": "<base64>", ... },   // public Identity info
//     "created_at": "<rfc3339>",
//     "created_by": "<browser-fingerprint>"
//   }
//
// Forward-compat: unknown fields are silently ignored on read; the daemon
// only requires `v` and `salt`. Future browser versions may add fields.
package cratejson

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/NakliTechie/crate-agent/internal/httpc"
)

// CratePath is the canonical key for the metadata blob. The slash is part of
// the key — most S3-API providers treat it as a path-style prefix in their
// own UIs, which is the intended visual grouping.
const CratePath = ".crate/crate.json"

// Doc mirrors the on-bucket JSON schema. Unknown fields are tolerated;
// `v` and `Salt` are required.
type Doc struct {
	V         int             `json:"v"`
	Version   string          `json:"version,omitempty"`
	Salt      string          `json:"salt"` // base64
	Identity  json.RawMessage `json:"identity,omitempty"`
	CreatedAt string          `json:"created_at,omitempty"`
	CreatedBy string          `json:"created_by,omitempty"`
}

// ErrAbsent is returned by Fetch when the bucket does not yet contain
// .crate/crate.json. The browser has not yet completed first-time setup
// for this folder. Callers should treat this as a no-op condition.
var ErrAbsent = errors.New("cratejson: .crate/crate.json not present in bucket")

// ErrUnsupportedVersion is returned when the doc's `v` is not 1.
var ErrUnsupportedVersion = errors.New("cratejson: unsupported version (expected v=1)")

// Fetch GETs .crate/crate.json from the bucket via the Hub bucket-proxy.
// A 404 from the upstream becomes ErrAbsent — the caller decides what to
// do (typically: no-op, the browser hasn't written this folder yet).
//
// Any other non-2xx is returned as a regular error.
func Fetch(ctx context.Context, hub *httpc.Client, bucketID, capability string) (*Doc, error) {
	resp, err := hub.GetObject(ctx, bucketID, CratePath, capability)
	if err != nil {
		return nil, fmt.Errorf("cratejson: GET: %w", err)
	}
	if resp.Status == http.StatusNotFound {
		return nil, ErrAbsent
	}
	if resp.Status < 200 || resp.Status >= 300 {
		if resp.Envelope.Error != nil {
			return nil, fmt.Errorf("cratejson: HTTP %d %s: %s",
				resp.Status, resp.Envelope.Error.Code, resp.Envelope.Error.Message)
		}
		return nil, fmt.Errorf("cratejson: HTTP %d", resp.Status)
	}
	if len(resp.Body) == 0 {
		return nil, errors.New("cratejson: empty body")
	}
	var doc Doc
	if err := json.Unmarshal(resp.Body, &doc); err != nil {
		return nil, fmt.Errorf("cratejson: parse: %w", err)
	}
	if doc.V != 1 {
		return nil, fmt.Errorf("%w: got v=%d", ErrUnsupportedVersion, doc.V)
	}
	if doc.Salt == "" {
		return nil, errors.New("cratejson: salt is empty")
	}
	return &doc, nil
}

// SaltBytes returns the decoded canonical salt. Returns an error if the
// stored salt is not valid base64 OR not the expected length (16 bytes
// per crate-browser-handoff §"Encryption details").
func (d *Doc) SaltBytes() ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(d.Salt)
	if err != nil {
		// Try URL-safe encoding too — the browser might emit either.
		if b2, err2 := base64.RawURLEncoding.DecodeString(d.Salt); err2 == nil {
			b = b2
		} else {
			return nil, fmt.Errorf("cratejson: salt b64: %w", err)
		}
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("cratejson: salt length %d, want 16", len(b))
	}
	return b, nil
}
