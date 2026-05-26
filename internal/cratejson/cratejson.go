// SPDX-License-Identifier: AGPL-3.0-or-later
// Package cratejson handles the .crate/crate.json metadata blob the browser
// writes to the bucket on first paired-folder setup. The browser is the
// authority for this file; daemons read it.
//
// Two schemas exist (browser-side: lib/cratejson.js):
//
//   v1.0 (legacy):
//     {
//       "v": 1,
//       "version": "1.0",
//       "salt": "<base64 16 bytes>",        // master key = PBKDF2(passphrase, salt)
//       "identity": { ... },
//       "created_at": "<rfc3339>",
//       "created_by": "<fingerprint>"
//     }
//
//   v1.1 (current — adds recovery credential):
//     {
//       "v": 1,
//       "version": "1.1",
//       "passphrase_wrap": {                 // content key wrapped under passphrase-KEK
//         "kdf":  "PBKDF2-SHA256",
//         "iter": 600000,
//         "salt": "<base64 16 bytes>",
//         "iv":   "<base64 12 bytes>",
//         "ct":   "<base64 48 bytes — 32-byte key + 16-byte GCM tag>"
//       },
//       "recovery_wrap": {                   // OPTIONAL — present if user enabled recovery
//         "kdf":  "PBKDF2-SHA256",
//         "iter": 600000,
//         "salt": "<base64 16 bytes>",       // independent from passphrase_wrap.salt
//         "iv":   "<base64 12 bytes>",
//         "ct":   "<base64 48 bytes>"
//       },
//       ...identity / created_at / created_by as above
//     }
//
// `v: 1` is the WIRE FORMAT version (JSON-level). Adding optional fields keeps
// it at 1. The string `version` is the SEMANTIC schema version; presence of
// `passphrase_wrap` is the authoritative v1.1 signal (older daemons that don't
// know v1.1 will see no `salt` and reject — fail loud rather than silently
// derive the wrong key).
//
// Forward-compat: unknown fields are silently ignored on read; the daemon
// only requires (v=1) AND (salt OR passphrase_wrap).
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

// Schema constants for v1.1 wrap slots.
const (
	wrapSaltLen      = 16        // PBKDF2 salt
	wrapIVLen        = 12        // AES-GCM nonce
	wrapCTLen        = 32 + 16   // 32-byte wrapped content key + 16-byte GCM tag
	wrapMinIter      = 100_000   // reject obviously-weak iter counts
	wrapKDFAlgorithm = "PBKDF2-SHA256"
)

// Wrap is a single key-encryption-key slot in a v1.1 crate.json. The same
// content key is wrapped under one or more KEKs (passphrase, recovery,
// future hardware-key), each independently able to unwrap it.
type Wrap struct {
	KDF  string `json:"kdf"`
	Iter int    `json:"iter"`
	Salt string `json:"salt"` // base64 std OR url-safe; 16 bytes when decoded
	IV   string `json:"iv"`   // base64; 12 bytes when decoded
	CT   string `json:"ct"`   // base64; 48 bytes when decoded (key + GCM tag)
}

// Doc mirrors the on-bucket JSON schema for BOTH v1.0 and v1.1. Unknown
// fields are tolerated. For v1.0: Salt is required, PassphraseWrap is nil.
// For v1.1: PassphraseWrap is required, Salt is empty/absent, RecoveryWrap
// may be nil.
type Doc struct {
	V              int             `json:"v"`
	Version        string          `json:"version,omitempty"`
	Salt           string          `json:"salt,omitempty"`            // v1.0 only
	PassphraseWrap *Wrap           `json:"passphrase_wrap,omitempty"` // v1.1
	RecoveryWrap   *Wrap           `json:"recovery_wrap,omitempty"`   // v1.1, optional
	Identity       json.RawMessage `json:"identity,omitempty"`
	CreatedAt      string          `json:"created_at,omitempty"`
	CreatedBy      string          `json:"created_by,omitempty"`
}

// IsV11 returns true if the doc encodes the v1.1 schema (presence of
// PassphraseWrap is authoritative).
func (d *Doc) IsV11() bool { return d != nil && d.PassphraseWrap != nil }

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
// Any other non-2xx is returned as a regular error. v1.1 wraps are
// validated structurally on parse (lengths, kdf algorithm, iter floor).
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

	if doc.PassphraseWrap != nil {
		// v1.1 schema
		if doc.Version != "" && doc.Version != "1.1" {
			return nil, fmt.Errorf("cratejson: passphrase_wrap present but version=%q (expected 1.1)", doc.Version)
		}
		if err := doc.PassphraseWrap.Validate(); err != nil {
			return nil, fmt.Errorf("cratejson: passphrase_wrap: %w", err)
		}
		if doc.RecoveryWrap != nil {
			if err := doc.RecoveryWrap.Validate(); err != nil {
				return nil, fmt.Errorf("cratejson: recovery_wrap: %w", err)
			}
		}
		return &doc, nil
	}

	// v1.0 schema — top-level salt required
	if doc.Salt == "" {
		return nil, errors.New("cratejson: salt is empty (and no passphrase_wrap — schema malformed)")
	}
	return &doc, nil
}

// SaltBytes returns the decoded canonical v1.0 salt. Returns an error if
// the doc is v1.1 (callers should use PassphraseWrap.SaltBytes() in that
// case) OR if the stored salt is not valid base64 / not 16 bytes.
func (d *Doc) SaltBytes() ([]byte, error) {
	if d.IsV11() {
		return nil, errors.New("cratejson: SaltBytes called on a v1.1 doc; use PassphraseWrap.SaltBytes()")
	}
	return decodeBase64Bytes(d.Salt, "salt", wrapSaltLen)
}

// Validate checks that a Wrap is structurally well-formed. Returns the
// first error encountered; no error means SaltBytes/IVBytes/CTBytes will
// succeed.
func (w *Wrap) Validate() error {
	if w == nil {
		return errors.New("wrap is nil")
	}
	if w.KDF != "" && w.KDF != wrapKDFAlgorithm {
		return fmt.Errorf("kdf %q not supported (expected %s)", w.KDF, wrapKDFAlgorithm)
	}
	if w.Iter < wrapMinIter {
		return fmt.Errorf("iter %d too low (minimum %d)", w.Iter, wrapMinIter)
	}
	if _, err := w.SaltBytes(); err != nil {
		return err
	}
	if _, err := w.IVBytes(); err != nil {
		return err
	}
	if _, err := w.CTBytes(); err != nil {
		return err
	}
	return nil
}

// SaltBytes returns the decoded wrap salt (must be 16 bytes).
func (w *Wrap) SaltBytes() ([]byte, error) {
	return decodeBase64Bytes(w.Salt, "salt", wrapSaltLen)
}

// IVBytes returns the decoded wrap IV (must be 12 bytes).
func (w *Wrap) IVBytes() ([]byte, error) {
	return decodeBase64Bytes(w.IV, "iv", wrapIVLen)
}

// CTBytes returns the decoded wrap ciphertext (must be 48 bytes —
// 32-byte wrapped content key + 16-byte AES-GCM auth tag).
func (w *Wrap) CTBytes() ([]byte, error) {
	return decodeBase64Bytes(w.CT, "ct", wrapCTLen)
}

// IterOrDefault returns the wrap's PBKDF2 iteration count, falling back to
// the v1.1 default (600k) if unset. Validate() rejects too-low values, so
// any value that survives Validate() is safe to use directly.
func (w *Wrap) IterOrDefault() int {
	if w.Iter > 0 {
		return w.Iter
	}
	return 600_000
}

// decodeBase64Bytes is the tolerant base64 decoder used by both v1.0 and
// v1.1 paths: tries StdEncoding then RawURLEncoding (browser may emit
// either; SubtleCrypto + Web encoding choices vary). Validates the
// expected length.
func decodeBase64Bytes(s, name string, wantLen int) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("%s is empty", name)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		if b2, err2 := base64.RawURLEncoding.DecodeString(s); err2 == nil {
			b = b2
		} else {
			return nil, fmt.Errorf("%s b64: %w", name, err)
		}
	}
	if len(b) != wantLen {
		return nil, fmt.Errorf("%s length %d, want %d", name, len(b), wantLen)
	}
	return b, nil
}
