// SPDX-License-Identifier: AGPL-3.0-or-later
// Token decode + validation for CRATE-PAIR tokens. Each failure maps to
// one of the spec's error codes (crate-pairing-protocol-v1.0.md §"Error
// codes"); callers print the user-facing recovery message on stderr.

package pairing

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// TokenPrefix is the literal string every well-formed token starts with.
const TokenPrefix = "CRATE-PAIR-"

// TokenType is the required `type` field value per spec §"Wire format".
const TokenType = "crate.pairing.token"

// CurrentVersion is the only `v` value v1.0 accepts; higher values are
// rejected with E_PROTOCOL_VERSION.
const CurrentVersion = 1

// Token mirrors the JSON payload encoded inside a CRATE-PAIR-{base64(JSON)}
// string per crate-pairing-protocol-v1.0.md §"Wire format". Fields use
// JSON tags so callers can re-marshal verbatim if needed.
type Token struct {
	V                 int    `json:"v"`
	Type              string `json:"type"`
	Secret            string `json:"secret"`
	TransportEndpoint string `json:"transport_endpoint"`
	TransportType     string `json:"transport_type"`
	BucketID          string `json:"bucket_id"`
	IdentityPubkey    string `json:"identity_pubkey"`
	IssuedAt          int64  `json:"issued_at"`
	ExpiresAt         int64  `json:"expires_at"`
}

// Code is the protocol error-code returned by Decode and Validate. Callers
// switch on it to surface the right user-facing recovery message.
type Code string

const (
	CodeNone             Code = ""
	CodeTokenFormat      Code = "E_TOKEN_FORMAT"
	CodeTokenExpired     Code = "E_TOKEN_EXPIRED"
	CodeProtocolVersion  Code = "E_PROTOCOL_VERSION"
	CodeTokenNotFound    Code = "E_TOKEN_NOT_FOUND"
	CodeTokenRedeemed    Code = "E_TOKEN_ALREADY_REDEEMED"
	CodeTokenCancelled   Code = "E_TOKEN_CANCELLED"
	CodeTransportFailure Code = "E_TRANSPORT_UNREACHABLE"
)

// Err is the typed error returned by Decode / Validate / Phase3. The
// Code field maps to a row in the protocol's error table; Message is
// the user-facing recovery string. Errors with no Code wrap whatever
// non-protocol error surfaced (caller decides how to surface).
type Err struct {
	Code    Code
	Message string
	Err     error
}

func (e *Err) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	if e.Code == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Err) Unwrap() error { return e.Err }

// IsCode reports whether `err` is an *Err with the given code.
func IsCode(err error, code Code) bool {
	var e *Err
	if !errors.As(err, &e) {
		return false
	}
	return e.Code == code
}

// Decode parses a CRATE-PAIR-{base64(JSON)} token string. Returns a
// populated Token on success. On failure returns *Err with the
// appropriate Code (always E_TOKEN_FORMAT for decode-time failures
// except wrong-version, which is E_PROTOCOL_VERSION). Decode does not
// check expiry — call Validate for that.
func Decode(s string) (*Token, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, TokenPrefix) {
		return nil, &Err{
			Code:    CodeTokenFormat,
			Message: "token does not begin with the literal \"CRATE-PAIR-\" prefix",
		}
	}
	encoded := s[len(TokenPrefix):]

	// Try base64url (RFC 4648 URL-safe alphabet) first, then standard
	// base64 as a fallback — some token generators round-trip through
	// libraries that emit padded standard base64 instead.
	raw, decErr := base64.RawURLEncoding.DecodeString(encoded)
	if decErr != nil {
		raw, decErr = base64.URLEncoding.DecodeString(encoded)
	}
	if decErr != nil {
		raw, decErr = base64.StdEncoding.DecodeString(encoded)
	}
	if decErr != nil {
		return nil, &Err{
			Code:    CodeTokenFormat,
			Message: "token base64 body could not be decoded",
			Err:     decErr,
		}
	}

	var t Token
	if err := json.Unmarshal(raw, &t); err != nil {
		return nil, &Err{
			Code:    CodeTokenFormat,
			Message: "token payload is not valid JSON",
			Err:     err,
		}
	}

	// v / type checks happen here (not in Validate) because they're
	// shape-level errors — the payload is structurally wrong, not just
	// out-of-policy. The order matters: a wrong-version token surfaces
	// E_PROTOCOL_VERSION, NOT E_TOKEN_FORMAT, per the spec's error table.
	if t.V == 0 {
		return nil, &Err{Code: CodeTokenFormat, Message: "token payload is missing required field \"v\""}
	}
	if t.V != CurrentVersion {
		return nil, &Err{
			Code:    CodeProtocolVersion,
			Message: fmt.Sprintf("token has v=%d; this crate-agent supports v=%d only — update the agent", t.V, CurrentVersion),
		}
	}
	if t.Type != TokenType {
		return nil, &Err{
			Code:    CodeTokenFormat,
			Message: fmt.Sprintf("token type field is %q, expected %q", t.Type, TokenType),
		}
	}
	if t.Secret == "" {
		return nil, &Err{Code: CodeTokenFormat, Message: "token payload is missing required field \"secret\""}
	}
	if t.TransportEndpoint == "" {
		return nil, &Err{Code: CodeTokenFormat, Message: "token payload is missing required field \"transport_endpoint\""}
	}
	if t.TransportType == "" {
		return nil, &Err{Code: CodeTokenFormat, Message: "token payload is missing required field \"transport_type\""}
	}
	if t.BucketID == "" {
		return nil, &Err{Code: CodeTokenFormat, Message: "token payload is missing required field \"bucket_id\""}
	}
	if t.IdentityPubkey == "" {
		return nil, &Err{Code: CodeTokenFormat, Message: "token payload is missing required field \"identity_pubkey\""}
	}
	if t.IssuedAt == 0 || t.ExpiresAt == 0 {
		return nil, &Err{Code: CodeTokenFormat, Message: "token payload is missing issued_at or expires_at"}
	}
	if t.ExpiresAt <= t.IssuedAt {
		return nil, &Err{Code: CodeTokenFormat, Message: "token has expires_at <= issued_at"}
	}
	return &t, nil
}

// Validate checks runtime invariants on a decoded Token — currently just
// expiry. Returns nil if the token is still redeemable; otherwise *Err
// with CodeTokenExpired.
func Validate(t *Token, now time.Time) error {
	if t == nil {
		return &Err{Code: CodeTokenFormat, Message: "token is nil"}
	}
	exp := time.Unix(t.ExpiresAt, 0)
	if exp.Before(now) {
		dur := now.Sub(exp).Round(time.Second)
		return &Err{
			Code:    CodeTokenExpired,
			Message: fmt.Sprintf("token expired %s ago — generate a new one from the browser", dur),
		}
	}
	return nil
}

// RecoveryMessage returns the user-facing recovery string for a given
// Code, suitable for printing on stderr per the spec's directive:
// "Daemons MUST print the user-facing recovery message on stderr, not
// just the code." If the error embeds its own message, that wins.
func RecoveryMessage(err error) string {
	var e *Err
	if !errors.As(err, &e) {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	switch e.Code {
	case CodeTokenFormat:
		return "Token looks malformed. Make sure you copied the full string including the \"CRATE-PAIR-\" prefix."
	case CodeTokenExpired:
		return "Token expired. Generate a new one from your browser."
	case CodeTokenNotFound:
		return "Token isn't recognised. Was it generated against a different transport?"
	case CodeTokenRedeemed:
		return "Token already used. Tokens are single-use. Generate a new one."
	case CodeTokenCancelled:
		return "Token was cancelled by the issuer. Generate a new one."
	case CodeProtocolVersion:
		return "Pairing protocol version mismatch. Update crate-agent."
	case CodeTransportFailure:
		return "Couldn't reach the transport. Check the URL and your network connection."
	}
	return ""
}
