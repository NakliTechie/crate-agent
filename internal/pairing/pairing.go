// SPDX-License-Identifier: AGPL-3.0-or-later
// Phase 3 orchestration: POST /v1/pairing/redeem and translate the
// Hub's response into either a populated RedeemResult or a typed *Err
// carrying the right protocol code.
//
// See crate-pairing-protocol-v1.0.md §"Phase 3: Daemon redeems the token"
// + §"Error codes". Wire-protocol audit covered the daemon-side gap at
// crate-agent/docs/wire-protocol-audit.md §3 (daemon brings its own
// thin HTTP client; the SDK is primitives-only at fabric M1).

package pairing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/NakliTechie/crate-agent/internal/httpc"
)

// Fingerprint mirrors the daemon_fingerprint sub-object spec lines 150–155.
type Fingerprint struct {
	Platform     string `json:"platform"`
	Arch         string `json:"arch"`
	Hostname     string `json:"hostname"`
	AgentVersion string `json:"agent_version"`
}

// RedeemResult is the parsed success response from /v1/pairing/redeem.
type RedeemResult struct {
	Capability      []byte // decoded base64
	BucketReference string
	TransportPubkey []byte // decoded base64
	ExpiresAtUnix   int64
}

// Phase3 executes the daemon's Phase 3 obligations: build the JSON body,
// POST to the transport's /v1/pairing/redeem, decode the response.
//
// Maps Hub error codes back onto the protocol's E_TOKEN_* codes so the
// CLI can print the right recovery message. Network failures surface
// as E_TRANSPORT_UNREACHABLE.
func Phase3(
	ctx context.Context,
	client *httpc.Client,
	secret string,
	daemonPubkey string,
	fp Fingerprint,
) (*RedeemResult, error) {
	body := map[string]any{
		"v":                  CurrentVersion,
		"secret":             secret,
		"daemon_pubkey":      daemonPubkey,
		"daemon_fingerprint": fp,
	}
	resp, err := client.PostJSON(ctx, "/v1/pairing/redeem", body)
	if err != nil {
		return nil, &Err{
			Code:    CodeTransportFailure,
			Message: "could not POST /v1/pairing/redeem",
			Err:     err,
		}
	}
	if resp.Status >= 200 && resp.Status < 300 && resp.Envelope.OK {
		out, err := parseRedeemSuccess(resp.Envelope.Data)
		if err != nil {
			return nil, &Err{
				Code:    CodeTokenFormat,
				Message: "redeem response missing expected fields",
				Err:     err,
			}
		}
		return out, nil
	}
	return nil, mapRedeemError(resp)
}

// parseRedeemSuccess decodes the envelope's `data` block into RedeemResult.
func parseRedeemSuccess(data []byte) (*RedeemResult, error) {
	// data is the raw JSON of the success envelope's data field.
	// Shape mirrors handlers_crate_pairing.go's cratePairingRedeemResp.
	var wire struct {
		V               int    `json:"v"`
		Capability      string `json:"capability"`        // base64 std
		BucketReference string `json:"bucket_reference"`
		TransportPubkey string `json:"transport_pubkey"`  // base64 std
		ExpiresAt       int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, fmt.Errorf("unmarshal data: %w", err)
	}
	if wire.V != CurrentVersion {
		return nil, fmt.Errorf("response v=%d, expected %d", wire.V, CurrentVersion)
	}
	if wire.Capability == "" || wire.BucketReference == "" || wire.TransportPubkey == "" {
		return nil, fmt.Errorf("response is missing capability, bucket_reference, or transport_pubkey")
	}
	cap, err := base64.StdEncoding.DecodeString(wire.Capability)
	if err != nil {
		return nil, fmt.Errorf("capability base64 decode: %w", err)
	}
	pk, err := base64.StdEncoding.DecodeString(wire.TransportPubkey)
	if err != nil {
		return nil, fmt.Errorf("transport_pubkey base64 decode: %w", err)
	}
	return &RedeemResult{
		Capability:      cap,
		BucketReference: wire.BucketReference,
		TransportPubkey: pk,
		ExpiresAtUnix:   wire.ExpiresAt,
	}, nil
}

// mapRedeemError translates a non-success response into a typed *Err.
func mapRedeemError(resp *httpc.Response) *Err {
	if resp == nil {
		return &Err{Code: CodeTransportFailure, Message: "no response"}
	}
	code := ""
	msg := fmt.Sprintf("HTTP %d", resp.Status)
	if resp.Envelope.Error != nil {
		code = resp.Envelope.Error.Code
		if resp.Envelope.Error.Message != "" {
			msg = resp.Envelope.Error.Message
		}
	}
	// Map Hub envelope codes → protocol codes.
	switch {
	case resp.Status == http.StatusNotFound && code == "token_cancelled":
		return &Err{Code: CodeTokenCancelled, Message: msg}
	case resp.Status == http.StatusNotFound:
		return &Err{Code: CodeTokenNotFound, Message: msg}
	case resp.Status == http.StatusConflict && (code == "token_already_redeemed" || strings.HasPrefix(code, "token_already")):
		return &Err{Code: CodeTokenRedeemed, Message: msg}
	case resp.Status == http.StatusGone:
		return &Err{Code: CodeTokenExpired, Message: msg}
	case resp.Status == http.StatusUpgradeRequired:
		return &Err{Code: CodeProtocolVersion, Message: msg}
	}
	// Catch-all: surface whatever the server said.
	return &Err{Code: CodeTransportFailure, Message: msg}
}
