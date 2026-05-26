// SPDX-License-Identifier: AGPL-3.0-or-later
package cratejson

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"log/slog"

	sdkcrypto "github.com/NakliTechie/private-mesh/fabric-sdk-go/crypto"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/kdf"
	"github.com/NakliTechie/crate-agent/internal/payload"
)

// ReconcileInput bundles what the daemon's boot path needs to attempt salt
// reconciliation. The daemon already holds the in-memory passphrase and the
// just-decrypted capability bytes; the reconciler may need to re-derive the
// master key and re-encrypt the capability with the canonical salt.
type ReconcileInput struct {
	// CfgPath is the absolute path to crate-agent.toml.
	CfgPath string

	// Cfg is the in-memory config. Updated in-place on reconciliation
	// success.
	Cfg *config.Config

	// Passphrase is the user's folder passphrase. Held only for the lifetime
	// of the reconcile call — caller may zero it after.
	Passphrase string

	// CurrentMasterKey is the master key derived with the LOCAL salt at
	// daemon start. Returned key from Reconcile() may differ if a canonical
	// salt was found in the bucket. Caller zeros the input either way.
	CurrentMasterKey []byte

	// CapabilityBytes is the plaintext capability the daemon currently
	// holds. On reconciliation, the reconciler re-encrypts these bytes
	// under the new master key.
	CapabilityBytes []byte

	// Hub is the bucket-proxy client.
	Hub *httpc.Client

	// Capability (base64) is the daemon's auth header for the Fetch call.
	Capability string

	// Logger for status reports. nil = slog.Default().
	Logger *slog.Logger
}

// ReconcileResult is what Reconcile returns. Action describes what happened
// so the caller can log + (if any key changed) replace its in-memory copies.
type ReconcileResult struct {
	Action Action

	// NewMasterKey is the new "capability KEK" — the key used to seal the
	// daemon's local capability blob (so the refresh runner can re-encrypt
	// on rotation). For v1.0 vaults this also IS the payload master key
	// (NewPayloadMasterKey is nil; caller uses NewMasterKey for everything).
	// For v1.1 vaults it's the passphrase-KEK (= PBKDF2(passphrase,
	// passphrase_wrap.salt)) — distinct from NewPayloadMasterKey below.
	//
	// Non-nil only when Action == ActionReconciled.
	NewMasterKey []byte

	// NewPayloadMasterKey is the key the syncer + puller use for manifest
	// + file crypto (the "content key" in v1.1 terms). For v1.0 vaults this
	// is nil — the caller falls back to NewMasterKey for payload work too.
	// For v1.1 vaults it is the unwrapped content key from passphrase_wrap.ct.
	//
	// Non-nil only when Action == ActionReconciled AND the doc is v1.1.
	NewPayloadMasterKey []byte
}

// Action enumerates reconciliation outcomes.
type Action int

const (
	// ActionAbsent — bucket has no .crate/crate.json yet (browser hasn't
	// completed first-time setup). No daemon state changed.
	ActionAbsent Action = iota + 1
	// ActionAlreadyCanonical — the local salt already matches the bucket's
	// canonical salt (v1.0 only). No daemon state changed.
	ActionAlreadyCanonical
	// ActionReconciled — keys were swapped in:
	//   v1.0: local salt differed; master key was re-derived, capability
	//         re-encrypted, config rewritten.
	//   v1.1: content key was unwrapped from passphrase_wrap (always —
	//         the unwrap is needed regardless of salt match). Capability
	//         re-encrypted iff local salt differed from passphrase_wrap.salt.
	ActionReconciled
	// ActionFailed — Fetch or re-encrypt errored. Daemon should keep
	// running with the local salt; the next start will retry.
	ActionFailed
)

// String returns a short label for logging.
func (a Action) String() string {
	switch a {
	case ActionAbsent:
		return "absent"
	case ActionAlreadyCanonical:
		return "already-canonical"
	case ActionReconciled:
		return "reconciled"
	case ActionFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// Reconcile attempts to fetch .crate/crate.json and align the daemon's keys
// with the browser-canonical state. Forward-compatible: when the browser
// hasn't shipped the file yet, Fetch returns ErrAbsent and the reconciler
// returns ActionAbsent — the daemon proceeds with its local salt.
//
// On ActionReconciled: in.Cfg is mutated in-place AND (if disk state
// changed) written to disk (atomic temp+rename) before returning. Caller
// MUST replace its in-memory master key with result.NewMasterKey and zero
// the previous one. For v1.1 reconciliations, caller MUST ALSO use
// result.NewPayloadMasterKey for payload-side crypto (syncer + puller).
//
// On ActionFailed: in.Cfg is NOT mutated; the daemon proceeds with the
// local salt. The error is logged but not returned — reconciliation
// failure is non-fatal at boot.
func Reconcile(ctx context.Context, in ReconcileInput) ReconcileResult {
	logger := in.Logger
	if logger == nil {
		logger = slog.Default()
	}
	doc, err := Fetch(ctx, in.Hub, in.Cfg.Crate.BucketID, in.Capability)
	if err != nil {
		if errors.Is(err, ErrAbsent) {
			logger.Info("salt reconciliation: .crate/crate.json absent — using local salt",
				"bucket", in.Cfg.Crate.BucketID)
			return ReconcileResult{Action: ActionAbsent}
		}
		logger.Warn("salt reconciliation: fetch failed; proceeding with local salt",
			"err", err)
		return ReconcileResult{Action: ActionFailed}
	}

	if doc.IsV11() {
		return reconcileV11(in, doc, logger)
	}
	return reconcileV10(in, doc, logger)
}

// reconcileV10 handles the legacy schema: master key = PBKDF2(passphrase,
// canonical salt). If local salt already matches, returns ActionAlreadyCanonical
// (no key swap). Otherwise re-derives, re-encrypts the capability, persists
// config, and returns ActionReconciled with NewMasterKey set.
func reconcileV10(in ReconcileInput, doc *Doc, logger *slog.Logger) ReconcileResult {
	canonicalSalt, err := doc.SaltBytes()
	if err != nil {
		logger.Warn("salt reconciliation: parse canonical salt failed; proceeding with local salt",
			"err", err)
		return ReconcileResult{Action: ActionFailed}
	}

	localSalt, err := base64.StdEncoding.DecodeString(in.Cfg.Crate.Salt)
	if err != nil {
		logger.Warn("salt reconciliation: parse local salt failed",
			"err", err)
		return ReconcileResult{Action: ActionFailed}
	}
	if bytes.Equal(localSalt, canonicalSalt) {
		logger.Info("salt reconciliation: local salt is canonical; no-op")
		return ReconcileResult{Action: ActionAlreadyCanonical}
	}

	// Re-derive master key with the canonical salt. The capability plaintext
	// (in.CapabilityBytes) is unchanged — it's the macaroon bytes the Hub
	// minted at /v1/pairing/redeem time; we just re-wrap it under a new key.
	newMasterKey := kdf.DeriveMasterKey(in.Passphrase, canonicalSalt)
	nonce, err := sdkcrypto.RandomNonce()
	if err != nil {
		zero(newMasterKey)
		logger.Warn("salt reconciliation: nonce failed", "err", err)
		return ReconcileResult{Action: ActionFailed}
	}
	sealed, err := sdkcrypto.Seal(newMasterKey, nonce, in.CapabilityBytes, nil)
	if err != nil {
		zero(newMasterKey)
		logger.Warn("salt reconciliation: re-encrypt failed", "err", err)
		return ReconcileResult{Action: ActionFailed}
	}

	// Persist: update Cfg in-place + atomic-rewrite the file.
	in.Cfg.Crate.Salt = base64.StdEncoding.EncodeToString(canonicalSalt)
	in.Cfg.Crate.CapabilityNonce = base64.StdEncoding.EncodeToString(nonce)
	in.Cfg.Crate.PairingToken = base64.StdEncoding.EncodeToString(sealed)
	if err := config.Write(in.CfgPath, in.Cfg); err != nil {
		zero(newMasterKey)
		logger.Warn("salt reconciliation: rewrite config failed; in-memory state advanced but disk did not",
			"err", err)
		return ReconcileResult{Action: ActionFailed}
	}
	logger.Info("salt reconciliation: re-derived master key + re-encrypted capability")
	return ReconcileResult{
		Action:       ActionReconciled,
		NewMasterKey: newMasterKey,
	}
}

// reconcileV11 handles the v1.1 schema. ALWAYS returns ActionReconciled on
// success (since the content key must be unwrapped from passphrase_wrap.ct
// every boot — there's no equivalent of "already canonical" because the
// local capability KEK can't equal the payload master key in v1.1).
//
// The capability blob is re-encrypted iff the local salt differs from
// passphrase_wrap.salt; the content key is unwrapped unconditionally.
func reconcileV11(in ReconcileInput, doc *Doc, logger *slog.Logger) ReconcileResult {
	pw := doc.PassphraseWrap
	canonicalSalt, err := pw.SaltBytes()
	if err != nil {
		logger.Warn("v1.1 reconciliation: parse passphrase_wrap.salt failed", "err", err)
		return ReconcileResult{Action: ActionFailed}
	}
	pwIV, err := pw.IVBytes()
	if err != nil {
		logger.Warn("v1.1 reconciliation: parse passphrase_wrap.iv failed", "err", err)
		return ReconcileResult{Action: ActionFailed}
	}
	pwCT, err := pw.CTBytes()
	if err != nil {
		logger.Warn("v1.1 reconciliation: parse passphrase_wrap.ct failed", "err", err)
		return ReconcileResult{Action: ActionFailed}
	}

	// Derive passphrase-KEK = capability KEK for v1.1. Use the iteration
	// count stored in the wrap (so future bumps to higher iter counts are
	// honoured without a code change).
	capabilityKEK := kdf.DerivePassphraseKEK(in.Passphrase, canonicalSalt, pw.IterOrDefault())

	// Unwrap the content key (= payload master key downstream).
	contentKey, err := payload.UnwrapKey(capabilityKEK, pwIV, pwCT)
	if err != nil {
		zero(capabilityKEK)
		logger.Warn("v1.1 reconciliation: content-key unwrap failed (wrong passphrase or tampered crate.json)",
			"err", err)
		return ReconcileResult{Action: ActionFailed}
	}

	// Salt-rotation: if local salt differs from passphrase_wrap.salt, the
	// daemon's local capability blob is sealed under the OLD KEK. Re-seal
	// under the new KEK + persist config.
	localSalt, err := base64.StdEncoding.DecodeString(in.Cfg.Crate.Salt)
	if err != nil {
		zero(capabilityKEK)
		zero(contentKey)
		logger.Warn("v1.1 reconciliation: parse local salt failed", "err", err)
		return ReconcileResult{Action: ActionFailed}
	}
	if !bytes.Equal(localSalt, canonicalSalt) {
		nonce, err := sdkcrypto.RandomNonce()
		if err != nil {
			zero(capabilityKEK)
			zero(contentKey)
			logger.Warn("v1.1 reconciliation: nonce failed", "err", err)
			return ReconcileResult{Action: ActionFailed}
		}
		sealed, err := sdkcrypto.Seal(capabilityKEK, nonce, in.CapabilityBytes, nil)
		if err != nil {
			zero(capabilityKEK)
			zero(contentKey)
			logger.Warn("v1.1 reconciliation: capability re-encrypt failed", "err", err)
			return ReconcileResult{Action: ActionFailed}
		}
		in.Cfg.Crate.Salt = base64.StdEncoding.EncodeToString(canonicalSalt)
		in.Cfg.Crate.CapabilityNonce = base64.StdEncoding.EncodeToString(nonce)
		in.Cfg.Crate.PairingToken = base64.StdEncoding.EncodeToString(sealed)
		if err := config.Write(in.CfgPath, in.Cfg); err != nil {
			zero(capabilityKEK)
			zero(contentKey)
			logger.Warn("v1.1 reconciliation: rewrite config failed", "err", err)
			return ReconcileResult{Action: ActionFailed}
		}
		logger.Info("v1.1 reconciliation: salt rotated, capability re-encrypted, content key unwrapped")
	} else {
		logger.Info("v1.1 reconciliation: salt already canonical; content key unwrapped")
	}

	return ReconcileResult{
		Action:              ActionReconciled,
		NewMasterKey:        capabilityKEK,
		NewPayloadMasterKey: contentKey,
	}
}

// zero wipes a byte slice.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// CanonicalSaltEqual is a small helper to compare base64-encoded salt
// strings byte-for-byte. Returns false on any decode error.
func CanonicalSaltEqual(a, b string) bool {
	da, e1 := base64.StdEncoding.DecodeString(a)
	db, e2 := base64.StdEncoding.DecodeString(b)
	if e1 != nil || e2 != nil {
		return false
	}
	return bytes.Equal(da, db)
}
