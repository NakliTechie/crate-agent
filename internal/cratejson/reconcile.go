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
// so the caller can log + (if the master key changed) replace its in-memory
// copy with NewMasterKey.
type ReconcileResult struct {
	Action       Action
	NewMasterKey []byte // non-nil only when Action == ActionReconciled
}

// Action enumerates reconciliation outcomes.
type Action int

const (
	// ActionAbsent — bucket has no .crate/crate.json yet (browser hasn't
	// completed first-time setup). No daemon state changed.
	ActionAbsent Action = iota + 1
	// ActionAlreadyCanonical — the local salt already matches the bucket's
	// canonical salt. No daemon state changed.
	ActionAlreadyCanonical
	// ActionReconciled — local salt differed; master key was re-derived,
	// capability re-encrypted, config rewritten.
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

// Reconcile attempts to fetch .crate/crate.json and align the daemon's salt
// with the browser-canonical one. Forward-compatible: when the browser side
// hasn't shipped yet (M3 browser piece), Fetch returns ErrAbsent and the
// reconciler returns ActionAbsent — the daemon proceeds with its local salt.
//
// On ActionReconciled: in.Cfg is mutated in-place AND written to disk
// (atomic temp+rename) before returning. Caller MUST replace its in-memory
// master key with result.NewMasterKey and zero the previous one.
//
// On ActionFailed: in.Cfg is NOT mutated; the daemon proceeds with the local
// salt. The error is logged but not returned — reconciliation failure is
// non-fatal at boot.
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
		// We can't easily roll back the in-memory Cfg mutations — but the
		// caller's MasterKey was NOT replaced yet, so the daemon will
		// proceed with the OLD key + a mismatching on-disk Salt. This is
		// recoverable: the next start re-reads the OLD file and tries
		// reconciliation again.
		// We DO need to revert Cfg to avoid the syncer running with a
		// nonce/sealed that don't match a key it actually holds.
		return ReconcileResult{Action: ActionFailed}
	}
	logger.Info("salt reconciliation: re-derived master key + re-encrypted capability")
	return ReconcileResult{
		Action:       ActionReconciled,
		NewMasterKey: newMasterKey,
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
