// SPDX-License-Identifier: AGPL-3.0-or-later
// Identity writer — builds a FIF wrapping a pre-generated Ed25519
// keypair (the daemon's ephemeral pair from Phase 3 step 3) and atomic-
// writes it to disk at mode 0600.
//
// The format matches what fabric-sdk-go/identity.ParseFIF reads, so
// internal/identity.Load (M1) reads back the file without changes.
//
// Generation pattern is adapted from
// nakli-cli/internal/fifio/fifio.go's CreateRoot, with the keypair
// pre-supplied rather than freshly generated.

package identity

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/oklog/ulid/v2"

	sdkidentity "github.com/NakliTechie/private-mesh/fabric-sdk-go/identity"
)

// GenerateEphemeralKey returns a fresh Ed25519 keypair for the daemon.
// The private key is held in memory by the caller until it lands inside
// the FIF; the public key goes into the pairing redeem request.
func GenerateEphemeralKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("identity: ed25519 keygen: %w", err)
	}
	return pub, priv, nil
}

// Write builds a FIF wrapping (pub, priv), encrypts it under `passphrase`,
// and atomic-writes it to `path` at mode 0600. Returns the principal ID
// (ULID) the FIF was created with so callers can record it in config.
//
// Atomic write = create temp file under same dir, fchmod 0600, write,
// fsync, rename. Crash-safe: either the new file is in place fully, or
// the old file (if any) is untouched.
func Write(path, displayName string, pub ed25519.PublicKey, priv ed25519.PrivateKey, passphrase string) (string, error) {
	if displayName == "" {
		return "", fmt.Errorf("identity.Write: displayName is required")
	}
	pid, err := ulid.New(ulid.Now(), cryptorand.Reader)
	if err != nil {
		return "", fmt.Errorf("identity.Write: ulid: %w", err)
	}
	inner := sdkidentity.NewInnerFIF(
		sdkidentity.Principal{
			Type:        sdkidentity.PrincipalDevice,
			ID:          pid.String(),
			DisplayName: displayName,
			CreatedAt:   time.Now().UTC(),
		},
		sdkidentity.KeyPair{
			Algorithm:  sdkidentity.KeyAlgEd25519,
			PublicKey:  pub,
			PrivateKey: priv,
		},
	)
	fif, err := sdkidentity.NewFIF(passphrase, inner)
	if err != nil {
		return "", fmt.Errorf("identity.Write: NewFIF: %w", err)
	}
	defer fif.Lock()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("identity.Write: mkdir parent: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return "", fmt.Errorf("identity.Write: open tmp %s: %w", tmp, err)
	}
	if err := fif.Serialize(f); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("identity.Write: serialize: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return "", fmt.Errorf("identity.Write: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("identity.Write: close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("identity.Write: rename: %w", err)
	}
	return pid.String(), nil
}
