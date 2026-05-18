// SPDX-License-Identifier: AGPL-3.0-or-later
// Package identity wraps fabric-sdk-go/identity for daemon-side FIF
// loading. M1 covers read-only loading; M2's `pair` command will write
// FIFs via the same SDK package.

package identity

import (
	"fmt"
	"os"

	sdkidentity "github.com/NakliTechie/private-mesh/fabric-sdk-go/identity"
)

// Load opens the FIF at `path`, parses it, and unlocks it with `passphrase`.
// Returns the unlocked FIF — callers must NOT log or persist `Inner` or
// `passphrase` per crate-browser-handoff §"Persistence rules".
func Load(path, passphrase string) (*sdkidentity.FIF, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("identity: open %s: %w", path, err)
	}
	defer f.Close()

	fif, err := sdkidentity.ParseFIF(f)
	if err != nil {
		return nil, fmt.Errorf("identity: parse FIF %s: %w", path, err)
	}
	if err := fif.Unlock(passphrase); err != nil {
		return nil, fmt.Errorf("identity: unlock FIF %s: %w", path, err)
	}
	return fif, nil
}
