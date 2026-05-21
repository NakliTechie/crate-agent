// SPDX-License-Identifier: AGPL-3.0-or-later
// Anchor tests — exercise validateAndAdvanceAnchor across the four cases
// per 2026-05 audit finding H1: TOFU first load, accept extension, reject
// truncation, reject fork.
package puller

import (
	"context"
	"os"
	"testing"
)

// TestPuller_AnchorTOFUFirstLoad — no anchor row exists; the puller
// accepts the manifest and writes the baseline anchor.
func TestPuller_AnchorTOFUFirstLoad(t *testing.T) {
	r := setupPuller(t)
	r.publishFile(t, "/notes/a.txt", []byte("first"))

	ctx := context.Background()
	if got, err := r.state.GetManifestAnchor(ctx, "bk_test"); err != nil || got != nil {
		t.Fatalf("pre-tick anchor: got %+v err=%v, want nil/nil", got, err)
	}

	runTick(t, r)

	got, err := r.state.GetManifestAnchor(ctx, "bk_test")
	if err != nil {
		t.Fatalf("GetManifestAnchor: %v", err)
	}
	if got == nil {
		t.Fatal("anchor not written on TOFU first load")
	}
	if got.Count != 1 {
		t.Errorf("anchor count = %d, want 1", got.Count)
	}
	if got.LastSig == "" {
		t.Error("anchor lastSig empty")
	}
	// Sanity: the file actually landed locally.
	if _, err := os.Stat(r.localPath + "/notes/a.txt"); err != nil {
		t.Errorf("expected file written on accept: %v", err)
	}
}

// TestPuller_AnchorAcceptsExtension — TOFU anchor at count=1, then a
// real second event is published. The puller validates that the chain
// extends, accepts, and advances the anchor.
func TestPuller_AnchorAcceptsExtension(t *testing.T) {
	r := setupPuller(t)
	r.publishFile(t, "/a.txt", []byte("first"))
	runTick(t, r) // TOFU
	r.publishFile(t, "/b.txt", []byte("second"))
	runTick(t, r) // should advance

	ctx := context.Background()
	got, _ := r.state.GetManifestAnchor(ctx, "bk_test")
	if got == nil || got.Count != 2 {
		t.Fatalf("after extension: anchor = %+v, want count=2", got)
	}
}

// TestPuller_AnchorRejectsTruncation — TOFU anchor at count=2, then the
// bucket is rolled back to count=1. The puller refuses to apply.
func TestPuller_AnchorRejectsTruncation(t *testing.T) {
	r := setupPuller(t)
	r.publishFile(t, "/a.txt", []byte("one"))
	r.publishFile(t, "/b.txt", []byte("two"))
	runTick(t, r) // TOFU at count=2
	ctx := context.Background()
	anchor, _ := r.state.GetManifestAnchor(ctx, "bk_test")
	if anchor.Count != 2 {
		t.Fatalf("setup anchor count = %d, want 2", anchor.Count)
	}

	// Simulate rollback: rewind in-memory manifest to count=1 and re-encrypt.
	r.manMu.Lock()
	allEvents := r.manifest.Events()
	// Mutate the shared manifest via reflection-free path: build a fresh one
	// holding the first event and swap. We do this by truncating the slice
	// header, but Events() returns a defensive view. Easiest: rebuild.
	_ = allEvents
	r.manMu.Unlock()

	// Build a new manifest with only the first file. Re-publish.
	r2 := setupPuller(t) // throwaway just to get fresh helpers
	r2.hub = r.hub       // reuse same fake hub
	r2.state = r.state
	r2.masterKey = r.masterKey
	r2.manMu = r.manMu
	r2.localPath = r.localPath
	// Replace the bucket's manifest with a shorter version. We do this by
	// calling publishFile on the throwaway rig's manifest, which encrypts
	// under the same master key and PUTs to the same hub.
	r2.publishFile(t, "/a.txt", []byte("one"))

	// Now run the original puller again — the hub now serves the shorter
	// manifest. validateAndAdvanceAnchor must reject (count 1 < anchor 2).
	runTick(t, r)

	// Anchor should be unchanged (still 2).
	stillAnchor, _ := r.state.GetManifestAnchor(ctx, "bk_test")
	if stillAnchor == nil || stillAnchor.Count != 2 {
		t.Errorf("anchor moved on truncation: got %+v, want count=2 unchanged", stillAnchor)
	}
}

// TestPuller_AnchorRejectsFork — TOFU anchor at count=1 with a specific
// sig, then a different one-event manifest (different chain) is served at
// count=1. validateAndAdvanceAnchor must reject.
func TestPuller_AnchorRejectsFork(t *testing.T) {
	r := setupPuller(t)
	r.publishFile(t, "/a.txt", []byte("original"))
	runTick(t, r) // TOFU at count=1
	ctx := context.Background()
	first, _ := r.state.GetManifestAnchor(ctx, "bk_test")
	if first == nil || first.Count != 1 {
		t.Fatalf("setup anchor count = %d, want 1", first.Count)
	}
	firstSig := first.LastSig

	// Throwaway rig with the SAME master key and SAME hub but its own
	// in-memory manifest — publishing through it creates a different
	// first-event sig (different ts + UUID).
	r2 := setupPuller(t)
	r2.hub = r.hub
	r2.masterKey = r.masterKey
	r2.publishFile(t, "/a.txt", []byte("different content"))

	// Run the original puller. The hub now serves the forked manifest;
	// loaded.count == anchor.count == 1, but events[0].sig != anchor.LastSig.
	runTick(t, r)

	// Anchor must NOT have changed.
	after, _ := r.state.GetManifestAnchor(ctx, "bk_test")
	if after == nil {
		t.Fatal("anchor disappeared after fork attempt")
	}
	if after.LastSig != firstSig {
		t.Errorf("anchor.LastSig changed from %q to %q on fork rejection",
			firstSig, after.LastSig)
	}
}
