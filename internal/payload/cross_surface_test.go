// SPDX-License-Identifier: AGPL-3.0-or-later
package payload

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fixture is the cross-surface interchange record. The browser writes
// testdata/browser-v2.json (crate/test/gen-cross-surface-fixture.mjs);
// this package writes daemon-v2.json when CRATE_WRITE_FIXTURE is set, and
// crate/test/cross-surface-daemon.test.mjs opens that. Each side proves it
// can OPEN what the other SEALED — that is the byte-for-byte contract.
type fixture struct {
	Producer        string `json:"producer"`
	UUID            string `json:"uuid"`
	DataKey         string `json:"data_key"`
	Size            int64  `json:"size"`
	ChunkSize       int64  `json:"chunk_size"`
	ContentIV       string `json:"content_iv"`
	Body            string `json:"body"`
	PlaintextSHA256 string `json:"plaintext_sha256"`
}

func b64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}

func TestOpensBrowserSealedObject(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "browser-v2.json"))
	if err != nil {
		t.Fatalf("fixture missing — regenerate with `node test/gen-cross-surface-fixture.mjs` in the crate repo: %v", err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	pt, err := OpenObject(b64(t, f.DataKey), b64(t, f.Body), f.UUID, f.Size, b64(t, f.ContentIV), f.ChunkSize)
	if err != nil {
		t.Fatalf("daemon cannot open a browser-sealed v2 object: %v", err)
	}
	sum := sha256.Sum256(pt)
	if got := hex.EncodeToString(sum[:]); got != f.PlaintextSHA256 {
		t.Fatalf("plaintext sha256 %s, fixture says %s", got, f.PlaintextSHA256)
	}
	if int64(len(pt)) != f.Size {
		t.Fatalf("plaintext len %d, fixture size %d", len(pt), f.Size)
	}
	// and the tamper contract holds across surfaces too: the browser's
	// IV_0 must anchor the body
	body := b64(t, f.Body)
	body[0] ^= 1
	if _, err := OpenObject(b64(t, f.DataKey), body, f.UUID, f.Size, b64(t, f.ContentIV), f.ChunkSize); err == nil {
		t.Fatal("browser fixture with flipped IV_0 accepted")
	}
}

// TestWritesDaemonFixture emits testdata/daemon-v2.json for the browser's
// reverse test. Only when CRATE_WRITE_FIXTURE is set, so a routine
// `go test` never dirties the tree.
func TestWritesDaemonFixture(t *testing.T) {
	if os.Getenv("CRATE_WRITE_FIXTURE") == "" {
		t.Skip("set CRATE_WRITE_FIXTURE=1 to regenerate testdata/daemon-v2.json")
	}
	const chunk int64 = 1024
	size := 3*chunk + 17
	pt := make([]byte, size)
	for i := range pt {
		pt[i] = byte(i*31 + 7)
	}
	key := mustKey(t)
	uuid := "01DAEMONFIXTURE0000000000"
	civ, body, err := SealObject(key, pt, uuid, chunk)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pt)
	out, _ := json.MarshalIndent(fixture{
		Producer:        "crate-agent internal/payload SealObject",
		UUID:            uuid,
		DataKey:         base64.StdEncoding.EncodeToString(key),
		Size:            size,
		ChunkSize:       chunk,
		ContentIV:       base64.StdEncoding.EncodeToString(civ),
		Body:            base64.StdEncoding.EncodeToString(body),
		PlaintextSHA256: hex.EncodeToString(sum[:]),
	}, "", "  ")
	if err := os.WriteFile(filepath.Join("testdata", "daemon-v2.json"), append(out, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body[:IVSize], civ) {
		t.Fatal("self-check: leading IV")
	}
}
