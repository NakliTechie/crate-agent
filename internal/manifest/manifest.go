// SPDX-License-Identifier: AGPL-3.0-or-later
// Package manifest is the Go port of crate/lib/manifest.js. Same wire
// format: signed JSONL events at .crate/manifest.jsonl.enc, with
// HMAC-SHA256 prev_sig chain, AES-GCM envelope at flush.
//
// Cross-surface contract:
//   - Event schema MUST match the browser exactly (fields + types).
//   - canonical JSON MUST sort keys lex-ascending at every level so HMAC
//     inputs are byte-identical regardless of which surface emits.
//   - AES-GCM AAD is ".crate/manifest.jsonl.enc:v1" (binds the ciphertext
//     to its bucket key — moving it to a different key fails auth).
package manifest

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NakliTechie/crate-agent/internal/payload"
)

const (
	// Path is the bucket key for the manifest. Matches lib/manifest.js's
	// MANIFEST_PATH exactly.
	Path = ".crate/manifest.jsonl.enc"
	// EventV is the schema version we emit. Readers tolerate higher
	// versions for forward-compat; writers always emit v=1 in v1.0.
	EventV = 1
)

// manifestAAD is the AES-GCM AAD bound to the encrypted manifest payload.
// Identical to MANIFEST_AAD in lib/manifest.js.
var manifestAAD = []byte(".crate/manifest.jsonl.enc:v1")

// Error is the package error type.
type Error struct{ msg string }

func (e *Error) Error() string { return e.msg }
func newErr(format string, a ...interface{}) error {
	return &Error{msg: fmt.Sprintf(format, a...)}
}

// Event is one row of the JSONL log. Fields use string-tagged JSON so
// CanonicalJSON-via-map preserves the spec field names exactly.
//
// Per-op required fields (enforced by validateShape):
//   create: uuid, path, size, data_key_iv, data_key_ct, content_iv
//   update: uuid, content_iv, size
//   delete: uuid
//   move:   uuid, path
//   mkdir:  path
//
// All ops carry v, ts, op, prev_sig, sig.
type Event = map[string]interface{}

// Manifest is an append-only signed JSONL log held in memory. Construct
// via New() or LoadFromBytes(); append events via Append; serialise via
// EncryptToBytes; persist via your transport of choice (the puller PUTs
// to the bucket via httpc).
type Manifest struct {
	events  []Event
	lastSig string
}

// New returns an empty manifest.
func New() *Manifest {
	return &Manifest{events: nil, lastSig: ""}
}

// Events returns the underlying event slice. Mutating this slice
// invalidates the manifest's prev_sig chain — do not.
func (m *Manifest) Events() []Event { return m.events }

// Size returns the number of events.
func (m *Manifest) Size() int { return len(m.events) }

// Append validates the partial event, fills in v/ts/prev_sig, computes
// the signature with masterKey, appends. Returns the finalised event.
func (m *Manifest) Append(partial Event, masterKey []byte) (Event, error) {
	if partial == nil {
		return nil, errors.New("manifest.Append: event is nil")
	}
	evt := Event{
		"v":  float64(EventV),
		"ts": float64(time.Now().UnixMilli()),
	}
	for k, v := range partial {
		evt[k] = v
	}
	evt["prev_sig"] = m.lastSig
	if err := validateShape(evt); err != nil {
		return nil, err
	}
	sigB64, err := signEvent(evt, masterKey)
	if err != nil {
		return nil, err
	}
	evt["sig"] = sigB64
	m.events = append(m.events, evt)
	m.lastSig = sigB64
	return evt, nil
}

// Verify walks the chain and confirms every prev_sig + sig matches.
// Returns (ok, idx, reason). On success: (true, 0, "").
func (m *Manifest) Verify(masterKey []byte) (bool, int, string) {
	prev := ""
	for i, e := range m.events {
		got, _ := e["prev_sig"].(string)
		if got != prev {
			return false, i, fmt.Sprintf("prev_sig chain broken: %q vs %q", got, prev)
		}
		sigB64, _ := e["sig"].(string)
		clone := make(Event, len(e))
		for k, v := range e {
			if k == "sig" {
				continue
			}
			clone[k] = v
		}
		want, err := signEvent(clone, masterKey)
		if err != nil {
			return false, i, "sign recompute failed: " + err.Error()
		}
		// Constant-time compare. `want` and `sigB64` are both base64-
		// encoded HMAC outputs; comparing the encoded strings is
		// equivalent to comparing the underlying bytes IF the encoding
		// is deterministic (it is — base64 std with no padding
		// variance). subtle.ConstantTimeCompare returns 1 on equal.
		// See 2026-05 security audit, L1.
		if subtle.ConstantTimeCompare([]byte(want), []byte(sigB64)) != 1 {
			return false, i, "sig mismatch"
		}
		prev = sigB64
	}
	return true, 0, ""
}

// Entry is the result of materialise. Folders surface with Path set + IsDir=true.
type Entry struct {
	Path       string
	UUID       string
	IsDir      bool
	Size       int64
	Mime       string
	DataKeyIV  string // base64 (matches browser's data_key_iv)
	DataKeyCT  string // base64
	ContentIV  string // base64
	TSUnixMs   int64
}

// Materialise replays the log into a map keyed by remote path. Folders
// surface from explicit mkdir events; file paths imply parent folders.
func (m *Manifest) Materialise() map[string]*Entry {
	byUUID := map[string]*Entry{}
	byPath := map[string]*Entry{}
	for _, e := range m.events {
		op, _ := e["op"].(string)
		switch op {
		case "create":
			entry := &Entry{
				UUID:      strField(e, "uuid"),
				Path:      strField(e, "path"),
				Size:      int64Field(e, "size"),
				Mime:      strField(e, "mime"),
				DataKeyIV: strField(e, "data_key_iv"),
				DataKeyCT: strField(e, "data_key_ct"),
				ContentIV: strField(e, "content_iv"),
				TSUnixMs:  int64Field(e, "ts"),
			}
			byUUID[entry.UUID] = entry
			byPath[entry.Path] = entry
		case "update":
			uuid := strField(e, "uuid")
			entry, ok := byUUID[uuid]
			if !ok {
				continue // dangling
			}
			entry.Size = int64Field(e, "size")
			if iv := strField(e, "content_iv"); iv != "" {
				entry.ContentIV = iv
			}
			entry.TSUnixMs = int64Field(e, "ts")
		case "delete":
			uuid := strField(e, "uuid")
			entry, ok := byUUID[uuid]
			if !ok {
				continue
			}
			delete(byUUID, uuid)
			delete(byPath, entry.Path)
		case "move":
			uuid := strField(e, "uuid")
			entry, ok := byUUID[uuid]
			if !ok {
				continue
			}
			delete(byPath, entry.Path)
			entry.Path = strField(e, "path")
			entry.TSUnixMs = int64Field(e, "ts")
			byPath[entry.Path] = entry
		case "mkdir":
			path := strField(e, "path")
			byPath[path] = &Entry{
				Path:     path,
				IsDir:    true,
				TSUnixMs: int64Field(e, "ts"),
			}
		default:
			// Unknown op — forward-compat: ignore.
		}
	}
	return byPath
}

// EncryptToBytes serialises the events as JSONL, AES-GCM-seals under
// masterKey with the canonical AAD, and returns the bucket-ready bytes:
// 12-byte IV || ciphertext+tag.
func (m *Manifest) EncryptToBytes(masterKey []byte) ([]byte, error) {
	var sb strings.Builder
	for _, e := range m.events {
		// Use stdlib json (NOT canonical) for the on-wire JSONL — the
		// browser also uses JSON.stringify, which is not canonical. The
		// canonical form is only used as the HMAC input.
		b, err := json.Marshal(e)
		if err != nil {
			return nil, fmt.Errorf("manifest: marshal event: %w", err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	plaintext := []byte(sb.String())
	iv, err := payload.RandomIV()
	if err != nil {
		return nil, fmt.Errorf("manifest: iv: %w", err)
	}
	ct, err := payload.Seal(masterKey, iv, plaintext, manifestAAD)
	if err != nil {
		return nil, fmt.Errorf("manifest: seal: %w", err)
	}
	out := make([]byte, len(iv)+len(ct))
	copy(out, iv)
	copy(out[len(iv):], ct)
	return out, nil
}

// LoadFromBytes decrypts a bucket-stored manifest and parses the events.
// Empty input returns an empty manifest. Decrypt failure (wrong key,
// tamper, wrong AAD) returns a typed error.
func LoadFromBytes(bytesIn, masterKey []byte) (*Manifest, error) {
	if len(bytesIn) == 0 {
		return New(), nil
	}
	if len(bytesIn) < payload.IVSize {
		return nil, newErr("manifest: ciphertext too short (%d bytes; missing IV)", len(bytesIn))
	}
	iv := bytesIn[:payload.IVSize]
	ct := bytesIn[payload.IVSize:]
	plain, err := payload.Open(masterKey, iv, ct, manifestAAD)
	if err != nil {
		return nil, newErr("manifest: decrypt failed: %v", err)
	}
	return FromJSONL(string(plain))
}

// FromJSONL parses an unencrypted JSONL string. Validates each event
// shape + the prev_sig chain.
func FromJSONL(text string) (*Manifest, error) {
	m := New()
	if strings.TrimSpace(text) == "" {
		return m, nil
	}
	lines := strings.Split(text, "\n")
	prev := ""
	for i, line := range lines {
		if line == "" {
			continue
		}
		var evt Event
		if err := json.Unmarshal([]byte(line), &evt); err != nil {
			return nil, newErr("manifest: line %d not JSON: %v", i+1, err)
		}
		if err := validateShape(evt); err != nil {
			return nil, newErr("manifest: line %d: %v", i+1, err)
		}
		gotPrev, _ := evt["prev_sig"].(string)
		if gotPrev != prev {
			return nil, newErr("manifest: line %d prev_sig chain broken: %q vs %q",
				i+1, gotPrev, prev)
		}
		m.events = append(m.events, evt)
		sig, _ := evt["sig"].(string)
		prev = sig
	}
	m.lastSig = prev
	return m, nil
}

// --- event factories (mirror lib/manifest.js's exports) -------------------

// CreateEvent builds a `create` partial event. Caller passes via Append.
func CreateEvent(uuid, path string, size int64, mime string,
	dataKeyIV, dataKeyCT, contentIV []byte,
) Event {
	if mime == "" {
		mime = "application/octet-stream"
	}
	return Event{
		"op":          "create",
		"uuid":        uuid,
		"path":        path,
		"size":        float64(size),
		"mime":        mime,
		"data_key_iv": base64.StdEncoding.EncodeToString(dataKeyIV),
		"data_key_ct": base64.StdEncoding.EncodeToString(dataKeyCT),
		"content_iv":  base64.StdEncoding.EncodeToString(contentIV),
	}
}

func UpdateEvent(uuid string, size int64, contentIV []byte) Event {
	return Event{
		"op":         "update",
		"uuid":       uuid,
		"size":       float64(size),
		"content_iv": base64.StdEncoding.EncodeToString(contentIV),
	}
}

func DeleteEvent(uuid string) Event {
	return Event{"op": "delete", "uuid": uuid}
}

func MoveEvent(uuid, newPath string) Event {
	return Event{"op": "move", "uuid": uuid, "path": newPath}
}

func MkdirEvent(path string) Event {
	return Event{"op": "mkdir", "path": path}
}

// --- internal -------------------------------------------------------------

// signEvent computes the HMAC-SHA256 over canonical JSON of the event
// minus the `sig` field. Returns base64-encoded sig (matches the
// browser's lib/manifest.js).
func signEvent(evt Event, masterKey []byte) (string, error) {
	clone := make(Event, len(evt))
	for k, v := range evt {
		if k == "sig" {
			continue
		}
		clone[k] = v
	}
	canon, err := payload.CanonicalJSON(clone)
	if err != nil {
		return "", fmt.Errorf("manifest: canonical JSON: %w", err)
	}
	tag := payload.HMACSign(masterKey, canon)
	return base64.StdEncoding.EncodeToString(tag), nil
}

func validateShape(evt Event) error {
	v, _ := evt["v"].(float64)
	if int(v) > EventV {
		// Tolerate higher versions on read (forward-compat).
		return nil
	}
	if int(v) != EventV {
		return newErr("unknown event version v=%v", evt["v"])
	}
	op, _ := evt["op"].(string)
	if op == "" {
		return newErr("event missing op")
	}
	if _, ok := evt["ts"].(float64); !ok {
		return newErr("event missing ts")
	}
	switch op {
	case "create":
		for _, k := range []string{"uuid", "path", "data_key_iv", "data_key_ct", "content_iv"} {
			if !hasNonEmptyString(evt, k) {
				return newErr("create event requires string %s", k)
			}
		}
		if _, ok := evt["size"].(float64); !ok {
			return newErr("create event requires number size")
		}
	case "update":
		for _, k := range []string{"uuid", "content_iv"} {
			if !hasNonEmptyString(evt, k) {
				return newErr("update event requires string %s", k)
			}
		}
		if _, ok := evt["size"].(float64); !ok {
			return newErr("update event requires number size")
		}
	case "delete":
		if !hasNonEmptyString(evt, "uuid") {
			return newErr("delete event requires string uuid")
		}
	case "move":
		for _, k := range []string{"uuid", "path"} {
			if !hasNonEmptyString(evt, k) {
				return newErr("move event requires string %s", k)
			}
		}
	case "mkdir":
		if !hasNonEmptyString(evt, "path") {
			return newErr("mkdir event requires string path")
		}
	default:
		// Forward-compat: tolerate unknown ops on read.
	}
	return nil
}

func hasNonEmptyString(e Event, k string) bool {
	s, ok := e[k].(string)
	return ok && s != ""
}

func strField(e Event, k string) string {
	s, _ := e[k].(string)
	return s
}

func int64Field(e Event, k string) int64 {
	f, ok := e[k].(float64)
	if !ok {
		return 0
	}
	return int64(f)
}
