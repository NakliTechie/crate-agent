// SPDX-License-Identifier: AGPL-3.0-or-later
// Package refresh implements capability refresh — M3 piece 6.
//
// The daemon's capability has a `time <` caveat (1 year by default). At
// 80% of the TTL (i.e. when the capability is within 20% of expiry), the
// daemon POSTs /v1/capability/refresh to mint a fresh capability with an
// extended `time <`. The new capability is re-encrypted under the in-memory
// master key and the config is atomic-rewritten.
//
// Crucially: the master key (the PBKDF2-derived 32 bytes) stays in memory
// for the daemon's lifetime so the refresh can re-encrypt without
// re-prompting for the passphrase. This is the security trade-off — a
// long-running daemon is a long-lived key holder. Mitigations: the key
// never touches disk; it's zeroed when the daemon exits via the runtime's
// cleanup path.
package refresh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	sdkcrypto "github.com/NakliTechie/private-mesh/fabric-sdk-go/crypto"
	"github.com/NakliTechie/private-mesh/fabric-sdk-go/grant"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/httpc"
)

// DefaultThresholdFraction is the fraction of remaining-vs-total TTL at
// which the daemon triggers a refresh. 0.2 = "20% of TTL remains" =
// "80% of TTL elapsed" per the M3 plan.
//
// Computed against the capability's `expires_at` only (the daemon doesn't
// know `issued_at` — that's not in the redeem response). We approximate as
// "refresh when (expires - now) < threshold_seconds." threshold_seconds is
// computed from a known TTL (default 1 year).
const DefaultThresholdFraction = 0.2

// DefaultTotalTTL matches the Hub's `capabilityTTL` (1 year). If the Hub
// ever ships a different default, the daemon over-refreshes (cheap) but
// doesn't break.
const DefaultTotalTTL = 365 * 24 * time.Hour

// DefaultPollInterval is how often Run wakes up to check the expiry.
// Coarse — refresh decisions happen on a days/weeks horizon, so 1 minute
// is plenty.
const DefaultPollInterval = 1 * time.Minute

// Config bundles the inputs the refresh loop needs.
type Config struct {
	// CfgPath is the absolute path to crate-agent.toml. Refresh rewrites
	// this file atomically when a new capability arrives.
	CfgPath string

	// Cfg is the in-memory config object — Refresh updates this in-place
	// after a successful refresh so other daemon components see the new
	// capability + new expiry.
	Cfg *config.Config

	// MasterKey is the 32-byte PBKDF2-derived key used to re-encrypt the
	// refreshed capability. Caller keeps this in memory for the daemon's
	// lifetime; the refresh loop never persists it.
	MasterKey []byte

	// Hub is the HTTP client pointed at the transport.
	Hub *httpc.Client

	// CapabilityRef is a pointer the syncer + puller read to pick up the
	// latest capability after a refresh. Refresh writes to *CapabilityRef
	// under CapabilityMu after a successful refresh.
	//
	// nil is allowed (the daemon has not been wired with a live syncer
	// yet — the refresh still updates Cfg + the on-disk file).
	CapabilityRef *string

	// CapabilityMu guards reads + writes of *CapabilityRef across the
	// refresh writer and syncer / puller readers. Required when
	// CapabilityRef is non-nil; otherwise it's a Go data race
	// (security audit 2026-05 finding M1).
	CapabilityMu *sync.RWMutex

	// PollInterval / ThresholdFraction / TotalTTL override the defaults.
	// Zero values use the defaults.
	PollInterval      time.Duration
	ThresholdFraction float64
	TotalTTL          time.Duration

	// Logger optionally collects structured logs. nil = slog.Default().
	Logger *slog.Logger

	// Now overrides time.Now — testing only.
	Now func() time.Time
}

// Runner drives the periodic refresh check.
type Runner struct {
	cfg               Config
	logger            *slog.Logger
	now               func() time.Time
	pollInterval      time.Duration
	thresholdFraction float64
	totalTTL          time.Duration
}

// New validates Config and returns a Runner. The MasterKey is held by
// reference; the caller is responsible for zeroing it when the daemon
// terminates.
func New(cfg Config) (*Runner, error) {
	if cfg.CfgPath == "" {
		return nil, errors.New("refresh: CfgPath required")
	}
	if cfg.Cfg == nil {
		return nil, errors.New("refresh: Cfg required")
	}
	if len(cfg.MasterKey) != sdkcrypto.KeySize {
		return nil, fmt.Errorf("refresh: MasterKey must be %d bytes, got %d",
			sdkcrypto.KeySize, len(cfg.MasterKey))
	}
	if cfg.Hub == nil {
		return nil, errors.New("refresh: Hub required")
	}
	r := &Runner{
		cfg:               cfg,
		logger:            cfg.Logger,
		now:               cfg.Now,
		pollInterval:      cfg.PollInterval,
		thresholdFraction: cfg.ThresholdFraction,
		totalTTL:          cfg.TotalTTL,
	}
	if r.logger == nil {
		r.logger = slog.Default()
	}
	if r.now == nil {
		r.now = time.Now
	}
	if r.pollInterval <= 0 {
		r.pollInterval = DefaultPollInterval
	}
	if r.thresholdFraction <= 0 {
		r.thresholdFraction = DefaultThresholdFraction
	}
	if r.totalTTL <= 0 {
		r.totalTTL = DefaultTotalTTL
	}
	return r, nil
}

// Run polls until ctx is cancelled. Each tick: read the configured expiry,
// compare against the threshold, and if needed call /v1/capability/refresh,
// re-encrypt, atomic-write the config.
//
// Errors from refresh are LOGGED, not returned — a refresh failure should
// not crash the daemon. The next tick will retry. If the capability fully
// expires, the next sync request will fail with grant_expired and the
// syncer's normal backoff kicks in until the user re-pairs.
func (r *Runner) Run(ctx context.Context) {
	t := time.NewTicker(r.pollInterval)
	defer t.Stop()
	// Run once immediately to catch the "daemon started past 80% TTL" case.
	r.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *Runner) tick(ctx context.Context) {
	if !r.needsRefresh() {
		return
	}
	if err := r.doRefresh(ctx); err != nil {
		r.logger.Warn("capability refresh failed; will retry next tick", "err", err)
		return
	}
	r.logger.Info("capability refreshed",
		"new_expires", time.Unix(r.cfg.Cfg.Crate.CapabilityExpires, 0).UTC().Format(time.RFC3339))
}

// needsRefresh returns true when (expires - now) < (totalTTL * threshold).
// Default: refresh when < ~73 days remain on a 1-year capability.
func (r *Runner) needsRefresh() bool {
	if r.cfg.Cfg.Crate.CapabilityExpires == 0 {
		// No expiry set — pre-pair config; nothing to refresh.
		return false
	}
	remaining := time.Until(time.Unix(r.cfg.Cfg.Crate.CapabilityExpires, 0)) // uses real time.Now
	if r.now != nil {
		remaining = time.Unix(r.cfg.Cfg.Crate.CapabilityExpires, 0).Sub(r.now())
	}
	threshold := time.Duration(float64(r.totalTTL) * r.thresholdFraction)
	return remaining < threshold
}

// doRefresh hits /v1/capability/refresh, decodes the response, re-encrypts
// the new capability, and atomic-writes the config.
//
// On success Cfg + (if non-nil) *CapabilityRef are updated in-place; on
// failure neither is touched.
func (r *Runner) doRefresh(ctx context.Context) error {
	// Current capability is in Cfg.Crate.PairingToken as base64(sealed bytes);
	// the daemon's refresh request authenticates with the CURRENT (still-
	// valid) macaroon, not the sealed bytes — so the syncer's plaintext copy
	// (in CapabilityRef) is what we present as the auth header.
	if r.cfg.CapabilityRef == nil {
		return errors.New("CapabilityRef not configured")
	}
	currentCap := r.getCapability()
	if currentCap == "" {
		return errors.New("CapabilityRef holds empty capability")
	}

	resp, err := r.cfg.Hub.PostJSONAuth(ctx, "/v1/capability/refresh", struct{}{}, currentCap)
	if err != nil {
		return fmt.Errorf("POST refresh: %w", err)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		if resp.Envelope.Error != nil {
			return fmt.Errorf("refresh: HTTP %d %s: %s",
				resp.Status, resp.Envelope.Error.Code, resp.Envelope.Error.Message)
		}
		return fmt.Errorf("refresh: HTTP %d", resp.Status)
	}

	// Parse the envelope's data field.
	var data struct {
		V          int    `json:"v"`
		Capability string `json:"capability"` // base64 macaroon
		ExpiresAt  int64  `json:"expires_at"` // unix seconds
	}
	if err := json.Unmarshal(resp.Envelope.Data, &data); err != nil {
		return fmt.Errorf("refresh: parse envelope.data: %w", err)
	}
	if data.Capability == "" {
		return errors.New("refresh: empty capability in response")
	}

	// Decode the new (plaintext base64) capability and re-encrypt under
	// the master key with a fresh nonce.
	newCap, err := base64.StdEncoding.DecodeString(data.Capability)
	if err != nil {
		return fmt.Errorf("refresh: decode new capability: %w", err)
	}

	// Validate the refreshed capability before we commit it. A malicious
	// or buggy transport could otherwise return a wider-scope macaroon
	// (different bucket, more operations, longer TTL than allowed) that
	// we'd happily encrypt to disk and present on future requests.
	// Subset-check the new capability against the current one.
	// See 2026-05 security audit, H3.
	if err := r.validateRefreshedCapability(currentCap, newCap, data.ExpiresAt); err != nil {
		return fmt.Errorf("refresh: rejected new capability: %w", err)
	}

	nonce, err := sdkcrypto.RandomNonce()
	if err != nil {
		return fmt.Errorf("refresh: nonce: %w", err)
	}
	sealed, err := sdkcrypto.Seal(r.cfg.MasterKey, nonce, newCap, nil)
	if err != nil {
		return fmt.Errorf("refresh: seal: %w", err)
	}

	// Persist.
	r.cfg.Cfg.Crate.PairingToken = base64.StdEncoding.EncodeToString(sealed)
	r.cfg.Cfg.Crate.CapabilityNonce = base64.StdEncoding.EncodeToString(nonce)
	r.cfg.Cfg.Crate.CapabilityExpires = data.ExpiresAt
	if err := config.Write(r.cfg.CfgPath, r.cfg.Cfg); err != nil {
		return fmt.Errorf("refresh: rewrite config: %w", err)
	}
	r.setCapability(data.Capability)
	return nil
}

// getCapability returns the current capability under the shared RWMutex
// (read lock). Falls through to a plain read if no mutex was configured.
func (r *Runner) getCapability() string {
	if r.cfg.CapabilityMu == nil {
		return *r.cfg.CapabilityRef
	}
	r.cfg.CapabilityMu.RLock()
	defer r.cfg.CapabilityMu.RUnlock()
	return *r.cfg.CapabilityRef
}

// setCapability writes the new capability under the shared RWMutex
// (write lock). The mutex is shared with the syncer + puller readers.
func (r *Runner) setCapability(s string) {
	if r.cfg.CapabilityMu == nil {
		*r.cfg.CapabilityRef = s
		return
	}
	r.cfg.CapabilityMu.Lock()
	defer r.cfg.CapabilityMu.Unlock()
	*r.cfg.CapabilityRef = s
}

// validateRefreshedCapability rejects refreshed capabilities that would
// broaden the daemon's authority. Checks:
//
//   - expiry MUST be in the future
//   - expiry MUST NOT exceed now + 2 × TotalTTL (sanity bound; a malicious
//     transport returning "valid for 100 years" would otherwise let the
//     daemon present an effectively unrevocable credential)
//   - both capabilities MUST decode as macaroons via fabric-sdk-go/grant.Parse
//   - issued_by_principal MUST match the current (rotating the issuer under
//     us is suspicious + breaks the daemon's caller identity)
//   - primitive MUST match (current daemon scope is `sync`; a refresh that
//     returned `vault` or `bridge` is rejected)
//   - namespace MUST match (the bucket_id can't change across refresh)
//   - operations MUST be a subset of the current operations (a refresh that
//     widens read-only → read-write is rejected)
//
// On any structural surprise we fail closed — keep using the still-valid
// current capability rather than accept an unverifiable replacement. See
// 2026-05 security audit, H3.
func (r *Runner) validateRefreshedCapability(currentB64 string, newRawBytes []byte, newExpires int64) error {
	// 1. Expiry bounds (cheapest check, runs first).
	now := r.now()
	if newExpires <= now.Unix() {
		return errors.New("refreshed capability expires in the past or now")
	}
	maxAllowed := now.Add(2 * r.totalTTL).Unix()
	if newExpires > maxAllowed {
		return fmt.Errorf("refreshed expiry %d exceeds permitted %d (more than 2× TotalTTL out)",
			newExpires, maxAllowed)
	}

	// 2. Decode the current capability (base64-wrapped macaroon bytes).
	currentBytes, err := base64.StdEncoding.DecodeString(currentB64)
	if err != nil {
		return fmt.Errorf("decode current capability: %w", err)
	}
	current, err := grant.Parse(currentBytes)
	if err != nil {
		return fmt.Errorf("parse current capability: %w", err)
	}
	next, err := grant.Parse(newRawBytes)
	if err != nil {
		return fmt.Errorf("parse refreshed capability: %w", err)
	}

	// 3. Issuer identity unchanged.
	if next.Identifier.IssuedByPrincipal != current.Identifier.IssuedByPrincipal {
		return fmt.Errorf("refreshed issuer %q differs from current %q",
			next.Identifier.IssuedByPrincipal, current.Identifier.IssuedByPrincipal)
	}

	// 4. Primitive unchanged (daemon binds to sync; a different primitive
	// is structurally wrong even if the issuer matches).
	if next.Identifier.Scope.Primitive != current.Identifier.Scope.Primitive {
		return fmt.Errorf("refreshed primitive %q differs from current %q",
			next.Identifier.Scope.Primitive, current.Identifier.Scope.Primitive)
	}

	// 5. Namespace unchanged. The current capability's namespace pins it
	// to a specific bucket_id (or wildcard "*"). A refresh to a different
	// bucket would let the daemon read/write a folder it was never paired
	// for. Wildcard-current accepts any namespace (broadest scope already);
	// any other current value pins exactly.
	if current.Identifier.Scope.Namespace != "*" &&
		next.Identifier.Scope.Namespace != current.Identifier.Scope.Namespace {
		return fmt.Errorf("refreshed namespace %q differs from current %q",
			next.Identifier.Scope.Namespace, current.Identifier.Scope.Namespace)
	}

	// 6. Operations subset. Build a set from the current and walk the
	// new ones; any extra op is a scope widening.
	currentOps := stringSet(current.Identifier.Scope.Operations)
	for _, op := range next.Identifier.Scope.Operations {
		if _, ok := currentOps[op]; !ok {
			return fmt.Errorf("refreshed operations include %q which is not in current scope %v",
				op, sortedKeys(currentOps))
		}
	}

	return nil
}

// stringSet is a small set helper.
func stringSet(ss []string) map[string]struct{} {
	m := make(map[string]struct{}, len(ss))
	for _, s := range ss {
		m[s] = struct{}{}
	}
	return m
}

// sortedKeys returns a deterministic sorted slice — used only in error
// messages so test assertions stay stable.
func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
