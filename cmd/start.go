// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	sdkcrypto "github.com/NakliTechie/private-mesh/fabric-sdk-go/crypto"
	"github.com/NakliTechie/private-mesh/fabric-sdk-go/grant"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/cratejson"
	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/kdf"
	"github.com/NakliTechie/crate-agent/internal/manifest"
	"github.com/NakliTechie/crate-agent/internal/pidfile"
	"github.com/NakliTechie/crate-agent/internal/puller"
	"github.com/NakliTechie/crate-agent/internal/refresh"
	"github.com/NakliTechie/crate-agent/internal/state"
	"github.com/NakliTechie/crate-agent/internal/syncer"
	"github.com/NakliTechie/crate-agent/internal/watcher"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Run the daemon (watcher + syncer + capability-refresh loop)",
	Long: `Foreground supervisor-managed daemon.

Decrypts the configured capability with the folder passphrase, opens the
SQLite state DB, starts the filesystem watcher on the configured
local_path, and runs the sync loop until the process receives SIGINT or
SIGTERM. The capability is refreshed in the background when it approaches
expiry (default: when <20% of TTL remains).

Process model: foreground by default. Supervisor wrappers (launchd
KeepAlive=true on macOS, systemd Type=simple on Linux) handle restart on
exit. There is no detach / self-daemonize mode.

Exit codes: 0 = clean shutdown; 1 = generic; 2 = config; 3 = transport;
4 = already running.`,
	RunE: runStart,
}

func init() {
	startCmd.Flags().StringP("config", "c", "", "Path to crate-agent.toml")
	startCmd.Flags().String("passphrase-env", "CRATE_AGENT_PASSPHRASE",
		"Env var holding the folder passphrase (interactive prompt otherwise)")
	startCmd.Flags().Bool("passphrase-stdin", false,
		"Read passphrase from stdin (for piping; one line)")
	startCmd.Flags().String("pidfile", "",
		"PID-file path (default: $XDG_STATE_HOME/nakli/crate-agent.pid)")
}

func runStart(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return exitErr(exitConfigError, fmt.Errorf("home: %w", err))
		}
		cfgPath = filepath.Join(home, ".config", "nakli", "crate-agent.toml")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗ Config:", err)
		return exitErr(exitConfigError, err)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "✗ Config:", err)
		return exitErr(exitConfigError, err)
	}
	if cfg.Crate.PairingToken == "" || cfg.Crate.Salt == "" || cfg.Crate.CapabilityNonce == "" {
		fmt.Fprintln(os.Stderr,
			"✗ Config: this daemon hasn't been paired yet — run `crate-agent pair` first")
		return exitErr(exitConfigError, errors.New("not paired"))
	}

	pidPath, _ := cmd.Flags().GetString("pidfile")
	if pidPath == "" {
		p, perr := pidfile.DefaultPath()
		if perr != nil {
			return exitErr(exitConfigError, perr)
		}
		pidPath = p
	}

	if err := pidfile.Create(pidPath); err != nil {
		if errors.Is(err, pidfile.ErrAlreadyRunning) {
			fmt.Fprintln(os.Stderr, "✗", err)
			return exitErr(exitAlreadyRunning, err)
		}
		return exitErr(exitGeneric, err)
	}
	defer func() { _ = pidfile.Remove(pidPath) }()

	// --- Read passphrase --------------------------------------------------
	passStdin, _ := cmd.Flags().GetBool("passphrase-stdin")
	passEnv, _ := cmd.Flags().GetString("passphrase-env")
	passphrase, err := obtainPassphrase(passStdin, passEnv, "Folder passphrase: ")
	if err != nil {
		return exitErr(exitGeneric, err)
	}
	if passphrase == "" {
		return exitErr(exitGeneric, errors.New("passphrase is empty"))
	}

	// --- Decrypt capability ----------------------------------------------
	salt, err := base64.StdEncoding.DecodeString(cfg.Crate.Salt)
	if err != nil {
		return exitErr(exitConfigError, fmt.Errorf("salt b64: %w", err))
	}
	nonce, err := base64.StdEncoding.DecodeString(cfg.Crate.CapabilityNonce)
	if err != nil {
		return exitErr(exitConfigError, fmt.Errorf("capability_nonce b64: %w", err))
	}
	sealed, err := base64.StdEncoding.DecodeString(cfg.Crate.PairingToken)
	if err != nil {
		return exitErr(exitConfigError, fmt.Errorf("pairing_token b64: %w", err))
	}
	masterKey := kdf.DeriveMasterKey(passphrase, salt)
	// Keep the passphrase reachable for the reconciliation step below
	// (re-derive master key if the canonical salt differs from local).
	// Cleared after reconciliation completes.
	passphraseForReconcile := passphrase
	passphrase = "" // drop the early-pipeline reference

	capabilityBytes, err := sdkcrypto.Open(masterKey, nonce, sealed, nil)
	if err != nil {
		// Wrong passphrase is the most likely cause.
		zeroBytes(masterKey)
		fmt.Fprintln(os.Stderr,
			"✗ Capability decrypt failed — is the passphrase correct?")
		return exitErr(exitGeneric, err)
	}
	// liveCapability is the base64-encoded macaroon the syncer presents on
	// every Hub request. refresh.Runner updates this in-place on success.
	liveCapability := base64.StdEncoding.EncodeToString(capabilityBytes)
	// masterKey stays in memory for the daemon's lifetime so refresh can
	// re-encrypt without re-prompting; zeroed on shutdown.
	defer zeroBytes(masterKey)

	// --- Open state DB ----------------------------------------------------
	statePath := cfg.Agent.StateDB
	if statePath == "" {
		statePath = state.DefaultPath(cfg.Crate.LocalPath)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		return exitErr(exitConfigError, fmt.Errorf("mkdir state dir: %w", err))
	}
	store, err := state.Open(statePath)
	if err != nil {
		return exitErr(exitGeneric, err)
	}
	defer func() { _ = store.Close() }()

	// --- Watcher ----------------------------------------------------------
	if err := os.MkdirAll(cfg.Crate.LocalPath, 0o700); err != nil {
		return exitErr(exitConfigError, fmt.Errorf("mkdir local_path: %w", err))
	}
	ignorePath := filepath.Join(cfg.Crate.LocalPath, ".crateignore")
	w, err := watcher.New(watcher.Options{
		Root:       cfg.Crate.LocalPath,
		IgnoreFile: ignorePath,
	})
	if err != nil {
		return exitErr(exitGeneric, err)
	}
	defer func() { _ = w.Close() }()

	// --- HTTP client -----------------------------------------------------
	// For a crate-carrier the "capability" decrypted above IS the Worker's
	// shared secret; the client signs every request with it and ignores
	// the per-call capability argument.
	client := httpc.NewFor(cfg.Crate.TransportType, cfg.Crate.TransportEndpoint, string(capabilityBytes))
	// The daemon's capability carries `device-id == <daemon_pubkey>` from
	// the pair-mint flow. Extract it and tell the client to send the
	// matching X-Fabric-Device-Id header on every authenticated request,
	// so the Hub's strict caveat-binding mode (private-mesh PR #5) is
	// satisfied. Failure here is non-fatal: the daemon proceeds without
	// the header, which the Hub accepts in lax mode (the default today).
	if did := deviceIDFromCapability(capabilityBytes); did != "" {
		client.SetDeviceID(did)
	}

	// --- Salt reconciliation (M3 piece 7) --------------------------------
	// Forward-compatible: the browser may not have written .crate/crate.json
	// yet, in which case the reconciler returns ActionAbsent and the daemon
	// proceeds with its local salt. When the browser DOES write the file,
	// the next start aligns the master key with the canonical salt.
	//
	// v1.1: reconcile additionally unwraps the content key (NewPayloadMasterKey).
	// The capability KEK (masterKey) stays distinct from the payload master
	// key (payloadKey, declared just below). For v1.0 vaults the two are the
	// same key; payloadKey aliases masterKey.
	var payloadKey []byte
	{
		reconCtx, reconCancel := context.WithTimeout(cmd.Context(), 30*time.Second)
		res := cratejson.Reconcile(reconCtx, cratejson.ReconcileInput{
			CfgPath:          cfgPath,
			Cfg:              cfg,
			Passphrase:       passphraseForReconcile,
			CurrentMasterKey: masterKey,
			CapabilityBytes:  capabilityBytes,
			Hub:              client,
			Capability:       liveCapability,
			Logger:           slog.Default(),
		})
		reconCancel()
		switch res.Action {
		case cratejson.ActionReconciled:
			// Swap in the new master key; zero the old one.
			zeroBytes(masterKey)
			masterKey = res.NewMasterKey
			slog.Info("master key re-derived from canonical salt")
		case cratejson.ActionAbsent, cratejson.ActionAlreadyCanonical, cratejson.ActionFailed:
			// Nothing to do.
		}
		if res.NewPayloadMasterKey != nil {
			// v1.1 vault: distinct payload key (unwrapped content key from
			// passphrase_wrap). Schedule zeroing on shutdown.
			payloadKey = res.NewPayloadMasterKey
			defer zeroBytes(payloadKey)
		}
	}
	if payloadKey == nil {
		// v1.0 vault (or v1.1 reconciliation failed): payload key == capability
		// KEK == masterKey. Same backing array; masterKey's defer covers it.
		payloadKey = masterKey
	}
	// Now that reconciliation is done, the plaintext capability + passphrase
	// can be wiped — the syncer holds the base64-encoded liveCapability for
	// future Hub calls, and the refresh runner re-encrypts via masterKey.
	zeroBytes(capabilityBytes)
	passphraseForReconcile = ""

	// --- Shared M3 manifest + master-key references ----------------------
	// Both the puller and the syncer mutate the in-memory manifest; the
	// refresh runner may rotate the master key. A single mutex guards the
	// manifest. M6.x adds two more shared fields — manifestETag (for
	// If-Match conditional PUTs) and lastFlushedEventCount (snapshot for
	// replay-on-412). The puller updates these on each successful pull;
	// the syncer reads + updates them on each PUT.
	sharedManifest := manifest.New()
	sharedManifestMu := &sync.Mutex{}
	sharedManifestETag := ""
	sharedLastFlushedEventCount := 0
	// sharedCapabilityMu guards the live capability pointer that the
	// refresh runner writes and the syncer/puller read. Closes the Go
	// data race flagged in the 2026-05 security audit (finding M1).
	sharedCapabilityMu := &sync.RWMutex{}

	// --- Sync loop -------------------------------------------------------
	syn, err := syncer.New(syncer.Config{
		LocalPath:                cfg.Crate.LocalPath,
		BucketID:                 cfg.Crate.BucketID,
		CapabilityRef:            &liveCapability,
		CapabilityMu:             sharedCapabilityMu,
		MasterKeyRef:             &payloadKey,
		ManifestRef:              sharedManifest,
		ManifestMu:               sharedManifestMu,
		ManifestETagRef:          &sharedManifestETag,
		LastFlushedEventCountRef: &sharedLastFlushedEventCount,
		Hub:                      client,
		Watcher:                  w,
		State:                    store,
		Logger:                   slog.Default(),
	})
	if err != nil {
		return exitErr(exitGeneric, err)
	}

	// --- Refresh loop ----------------------------------------------------
	ref, err := refresh.New(refresh.Config{
		CfgPath:       cfgPath,
		Cfg:           cfg,
		MasterKey:     masterKey,
		Hub:           client,
		CapabilityRef: &liveCapability,
		CapabilityMu:  sharedCapabilityMu,
		Logger:        slog.Default(),
	})
	if err != nil {
		return exitErr(exitGeneric, err)
	}

	// --- Pull loop (M3 — manifest-as-source-of-truth) --------------------
	pul, err := puller.New(puller.Config{
		LocalPath:                cfg.Crate.LocalPath,
		BucketID:                 cfg.Crate.BucketID,
		CapabilityRef:            &liveCapability,
		CapabilityMu:             sharedCapabilityMu,
		MasterKeyRef:             &payloadKey,
		ManifestRef:              sharedManifest,
		ManifestMu:               sharedManifestMu,
		ManifestETagRef:          &sharedManifestETag,
		LastFlushedEventCountRef: &sharedLastFlushedEventCount,
		Hub:                      client,
		State:                    store,
		Logger:                   slog.Default(),
	})
	if err != nil {
		return exitErr(exitGeneric, err)
	}

	// --- Signal handling -------------------------------------------------
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		slog.Info("received shutdown signal; draining…")
		cancel()
	}()

	// --- Run --------------------------------------------------------------
	fmt.Printf("✓ crate-agent running\n")
	fmt.Printf("  Folder:    %s\n", cfg.Crate.LocalPath)
	fmt.Printf("  Bucket:    %s\n", cfg.Crate.BucketID)
	fmt.Printf("  Transport: %s\n", cfg.Crate.TransportEndpoint)
	fmt.Printf("  State DB:  %s\n", statePath)
	fmt.Printf("  PID file:  %s\n", pidPath)
	fmt.Println("  (Send SIGTERM or Ctrl-C to stop.)")

	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); _ = w.Run(ctx) }()
	go func() { defer wg.Done(); _ = syn.Run(ctx) }()
	go func() { defer wg.Done(); ref.Run(ctx) }()
	go func() { defer wg.Done(); pul.Run(ctx) }()
	wg.Wait()

	fmt.Println("✓ stopped cleanly")
	return nil
}

// deviceIDFromCapability parses the daemon's capability macaroon and
// returns the value of the `device-id == <X>` caveat, or "" if the
// macaroon does not carry that caveat (unexpected for a pair-minted
// daemon capability, but should not crash the daemon).
func deviceIDFromCapability(macBytes []byte) string {
	g, err := grant.Parse(macBytes)
	if err != nil {
		return ""
	}
	const prefix = "device-id == "
	for _, c := range g.Caveats {
		if strings.HasPrefix(c, prefix) {
			return strings.TrimSpace(c[len(prefix):])
		}
	}
	return ""
}

// obtainPassphrase reads the passphrase from stdin / env / interactive
// prompt — same precedence as `pair`.
func obtainPassphrase(stdinMode bool, envVar, prompt string) (string, error) {
	if stdinMode {
		line, err := readLine(bufio.NewReader(os.Stdin))
		if err != nil {
			return "", fmt.Errorf("read passphrase from stdin: %w", err)
		}
		return line, nil
	}
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			return v, nil
		}
	}
	return promptPassphrase(prompt)
}
