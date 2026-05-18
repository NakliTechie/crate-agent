// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	sdkcrypto "github.com/NakliTechie/private-mesh/fabric-sdk-go/crypto"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/identity"
	"github.com/NakliTechie/crate-agent/internal/kdf"
	"github.com/NakliTechie/crate-agent/internal/pairing"
)

var pairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Redeem a CRATE-PAIR-… token from the browser",
	Long: `Phase 3 of crate-pairing-protocol-v1.0. The daemon decodes the token,
generates an ephemeral Ed25519 keypair, prompts for the folder passphrase,
posts to {transport_endpoint}/v1/pairing/redeem, receives a long-lived
capability, writes config TOML + identity key (0600), and runs doctor.

Interactive mode (default) prompts for the token and the passphrase.
Use --token-stdin and --passphrase-stdin (in that order) for scripting.`,
	RunE: runPair,
}

func init() {
	pairCmd.Flags().StringP("config", "c", "", "Path to crate-agent.toml to write (default: ~/.config/nakli/crate-agent.toml)")
	pairCmd.Flags().StringP("identity", "i", "", "Path to identity.key (FIF) to write (default: ~/.config/nakli/identity.key)")
	pairCmd.Flags().String("name", "personal", "Display name for the folder (stored in [crate].name)")
	pairCmd.Flags().String("local-path", "", "Local folder to sync (default: ~/crate)")
	pairCmd.Flags().Bool("token-stdin", false, "Read the CRATE-PAIR token from stdin (first line)")
	pairCmd.Flags().Bool("passphrase-stdin", false, "Read the passphrase from stdin (second line after token if --token-stdin, else first)")
	pairCmd.Flags().Bool("skip-doctor", false, "Skip the auto-doctor step at the end (testing only)")
}

func runPair(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	idPath, _ := cmd.Flags().GetString("identity")
	folderName, _ := cmd.Flags().GetString("name")
	localPath, _ := cmd.Flags().GetString("local-path")
	tokenStdin, _ := cmd.Flags().GetBool("token-stdin")
	passStdin, _ := cmd.Flags().GetBool("passphrase-stdin")
	skipDoctor, _ := cmd.Flags().GetBool("skip-doctor")

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗ Cannot resolve home directory:", err)
		return exitErr(exitConfigError, err)
	}
	if cfgPath == "" {
		cfgPath = filepath.Join(home, ".config/nakli/crate-agent.toml")
	}
	if idPath == "" {
		idPath = filepath.Join(home, ".config/nakli/identity.key")
	}
	if localPath == "" {
		localPath = filepath.Join(home, "crate")
	}

	// --- Step 1: read the CRATE-PAIR token ----------------------------
	stdin := bufio.NewReader(os.Stdin)
	var rawToken string
	if tokenStdin {
		rawToken, err = readLine(stdin)
		if err != nil {
			return exitErr(exitGeneric, fmt.Errorf("read token from stdin: %w", err))
		}
	} else {
		fmt.Print("Paste pairing token: ")
		rawToken, err = readLine(stdin)
		if err != nil {
			return exitErr(exitGeneric, fmt.Errorf("read token: %w", err))
		}
	}

	// --- Step 2: decode + validate -----------------------------------
	tok, err := pairing.Decode(rawToken)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗", pairing.RecoveryMessage(err))
		return exitErr(exitGeneric, err)
	}
	if err := pairing.Validate(tok, time.Now()); err != nil {
		fmt.Fprintln(os.Stderr, "✗", pairing.RecoveryMessage(err))
		return exitErr(exitGeneric, err)
	}

	// --- Step 3: generate ephemeral Ed25519 keypair -------------------
	pub, priv, err := identity.GenerateEphemeralKey()
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗ Keygen:", err)
		return exitErr(exitGeneric, err)
	}
	daemonPubkey := base64.RawURLEncoding.EncodeToString(pub)

	// --- Step 4: read folder passphrase ------------------------------
	var passphrase string
	if passStdin {
		passphrase, err = readLine(stdin)
		if err != nil {
			return exitErr(exitGeneric, fmt.Errorf("read passphrase from stdin: %w", err))
		}
	} else {
		passphrase, err = promptPassphrase("Folder passphrase: ")
		if err != nil {
			return exitErr(exitGeneric, err)
		}
	}
	if passphrase == "" {
		return exitErr(exitGeneric, errors.New("passphrase is empty"))
	}

	// --- Step 5–6: POST /v1/pairing/redeem ----------------------------
	fp := pairing.Fingerprint{
		Platform:     runtime.GOOS,
		Arch:         runtime.GOARCH,
		Hostname:     hostnameOrUnknown(),
		AgentVersion: binaryVersion,
	}
	client := httpc.New(tok.TransportEndpoint)
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	result, err := pairing.Phase3(ctx, client, tok.Secret, daemonPubkey, fp)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗", pairing.RecoveryMessage(err))
		// Per spec §"CLI commands" exit codes: 3 is reserved for
		// "transport unreachable". Everything else the Hub rejected
		// (token state, version, etc.) is a generic error.
		code := exitGeneric
		if pairing.IsCode(err, pairing.CodeTransportFailure) {
			code = exitTransportDown
		}
		return exitErr(code, err)
	}

	// --- Step 7: derive master key, encrypt capability ---------------
	salt, err := sdkcrypto.RandomBytes(kdf.SaltLen)
	if err != nil {
		return exitErr(exitGeneric, fmt.Errorf("salt: %w", err))
	}
	masterKey := kdf.DeriveMasterKey(passphrase, salt)
	nonce, err := sdkcrypto.RandomNonce()
	if err != nil {
		return exitErr(exitGeneric, fmt.Errorf("nonce: %w", err))
	}
	sealed, err := sdkcrypto.Seal(masterKey, nonce, result.Capability, nil)
	if err != nil {
		return exitErr(exitGeneric, fmt.Errorf("encrypt capability: %w", err))
	}

	// --- Step 8: build + write the FIF -------------------------------
	if _, err := identity.Write(idPath, folderName, pub, priv, passphrase); err != nil {
		fmt.Fprintln(os.Stderr, "✗ Identity write:", err)
		return exitErr(exitConfigError, err)
	}

	// --- Step 8: write config ----------------------------------------
	cfg := &config.Config{
		Agent: config.AgentSection{
			LogLevel: "info",
			LogPath:  filepath.Join(home, ".local/share/nakli/crate-agent.log"),
			StateDB:  filepath.Join(home, ".local/share/nakli/crate-agent.db"),
		},
		Identity: config.IdentitySection{Path: idPath},
		Crate: config.CrateSection{
			Name:              folderName,
			LocalPath:         localPath,
			TransportEndpoint: tok.TransportEndpoint,
			TransportType:     tok.TransportType,
			PairingToken:      base64.StdEncoding.EncodeToString(sealed),
			BucketID:          result.BucketReference,
			EncryptAtRest:     false,
			Salt:              base64.StdEncoding.EncodeToString(salt),
			CapabilityNonce:   base64.StdEncoding.EncodeToString(nonce),
			TransportPubkey:   base64.StdEncoding.EncodeToString(result.TransportPubkey),
			CapabilityExpires: result.ExpiresAtUnix,
		},
	}
	if err := config.Write(cfgPath, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "✗ Config write:", err)
		return exitErr(exitConfigError, err)
	}

	// --- Step 10: clear sensitive material from memory ---------------
	zeroBytes(masterKey)
	for i := range priv {
		priv[i] = 0
	}
	for i := range passphrase {
		_ = passphrase[i] // strings are immutable; cannot zero. Note this in docs.
	}

	expires := time.Unix(result.ExpiresAtUnix, 0).UTC().Format(time.RFC3339)
	fmt.Println()
	fmt.Println("✓ Paired with", redactedEndpoint(tok.TransportEndpoint))
	fmt.Println("  Bucket:           ", result.BucketReference)
	fmt.Println("  Identity key:     ", idPath, "(mode 0600)")
	fmt.Println("  Config:           ", cfgPath, "(mode 0600)")
	fmt.Println("  Capability expires:", expires)

	// --- Step 11: auto-doctor ---------------------------------------
	if skipDoctor {
		fmt.Println("⚠ Skipped final doctor run (--skip-doctor)")
		return nil
	}
	fmt.Println()
	fmt.Println("==> Running doctor")
	// The passphrase string is still valid here even though we tried to
	// zero it — strings in Go are immutable. We feed it directly; the
	// runtime drops references on return.
	if err := RunChecks(cmd.Context(), os.Stdout, os.Stderr, cfgPath, passphrase); err != nil {
		code := exitCodeFor(err)
		return exitErr(code, err)
	}
	return nil
}

// --- helpers -----------------------------------------------------------

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func promptPassphrase(prompt string) (string, error) {
	fmt.Print(prompt)
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// Fall back to plain stdin when not a TTY (e.g. piped input).
		line, err := readLine(bufio.NewReader(os.Stdin))
		return line, err
	}
	b, err := term.ReadPassword(fd)
	fmt.Println()
	if err != nil {
		return "", fmt.Errorf("read passphrase: %w", err)
	}
	return string(b), nil
}

func hostnameOrUnknown() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "unknown"
	}
	return h
}

// redactedEndpoint hides any embedded user-info in the transport URL
// for the success line. Practically never set, but defensive.
func redactedEndpoint(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User != nil {
		u.User = url.User(u.User.Username())
	}
	return u.Redacted()
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
