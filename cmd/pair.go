// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	"github.com/NakliTechie/crate-agent/internal/state"
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
	pairCmd.Flags().String("carrier", "", "Pair with a crate-carrier Worker at this https:// URL instead of redeeming a token; the first stdin/prompt line is then the Worker's CARRIER_SECRET")
}

func runPair(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	idPath, _ := cmd.Flags().GetString("identity")
	folderName, _ := cmd.Flags().GetString("name")
	localPath, _ := cmd.Flags().GetString("local-path")
	tokenStdin, _ := cmd.Flags().GetBool("token-stdin")
	passStdin, _ := cmd.Flags().GetBool("passphrase-stdin")
	skipDoctor, _ := cmd.Flags().GetBool("skip-doctor")
	carrierURL, _ := cmd.Flags().GetString("carrier")

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

	// --- Step 1: read the CRATE-PAIR token (or the carrier secret) ------
	stdin := bufio.NewReader(os.Stdin)
	carrier := carrierURL != ""
	if carrier {
		u, perr := url.Parse(carrierURL)
		if perr != nil || u.Scheme != "https" || u.Host == "" {
			return exitErr(exitConfigError, fmt.Errorf("--carrier must be an https:// URL, got %q", carrierURL))
		}
		carrierURL = strings.TrimRight(carrierURL, "/")
	}
	var rawToken string
	if tokenStdin {
		rawToken, err = readLine(stdin)
		if err != nil {
			return exitErr(exitGeneric, fmt.Errorf("read token from stdin: %w", err))
		}
	} else if carrier {
		rawToken, err = promptPassphrase("Carrier secret (CARRIER_SECRET): ")
		if err != nil {
			return exitErr(exitGeneric, err)
		}
	} else {
		fmt.Print("Paste pairing token: ")
		rawToken, err = readLine(stdin)
		if err != nil {
			return exitErr(exitGeneric, fmt.Errorf("read token: %w", err))
		}
	}

	// --- Step 2: decode + validate -----------------------------------
	// A carrier has no token: the secret IS the capability, the Worker
	// URL IS the transport, and there is nothing to redeem.
	var tok *pairing.Token
	if carrier {
		if strings.TrimSpace(rawToken) == "" {
			return exitErr(exitGeneric, errors.New("carrier secret is empty"))
		}
		tok = &pairing.Token{TransportEndpoint: carrierURL, TransportType: httpc.TransportCarrier, Secret: strings.TrimSpace(rawToken)}
	} else {
		tok, err = pairing.Decode(rawToken)
		if err != nil {
			fmt.Fprintln(os.Stderr, "✗", pairing.RecoveryMessage(err))
			return exitErr(exitGeneric, err)
		}
		if err := pairing.Validate(tok, time.Now()); err != nil {
			fmt.Fprintln(os.Stderr, "✗", pairing.RecoveryMessage(err))
			return exitErr(exitGeneric, err)
		}
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
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	var result *pairing.RedeemResult
	if carrier {
		// Prove the secret against the Worker before writing anything:
		// HEAD of crate.json is 200 or 404 with the right secret, 401 without.
		probe := httpc.NewCarrier(tok.TransportEndpoint, tok.Secret)
		hr, herr := probe.HeadObject(ctx, "carrier", ".crate/crate.json", "")
		if herr != nil {
			fmt.Fprintln(os.Stderr, "✗ Carrier unreachable:", herr)
			return exitErr(exitTransportDown, herr)
		}
		if hr.Status == http.StatusUnauthorized {
			err = errors.New("carrier rejected the secret (401) — it must match the Worker's CARRIER_SECRET")
			fmt.Fprintln(os.Stderr, "✗", err)
			return exitErr(exitGeneric, err)
		}
		if hr.Status != http.StatusOK && hr.Status != http.StatusNotFound {
			err = fmt.Errorf("carrier HEAD .crate/crate.json returned HTTP %d", hr.Status)
			fmt.Fprintln(os.Stderr, "✗", err)
			return exitErr(exitGeneric, err)
		}
		result = &pairing.RedeemResult{Capability: []byte(tok.Secret), BucketReference: "carrier"}
	} else {
		client := httpc.New(tok.TransportEndpoint)
		result, err = pairing.Phase3(ctx, client, tok.Secret, daemonPubkey, fp)
	}
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
	// State DB lives inside the crate folder by default (state.DefaultPath);
	// removing the crate folder also removes the daemon's local state. The
	// user can override via agent.state_db in the config.
	cfg := &config.Config{
		Agent: config.AgentSection{
			LogLevel: "info",
			LogPath:  filepath.Join(home, ".local/share/nakli/crate-agent.log"),
			StateDB:  state.DefaultPath(localPath),
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

	fmt.Println()
	fmt.Println("✓ Paired with", redactedEndpoint(tok.TransportEndpoint))
	fmt.Println("  Bucket:           ", result.BucketReference)
	fmt.Println("  Identity key:     ", idPath, "(mode 0600)")
	fmt.Println("  Config:           ", cfgPath, "(mode 0600)")
	if carrier {
		fmt.Println("  Capability expires: never (carrier secret; rotate CARRIER_SECRET on the Worker to revoke)")
	} else {
		fmt.Println("  Capability expires:", time.Unix(result.ExpiresAtUnix, 0).UTC().Format(time.RFC3339))
	}

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
