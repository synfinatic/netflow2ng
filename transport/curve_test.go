package transport

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	zmq "github.com/pebbe/zmq4"
)

// ntopng's built-in default private key (DEFAULT_ZMQ_ENCRYPTION_PRIV_KEY in
// include/ntop_defines.h). Only used here as a known-good Z85 sample.
const testNtopngDefaultPrivKey = "=m8rLxEcVs:*!M6x0iWW{)i$uwN9.:[5-3:NCIDY"

func TestValidateZ85Key_Valid(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"ntopng built-in public key", DefaultNtopngPublicKey},
		{"ntopng built-in private key", testNtopngDefaultPrivKey},
		{"all digits", strings.Repeat("0123456789", 4)},
		{"mixed case letters", strings.Repeat("abcdWXYZ12", 4)},
		{"punctuation from the Z85 alphabet", strings.Repeat(".-:+=^!/", 5)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateZ85Key(c.key); err != nil {
				t.Errorf("ValidateZ85Key(%q) returned unexpected error: %v", c.key, err)
			}
		})
	}
}

func TestValidateZ85Key_Invalid(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"empty", ""},
		{"one char short", strings.Repeat("a", 39)},
		{"one char long", strings.Repeat("a", 41)},
		// 12 chars is not a multiple of 5, the length that makes zmq.Z85decode
		// panic. Validation must reject it cleanly instead.
		{"length not a multiple of five", strings.Repeat("a", 12)},
		{"correct length but multiple of five", strings.Repeat("a", 45)},
		{"non-Z85 character (quote)", strings.Repeat("a", 39) + `"`},
		{"non-Z85 character (backslash)", strings.Repeat("a", 39) + `\`},
		{"non-Z85 character (space)", strings.Repeat("a", 39) + " "},
		{"non-Z85 character (semicolon)", "a;" + strings.Repeat("a", 38)},
		{"non-ASCII rune", strings.Repeat("a", 39) + "é"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := ValidateZ85Key(c.key); err == nil {
				t.Errorf("ValidateZ85Key(%q) returned nil, want an error", c.key)
			}
		})
	}
}

// TestZ85Alphabet_Complete guards against a typo in the alphabet constant: a
// dropped or duplicated character would silently reject valid keys.
func TestZ85Alphabet_Complete(t *testing.T) {
	if len(z85Alphabet) != 85 {
		t.Errorf("z85Alphabet has %d characters, want 85", len(z85Alphabet))
	}
	seen := map[rune]bool{}
	for _, c := range z85Alphabet {
		if seen[c] {
			t.Errorf("z85Alphabet contains duplicate character %q", c)
		}
		seen[c] = true
	}
}

// --- ResolveEncryption ---

// writeKeyFile writes contents to a file in a fresh temp dir and returns its path.
func writeKeyFile(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "zmq-key.pub")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("unable to write test key file: %v", err)
	}
	return path
}

func TestResolveEncryption_Disabled(t *testing.T) {
	// Disabling wins even when keys are supplied, so that a user debugging an
	// old ntopng doesn't have to unset their key flags first.
	cfg, err := ResolveEncryption(true, DefaultNtopngPublicKey, "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg != nil {
		t.Errorf("expected nil config when encryption is disabled, got %+v", cfg)
	}
}

func TestResolveEncryption_NoInputUsesBuiltinDefault(t *testing.T) {
	cfg, err := ResolveEncryption(false, "", "", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected a config, got nil")
	}
	if cfg.ServerKey != DefaultNtopngPublicKey {
		t.Errorf("ServerKey = %q, want the built-in default %q", cfg.ServerKey, DefaultNtopngPublicKey)
	}
	if !cfg.UsingDefaultKey {
		t.Error("UsingDefaultKey = false, want true when no key was configured")
	}
	if cfg.ClientPrivKey != "" {
		t.Errorf("ClientPrivKey = %q, want empty (ephemeral keypair)", cfg.ClientPrivKey)
	}
}

func TestResolveEncryption_ExplicitKeyBeatsKeyFile(t *testing.T) {
	fileKey := strings.Repeat("0123456789", 4)
	path := writeKeyFile(t, fileKey)

	cfg, err := ResolveEncryption(false, DefaultNtopngPublicKey, path, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerKey != DefaultNtopngPublicKey {
		t.Errorf("ServerKey = %q, want the explicit key %q", cfg.ServerKey, DefaultNtopngPublicKey)
	}
	// The explicit key happens to equal the built-in default here, but it was
	// supplied deliberately, so no "configure a key" warning is warranted.
	if cfg.UsingDefaultKey {
		t.Error("UsingDefaultKey = true, want false when a key was supplied explicitly")
	}
}

func TestResolveEncryption_KeyFileBeatsBuiltinDefault(t *testing.T) {
	fileKey := strings.Repeat("abcdWXYZ12", 4)
	path := writeKeyFile(t, fileKey)

	cfg, err := ResolveEncryption(false, "", path, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerKey != fileKey {
		t.Errorf("ServerKey = %q, want the key file contents %q", cfg.ServerKey, fileKey)
	}
	if cfg.UsingDefaultKey {
		t.Error("UsingDefaultKey = true, want false when a key file was supplied")
	}
}

func TestResolveEncryption_KeyFileWhitespaceTrimmed(t *testing.T) {
	// ntopng writes zmq-key.pub with no trailing newline, but a user editing it
	// by hand or piping it through a shell usually adds one.
	fileKey := strings.Repeat("abcdWXYZ12", 4)
	path := writeKeyFile(t, "  "+fileKey+"\n")

	cfg, err := ResolveEncryption(false, "", path, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ServerKey != fileKey {
		t.Errorf("ServerKey = %q, want the trimmed key %q", cfg.ServerKey, fileKey)
	}
}

func TestResolveEncryption_ClientPrivKeyPassedThrough(t *testing.T) {
	clientKey := strings.Repeat("abcdWXYZ12", 4)

	cfg, err := ResolveEncryption(false, "", "", clientKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientPrivKey != clientKey {
		t.Errorf("ClientPrivKey = %q, want %q", cfg.ClientPrivKey, clientKey)
	}
}

func TestResolveEncryption_Errors(t *testing.T) {
	validKey := strings.Repeat("abcdWXYZ12", 4)
	missingPath := filepath.Join(t.TempDir(), "does-not-exist.pub")
	garbagePath := writeKeyFile(t, "this is not a key")
	emptyPath := writeKeyFile(t, "")

	cases := []struct {
		name       string
		key        string
		keyFile    string
		clientPriv string
		wantSubstr string
	}{
		{"invalid explicit key", "BADKEY", "", "", "BADKEY"},
		{"missing key file", "", missingPath, "", missingPath},
		{"garbage key file contents", "", garbagePath, "", garbagePath},
		{"empty key file", "", emptyPath, "", emptyPath},
		{"invalid client private key", validKey, "", "BADKEY", "BADKEY"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := ResolveEncryption(false, c.key, c.keyFile, c.clientPriv)
			if err == nil {
				t.Fatalf("expected an error, got config %+v", cfg)
			}
			if cfg != nil {
				t.Errorf("expected nil config alongside the error, got %+v", cfg)
			}
			// The message must name the offending input so the user knows which
			// flag to fix.
			if !strings.Contains(err.Error(), c.wantSubstr) {
				t.Errorf("error %q does not mention %q", err.Error(), c.wantSubstr)
			}
		})
	}
}

// --- EncryptionConfig.apply ---

// newCurveTestSocket returns an unbound PUB socket, skipping the test when the
// linked libzmq has no CURVE support (built without libsodium).
func newCurveTestSocket(t *testing.T) *zmq.Socket {
	t.Helper()
	if !zmq.HasCurve() {
		t.Skip("libzmq built without CURVE support")
	}
	ctx, err := zmq.NewContext()
	if err != nil {
		t.Fatalf("unable to create ZMQ context: %v", err)
	}
	sock, err := ctx.NewSocket(zmq.PUB)
	if err != nil {
		t.Fatalf("unable to create ZMQ socket: %v", err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	return sock
}

func TestEncryptionConfig_Apply_SetsServerKey(t *testing.T) {
	sock := newCurveTestSocket(t)
	cfg := &EncryptionConfig{ServerKey: DefaultNtopngPublicKey}

	if err := cfg.apply(sock); err != nil {
		t.Fatalf("apply() returned unexpected error: %v", err)
	}

	got, err := sock.GetCurveServerkeyZ85()
	if err != nil {
		t.Fatalf("GetCurveServerkeyZ85() failed: %v", err)
	}
	if got != DefaultNtopngPublicKey {
		t.Errorf("ZMQ_CURVE_SERVERKEY = %q, want %q", got, DefaultNtopngPublicKey)
	}
}

func TestEncryptionConfig_Apply_GeneratesEphemeralClientKey(t *testing.T) {
	cfg := &EncryptionConfig{ServerKey: DefaultNtopngPublicKey}

	first := newCurveTestSocket(t)
	if err := cfg.apply(first); err != nil {
		t.Fatalf("apply() returned unexpected error: %v", err)
	}
	firstPub, err := first.GetCurvePublickeykeyZ85()
	if err != nil {
		t.Fatalf("GetCurvePublickeykeyZ85() failed: %v", err)
	}
	if err := ValidateZ85Key(firstPub); err != nil {
		t.Errorf("generated client public key %q is not a valid Z85 key: %v", firstPub, err)
	}

	second := newCurveTestSocket(t)
	if err := cfg.apply(second); err != nil {
		t.Fatalf("apply() returned unexpected error: %v", err)
	}
	secondPub, err := second.GetCurvePublickeykeyZ85()
	if err != nil {
		t.Fatalf("GetCurvePublickeykeyZ85() failed: %v", err)
	}

	if firstPub == secondPub {
		t.Errorf("expected a fresh client keypair per apply(), got %q twice", firstPub)
	}
}

func TestEncryptionConfig_Apply_PinnedClientKeyIsStable(t *testing.T) {
	if !zmq.HasCurve() {
		t.Skip("libzmq built without CURVE support")
	}
	_, clientPriv, err := zmq.NewCurveKeypair()
	if err != nil {
		t.Fatalf("unable to generate a test keypair: %v", err)
	}
	cfg := &EncryptionConfig{ServerKey: DefaultNtopngPublicKey, ClientPrivKey: clientPriv}

	// The public key must be *derived* from the pinned secret key, so it is the
	// same on every socket -- not a freshly generated pair.
	var pubs []string
	for i := 0; i < 2; i++ {
		sock := newCurveTestSocket(t)
		if err := cfg.apply(sock); err != nil {
			t.Fatalf("apply() returned unexpected error: %v", err)
		}
		pub, err := sock.GetCurvePublickeykeyZ85()
		if err != nil {
			t.Fatalf("GetCurvePublickeykeyZ85() failed: %v", err)
		}
		pubs = append(pubs, pub)
	}

	if pubs[0] != pubs[1] {
		t.Errorf("pinned client key produced different public keys: %q vs %q", pubs[0], pubs[1])
	}
}

func TestEncryptionConfig_Apply_NilIsNoOp(t *testing.T) {
	sock := newCurveTestSocket(t)
	var cfg *EncryptionConfig

	if err := cfg.apply(sock); err != nil {
		t.Fatalf("apply() on a nil config returned unexpected error: %v", err)
	}

	// A socket with no CURVE configuration reports the NULL mechanism.
	mech, err := sock.GetMechanism()
	if err != nil {
		t.Fatalf("GetMechanism() failed: %v", err)
	}
	if mech != zmq.NULL {
		t.Errorf("mechanism = %v, want NULL (cleartext) for a nil config", mech)
	}
}
