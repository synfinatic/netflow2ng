package transport

/*
 * CurveZMQ (CURVE) encryption support for the ZMQ transport.
 *
 * ntopng's ZMQ collector always takes the CURVE *server* role -- it sets
 * ZMQ_CURVE_SERVER together with its own secret key whether it binds or
 * connects (see ZMQUtils::setServerEncryptionKeys in ntopng's src/ZMQUtils.cpp).
 * netflow2ng is therefore the CURVE *client*: it sets ZMQ_CURVE_SERVERKEY to
 * ntopng's public key plus a client keypair of its own, exactly as nProbe does
 * with --zmq-encryption-key.
 */

import (
	"fmt"
	"os"
	"strings"

	zmq "github.com/pebbe/zmq4"
)

// DefaultNtopngPublicKey mirrors DEFAULT_ZMQ_ENCRYPTION_PUB_KEY from ntopng's
// include/ntop_defines.h. ntopng falls back to this built-in pair whenever the
// user hasn't configured a dedicated key, so it lets netflow2ng interoperate
// with a stock ntopng install out of the box.
const DefaultNtopngPublicKey = "+hO@^5%GQ]^H6=fim{?$i-eu^Qcgi0l1}I:dYFN{"

// z85Alphabet is the 85-character Z85 encoding alphabet from the ZeroMQ spec.
const z85Alphabet = "0123456789" +
	"abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	".-:+=^!/*?&<>()[]{}@%$#"

// z85KeyLen is the length of a Z85-encoded CURVE key (32 raw bytes -> 40 chars).
const z85KeyLen = 40

// ValidateZ85Key reports whether key is a well-formed Z85-encoded CURVE key.
//
// We check by hand rather than calling zmq.Z85decode, which panics when the
// input length isn't a multiple of 5. A bad key comes from the command line,
// so it must produce an error the user can read, not a stack trace.
func ValidateZ85Key(key string) error {
	if len(key) != z85KeyLen {
		return fmt.Errorf("invalid CURVE key: expected %d characters, got %d", z85KeyLen, len(key))
	}
	for i, c := range key {
		if !strings.ContainsRune(z85Alphabet, c) {
			return fmt.Errorf("invalid CURVE key: illegal character %q at position %d", c, i)
		}
	}
	return nil
}

// EncryptionConfig describes how netflow2ng authenticates to ntopng over CURVE.
type EncryptionConfig struct {
	// ServerKey is ntopng's CURVE public key (Z85).
	ServerKey string
	// ClientPrivKey pins netflow2ng's own CURVE secret key (Z85). Empty means a
	// fresh keypair is generated at startup, which is what nProbe does -- ntopng
	// installs no ZAP handler, so it does not authenticate client keys.
	ClientPrivKey string
	// UsingDefaultKey is true when ServerKey is ntopng's built-in default,
	// meaning no dedicated key was configured on either side.
	UsingDefaultKey bool
}

// ResolveEncryption turns the CLI/env inputs into an EncryptionConfig.
//
// It returns (nil, nil) when encryption is disabled. Otherwise the ntopng
// public key is taken from key, else from the contents of keyFile, else from
// ntopng's built-in default pair.
func ResolveEncryption(disable bool, key, keyFile, clientPriv string) (*EncryptionConfig, error) {
	if disable {
		return nil, nil
	}

	if clientPriv != "" {
		if err := ValidateZ85Key(clientPriv); err != nil {
			return nil, fmt.Errorf("client private key %q: %w", clientPriv, err)
		}
	}

	cfg := &EncryptionConfig{ClientPrivKey: clientPriv}

	switch {
	case key != "":
		if err := ValidateZ85Key(key); err != nil {
			return nil, fmt.Errorf("ntopng public key %q: %w", key, err)
		}
		cfg.ServerKey = key

	case keyFile != "":
		contents, err := os.ReadFile(keyFile) // #nosec G304 -- path is operator-supplied
		if err != nil {
			return nil, fmt.Errorf("unable to read ntopng public key file: %w", err)
		}
		fileKey := strings.TrimSpace(string(contents))
		if err := ValidateZ85Key(fileKey); err != nil {
			return nil, fmt.Errorf("ntopng public key file %s: %w", keyFile, err)
		}
		cfg.ServerKey = fileKey

	default:
		cfg.ServerKey = DefaultNtopngPublicKey
		cfg.UsingDefaultKey = true
	}

	return cfg, nil
}

// apply configures sock as a CURVE client talking to ntopng.
//
// This MUST be called before Bind()/Connect(): libzmq reads the CURVE options
// when the socket's transport is set up, and silently ignores them afterwards.
// A nil receiver is a no-op, which is the cleartext path.
func (e *EncryptionConfig) apply(sock *zmq.Socket) error {
	if e == nil {
		return nil
	}

	if !zmq.HasCurve() {
		return fmt.Errorf("this build of libzmq has no CURVE support: rebuild libzmq with libsodium, " +
			"or run with --zmq-disable-encryption (which requires ntopng --zmq-disable-encryption too)")
	}

	clientPub, clientPriv, err := e.clientKeypair()
	if err != nil {
		return err
	}

	// Setting ZMQ_CURVE_SERVERKEY is what puts the socket in the CURVE client
	// role, which is the role ntopng expects of a probe.
	if err := sock.SetCurveServerkey(e.ServerKey); err != nil {
		return fmt.Errorf("unable to set ntopng public key: %w", err)
	}
	if err := sock.SetCurvePublickey(clientPub); err != nil {
		return fmt.Errorf("unable to set client public key: %w", err)
	}
	if err := sock.SetCurveSecretkey(clientPriv); err != nil {
		return fmt.Errorf("unable to set client secret key: %w", err)
	}

	return nil
}

// clientKeypair returns netflow2ng's own CURVE keypair: the pinned one when
// ClientPrivKey is set, otherwise a freshly generated pair.
func (e *EncryptionConfig) clientKeypair() (pub, priv string, err error) {
	if e.ClientPrivKey != "" {
		pub, err = zmq.AuthCurvePublic(e.ClientPrivKey)
		if err != nil {
			return "", "", fmt.Errorf("unable to derive the public key from the client private key: %w", err)
		}
		return pub, e.ClientPrivKey, nil
	}

	pub, priv, err = zmq.NewCurveKeypair()
	if err != nil {
		return "", "", fmt.Errorf("unable to generate a client keypair: %w", err)
	}
	return pub, priv, nil
}
