package meshcore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
)

// KeyFormat identifies one of the private-key serializations found in
// the MeshCore ecosystem. The expansion seed → expanded is one-way
// (SHA-512 + clamp): a seed can always be converted to the firmware
// format, an expanded key can never be turned back into a seed.
type KeyFormat int

const (
	// KeyFormatSeed is a bare 32-byte Ed25519 seed — what openHop
	// (PyNaCl), the Go standard library and libsodium generate from.
	KeyFormatSeed KeyFormat = iota + 1
	// KeyFormatExpanded is the 64-byte orlp/ed25519 layout the MeshCore
	// firmware stores and exports (prv.key): clamped scalar ‖ signing
	// prefix, the two halves of SHA-512(seed).
	KeyFormatExpanded
	// KeyFormatSeedPub is the 64-byte seed ‖ public-key layout of Go's
	// ed25519.PrivateKey and libsodium's crypto_sign secret key.
	KeyFormatSeedPub
)

// String implements fmt.Stringer.
func (f KeyFormat) String() string {
	switch f {
	case KeyFormatSeed:
		return "seed"
	case KeyFormatExpanded:
		return "expanded"
	case KeyFormatSeedPub:
		return "seed+pub"
	default:
		return fmt.Sprintf("KeyFormat(%d)", int(f))
	}
}

// ErrUnknownKeyFormat reports bytes that match no known private-key
// serialization.
var ErrUnknownKeyFormat = errors.New("meshcore: unrecognised private key format")

// ParsePrivateKey loads a private key in any of the ecosystem's
// serializations, detecting which one it got:
//
//   - 32 bytes: a seed;
//   - 64 bytes whose second half is the public key derived from the
//     first half taken as a seed: seed ‖ pub (Go/libsodium);
//   - 64 bytes otherwise: the firmware's expanded format.
//
// The two 64-byte layouts are distinguished by that derivation check —
// a collision would require the expanded key's prefix half to equal a
// derived public key, which random halves hit with probability 2^-256.
func ParsePrivateKey(key []byte) (*LocalIdentity, KeyFormat, error) {
	switch len(key) {
	case SeedSize:
		li, err := LocalIdentityFromSeed(key)
		return li, KeyFormatSeed, err
	case PrvKeySize:
		std := ed25519.NewKeyFromSeed(key[:SeedSize])
		if pub := std[SeedSize:]; string(pub) == string(key[SeedSize:]) {
			li, err := LocalIdentityFromSeed(key[:SeedSize])
			return li, KeyFormatSeedPub, err
		}
		li, err := LocalIdentityFromKeys(key, nil)
		return li, KeyFormatExpanded, err
	default:
		return nil, 0, ErrUnknownKeyFormat
	}
}

// Seed returns the 32-byte seed when this identity was built from one
// (generated, or loaded from a seed-bearing format), and nil for
// identities loaded from an expanded key: the expansion is one-way, so
// firmware-exported keys have no recoverable seed.
func (li *LocalIdentity) Seed() []byte {
	if li.seed == nil {
		return nil
	}
	return append([]byte(nil), li.seed...)
}

// StdPrivateKey returns the identity in Go's ed25519.PrivateKey layout
// (seed ‖ pub). It reports false when the seed is unknown — an
// expanded firmware key cannot be represented in seed-bearing formats.
func (li *LocalIdentity) StdPrivateKey() (ed25519.PrivateKey, bool) {
	if li.seed == nil {
		return nil, false
	}
	return ed25519.NewKeyFromSeed(li.seed), true
}

// FirmwareImportable reports whether the firmware would accept this
// identity's keypair: validatePrivateKey refuses public keys starting
// 0x00 or 0xFF (reserved prefixes).
func (li *LocalIdentity) FirmwareImportable() bool {
	return li.PubKey[0] != 0x00 && li.PubKey[0] != 0xFF
}

// PubKeyPrefixMatcher builds a MineIdentity predicate from a hex
// prefix, e.g. "f00d" or "ca7" — an odd nibble count matches the high
// nibble of the trailing byte. Prefixes forcing a reserved first byte
// (00 or ff) are refused: the firmware would not import such a key.
func PubKeyPrefixMatcher(hexPrefix string) (func(pub []byte) bool, error) {
	if hexPrefix == "" {
		return nil, fmt.Errorf("%w: empty prefix", ErrBadPublicKey)
	}
	odd := len(hexPrefix)%2 == 1
	full, err := hex.DecodeString(hexPrefix + map[bool]string{true: "0", false: ""}[odd])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadPublicKey, err)
	}
	if len(full) > PubKeySize {
		return nil, fmt.Errorf("%w: prefix longer than a public key", ErrBadPublicKey)
	}
	if len(hexPrefix) >= 2 && (full[0] == 0x00 || full[0] == 0xFF) {
		return nil, fmt.Errorf("%w: prefix %02x is reserved by the firmware", ErrBadPublicKey, full[0])
	}

	wholeBytes := len(full)
	if odd {
		wholeBytes--
	}
	return func(pub []byte) bool {
		if string(pub[:wholeBytes]) != string(full[:wholeBytes]) {
			return false
		}
		return !odd || pub[wholeBytes]>>4 == full[wholeBytes]>>4
	}, nil
}

// MineIdentity generates random identities until match(pub) returns
// true, fanning out over all CPUs. Only firmware-importable keys are
// considered (see FirmwareImportable). It returns the found identity
// and the number of candidates tried; cancel ctx to bound the search.
//
// Cost scales as 16^nibbles: a 4-hex-char prefix takes tens of
// thousands of attempts, 6 chars millions.
func MineIdentity(ctx context.Context, match func(pub []byte) bool) (*LocalIdentity, uint64, error) {
	var (
		attempts atomic.Uint64
		found    atomic.Pointer[LocalIdentity]
	)
	inner, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Go(func() {
			seed := make([]byte, SeedSize)
			for inner.Err() == nil {
				if _, err := rand.Read(seed); err != nil {
					panic("meshcore: crypto/rand failed: " + err.Error())
				}
				li, err := LocalIdentityFromSeed(seed)
				if err != nil {
					continue
				}
				attempts.Add(1)
				if li.FirmwareImportable() && match(li.PubKey[:]) {
					found.CompareAndSwap(nil, li)
					cancel()
					return
				}
			}
		})
	}
	wg.Wait()

	if li := found.Load(); li != nil {
		return li, attempts.Load(), nil
	}
	// The workers only stop on a found key (handled above) or ctx
	// cancellation, so the search ended because ctx did.
	return nil, attempts.Load(), ctx.Err()
}
