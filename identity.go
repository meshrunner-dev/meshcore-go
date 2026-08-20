package meshcore

import (
	"crypto/ed25519"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/curve25519"
)

// Identity errors.
var (
	ErrBadKeyLength = errors.New("meshcore: bad key length")
	ErrKeyMismatch  = errors.New("meshcore: public key does not match private key")
	ErrBadPublicKey = errors.New("meshcore: invalid public key point")
)

// Identity is a party in the mesh whose signatures can be verified: an
// Ed25519 public key. A node's hash, as used in packet paths and
// payload envelopes, is simply a prefix of this key.
//
// Reference: MeshCore src/Identity.{h,cpp}.
type Identity struct {
	PubKey [PubKeySize]byte
}

// IdentityFromBytes builds an Identity from a 32-byte public key.
func IdentityFromBytes(pub []byte) (Identity, error) {
	var id Identity
	if len(pub) != PubKeySize {
		return id, ErrBadKeyLength
	}
	copy(id.PubKey[:], pub)
	return id, nil
}

// Hash returns the first n bytes of the public key — the node hash the
// mesh uses to address and dedup. n must be in [0, PubKeySize]; it
// panics otherwise, like any out-of-range slice.
func (id Identity) Hash(n int) []byte {
	return append([]byte(nil), id.PubKey[:n]...)
}

// HashMatches reports whether the given hash bytes are a prefix of the
// public key.
func (id Identity) HashMatches(hash []byte) bool {
	if len(hash) > PubKeySize {
		return false
	}
	for i, b := range hash {
		if id.PubKey[i] != b {
			return false
		}
	}
	return true
}

// Verify checks an Ed25519 signature over message.
func (id Identity) Verify(sig, message []byte) bool {
	if len(sig) != SignatureSize {
		return false
	}
	return ed25519.Verify(id.PubKey[:], message, sig)
}

// LocalIdentity is an identity whose private key is held locally.
//
// The private key uses the reference firmware's expanded layout
// (orlp/ed25519): bytes 0-31 hold the clamped scalar, bytes 32-63 the
// signing prefix — both halves of SHA-512(seed). This is NOT the Go
// standard library layout (seed ‖ public key); identities exported
// from firmware or companion apps load directly with
// LocalIdentityFromKeys.
// The String/GoString redaction methods use value receivers on purpose
// — pointer receivers would leave fmt of a dereferenced copy printing
// the raw struct, private key included.
//
//nolint:recvcheck // see above: value receivers are load-bearing
type LocalIdentity struct {
	Identity

	prv  [PrvKeySize]byte
	seed []byte // retained when known; nil for expanded-key imports
}

// NewLocalIdentity generates a fresh identity from the given entropy
// source (typically crypto/rand.Reader). Public keys starting 0x00 or
// 0xFF are redrawn: the firmware reserves those prefixes and refuses
// to import such keypairs, and openHop regenerates the same way.
func NewLocalIdentity(rand io.Reader) (*LocalIdentity, error) {
	seed := make([]byte, SeedSize)
	for {
		if _, err := io.ReadFull(rand, seed); err != nil {
			return nil, err
		}
		li, err := LocalIdentityFromSeed(seed)
		if err != nil {
			return nil, err
		}
		if li.FirmwareImportable() {
			return li, nil
		}
	}
}

// LocalIdentityFromSeed expands a 32-byte seed exactly as the
// reference does: SHA-512, clamp the lower half into the scalar, keep
// the upper half as the signing prefix.
func LocalIdentityFromSeed(seed []byte) (*LocalIdentity, error) {
	if len(seed) != SeedSize {
		return nil, ErrBadKeyLength
	}
	h := sha512.Sum512(seed)
	h[0] &= 248
	h[31] &= 63
	h[31] |= 64

	li := &LocalIdentity{seed: append([]byte(nil), seed...)}
	copy(li.prv[:], h[:])
	pub, err := derivePub(li.prv[:32])
	if err != nil {
		return nil, err
	}
	copy(li.PubKey[:], pub)
	return li, nil
}

// LocalIdentityFromKeys loads an expanded 64-byte private key (and,
// optionally, its 32-byte public key; pass nil to re-derive it, as the
// reference does when restoring a private key alone). The scalar half
// must carry the Ed25519 clamp: every genuinely expanded key does, and
// rejecting the rest loudly beats silently deriving a public key the
// firmware (which multiplies the raw bytes) would disagree on.
func LocalIdentityFromKeys(prv, pub []byte) (*LocalIdentity, error) {
	if len(prv) != PrvKeySize {
		return nil, ErrBadKeyLength
	}
	if prv[0]&7 != 0 || prv[31]&0x80 != 0 || prv[31]&0x40 == 0 {
		return nil, fmt.Errorf("meshcore: %w: scalar half is not clamped", ErrUnknownKeyFormat)
	}
	li := &LocalIdentity{}
	copy(li.prv[:], prv)

	derived, err := derivePub(li.prv[:32])
	if err != nil {
		return nil, err
	}
	if pub == nil {
		copy(li.PubKey[:], derived)
		return li, nil
	}
	if len(pub) != PubKeySize {
		return nil, ErrBadKeyLength
	}
	copy(li.PubKey[:], pub)
	for i := range derived {
		if derived[i] != pub[i] {
			return nil, ErrKeyMismatch
		}
	}
	return li, nil
}

// PrvKey returns a copy of the expanded 64-byte private key.
func (li *LocalIdentity) PrvKey() []byte {
	return append([]byte(nil), li.prv[:]...)
}

// Sign produces an Ed25519 signature over message with the expanded
// private key: r = SHA-512(prefix ‖ M), R = rB, k = SHA-512(R ‖ A ‖ M),
// S = k·a + r. Signatures are identical to the standard construction
// for keys expanded from a seed.
func (li *LocalIdentity) Sign(message []byte) []byte {
	a, err := edwards25519.NewScalar().SetBytesWithClamping(li.prv[:32])
	if err != nil {
		panic("meshcore: invalid stored scalar: " + err.Error()) // unreachable: clamped at load
	}

	mh := sha512.New()
	mh.Write(li.prv[32:])
	mh.Write(message)
	r, err := edwards25519.NewScalar().SetUniformBytes(mh.Sum(nil))
	if err != nil {
		panic("meshcore: SetUniformBytes: " + err.Error()) // unreachable: 64-byte input
	}

	R := (&edwards25519.Point{}).ScalarBaseMult(r)

	kh := sha512.New()
	kh.Write(R.Bytes())
	kh.Write(li.PubKey[:])
	kh.Write(message)
	k, err := edwards25519.NewScalar().SetUniformBytes(kh.Sum(nil))
	if err != nil {
		panic("meshcore: SetUniformBytes: " + err.Error()) // unreachable
	}

	S := edwards25519.NewScalar().MultiplyAdd(k, a, r)

	sig := make([]byte, 0, SignatureSize)
	sig = append(sig, R.Bytes()...)
	sig = append(sig, S.Bytes()...)
	return sig
}

// SharedSecret performs the reference ECDH: the peer's Ed25519 public
// key is transposed to its X25519 (Montgomery) form, then multiplied
// by this identity's clamped scalar. Both parties derive the same
// 32-byte secret, which keys the payload cipher and MAC.
func (li *LocalIdentity) SharedSecret(otherPub []byte) ([]byte, error) {
	if len(otherPub) != PubKeySize {
		return nil, ErrBadKeyLength
	}
	p, err := (&edwards25519.Point{}).SetBytes(otherPub)
	if err != nil {
		return nil, ErrBadPublicKey
	}
	// X25519 rejects low-order points with a crypto/ecdh error; report
	// it as ErrBadPublicKey so the package's error set stays exhaustive.
	// (The reference's ed25519_key_exchange cannot fail — it returns an
	// all-zero secret — so we are strictly stricter here.)
	secret, err := curve25519.X25519(li.prv[:32], p.BytesMontgomery())
	if err != nil {
		return nil, ErrBadPublicKey
	}
	return secret, nil
}

// derivePub computes A = a·B from the clamped scalar.
func derivePub(scalar []byte) ([]byte, error) {
	a, err := edwards25519.NewScalar().SetBytesWithClamping(scalar)
	if err != nil {
		return nil, err
	}
	return (&edwards25519.Point{}).ScalarBaseMult(a).Bytes(), nil
}
