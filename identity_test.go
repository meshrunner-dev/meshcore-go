package meshcore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// The known-good test client keypair embedded in the reference
// (MeshCore src/Identity.cpp, validatePrivateKey) — a real firmware
// vector for the expanded orlp private-key layout.
var (
	fwTestPrv = []byte{
		0x70, 0x65, 0xe1, 0x8f, 0xd9, 0xfa, 0xbb, 0x70,
		0xc1, 0xed, 0x90, 0xdc, 0xa1, 0x99, 0x07, 0xde,
		0x69, 0x8c, 0x88, 0xb7, 0x09, 0xea, 0x14, 0x6e,
		0xaf, 0xd9, 0x3d, 0x9b, 0x83, 0x0c, 0x7b, 0x60,
		0xc4, 0x68, 0x11, 0x93, 0xc7, 0x9b, 0xbc, 0x39,
		0x94, 0x5b, 0xa8, 0x06, 0x41, 0x04, 0xbb, 0x61,
		0x8f, 0x8f, 0xd7, 0xa8, 0x4a, 0x0a, 0xf6, 0xf5,
		0x70, 0x33, 0xd6, 0xe8, 0xdd, 0xcd, 0x64, 0x71,
	}
	fwTestPub = []byte{
		0x1e, 0xc7, 0x71, 0x75, 0xb0, 0x91, 0x8e, 0xd2,
		0x06, 0xf9, 0xae, 0x04, 0xec, 0x13, 0x6d, 0x6d,
		0x5d, 0x43, 0x15, 0xbb, 0x26, 0x30, 0x54, 0x27,
		0xf6, 0x45, 0xb4, 0x92, 0xe9, 0x35, 0x0c, 0x10,
	}
)

func TestFirmwareTestClientKeypair(t *testing.T) {
	li, err := LocalIdentityFromKeys(fwTestPrv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(li.PubKey[:], fwTestPub) {
		t.Fatalf("derived pub = %x,\nfirmware says  %x", li.PubKey, fwTestPub)
	}

	// Loading with the matching public key must succeed; with a wrong
	// one it must be refused.
	if _, err := LocalIdentityFromKeys(fwTestPrv, fwTestPub); err != nil {
		t.Fatalf("load with matching pub: %v", err)
	}
	wrong := append([]byte(nil), fwTestPub...)
	wrong[0] ^= 1
	if _, err := LocalIdentityFromKeys(fwTestPrv, wrong); err == nil {
		t.Fatal("mismatched public key accepted")
	}

	// Signatures from the expanded key must verify under the public key.
	msg := []byte("meshrunner interop probe")
	if !li.Verify(li.Sign(msg), msg) {
		t.Fatal("self-verify failed for the firmware keypair")
	}
}

// Our expanded-key signer must produce byte-identical signatures to the
// standard construction when both start from the same seed — Ed25519 is
// deterministic, so this cross-validates the whole signing path against
// the Go standard library.
func TestSignMatchesStdlibFromSameSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, SeedSize)
	li, err := LocalIdentityFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	std := ed25519.NewKeyFromSeed(seed)

	stdPub, ok := std.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("stdlib key has unexpected public key type")
	}
	if !bytes.Equal(li.PubKey[:], stdPub) {
		t.Fatalf("public keys diverge: %x vs %x", li.PubKey, stdPub)
	}
	for _, msg := range [][]byte{nil, []byte("a"), bytes.Repeat([]byte{0xA5}, 300)} {
		ours := li.Sign(msg)
		theirs := ed25519.Sign(std, msg)
		if !bytes.Equal(ours, theirs) {
			t.Fatalf("signature diverges for %d-byte message", len(msg))
		}
	}
}

func TestSharedSecretSymmetry(t *testing.T) {
	a, err := NewLocalIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LocalIdentityFromKeys(fwTestPrv, nil)
	if err != nil {
		t.Fatal(err)
	}

	sab, err := a.SharedSecret(b.PubKey[:])
	if err != nil {
		t.Fatal(err)
	}
	sba, err := b.SharedSecret(a.PubKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sab, sba) {
		t.Fatal("shared secrets are not symmetric")
	}
	if len(sab) != 32 || bytes.Equal(sab, make([]byte, 32)) {
		t.Fatalf("degenerate shared secret: %x", sab)
	}
}

func TestIdentityHashing(t *testing.T) {
	id, err := IdentityFromBytes(fwTestPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id.Hash(1), []byte{0x1e}) || !bytes.Equal(id.Hash(2), []byte{0x1e, 0xc7}) {
		t.Fatalf("hash prefixes wrong: %x / %x", id.Hash(1), id.Hash(2))
	}
	if !id.HashMatches([]byte{0x1e, 0xc7}) || id.HashMatches([]byte{0x1e, 0xc8}) {
		t.Fatal("HashMatches wrong")
	}
}

func TestIdentityRejections(t *testing.T) {
	if _, err := IdentityFromBytes(make([]byte, 31)); err == nil {
		t.Error("short public key accepted")
	}
	if _, err := LocalIdentityFromSeed(make([]byte, 16)); err == nil {
		t.Error("short seed accepted")
	}
	if _, err := LocalIdentityFromKeys(make([]byte, 32), nil); err == nil {
		t.Error("short private key accepted")
	}

	li, _ := LocalIdentityFromKeys(fwTestPrv, nil)
	if _, err := li.SharedSecret(make([]byte, 16)); err == nil {
		t.Error("short peer key accepted")
	}

	id := Identity{}
	copy(id.PubKey[:], fwTestPub)
	msg := []byte("x")
	sig := li.Sign(msg)
	sig[10] ^= 1
	if id.Verify(sig, msg) {
		t.Error("tampered signature verified")
	}
}

func TestIdentityHashBoundaries(t *testing.T) {
	id, _ := IdentityFromBytes(fwTestPub)
	if len(id.Hash(0)) != 0 {
		t.Fatal("Hash(0) should be empty")
	}
	if !bytes.Equal(id.Hash(PubKeySize), fwTestPub) {
		t.Fatal("Hash(PubKeySize) should be the whole key")
	}
}
