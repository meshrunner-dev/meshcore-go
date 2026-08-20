package meshcore

import (
	"bytes"
	"errors"
	"testing"
)

var testSecret = bytes.Repeat([]byte{0x0F, 0xF0}, 16) // 32 bytes

func TestEncryptDecryptRoundTrip(t *testing.T) {
	for _, n := range []int{1, 15, 16, 17, 32, 33, 100} {
		plain := bytes.Repeat([]byte{0xAB}, n)
		ct, err := Encrypt(testSecret, plain)
		if err != nil {
			t.Fatal(err)
		}
		if len(ct)%CipherBlockSize != 0 {
			t.Fatalf("n=%d: ciphertext length %d not block-aligned", n, len(ct))
		}
		back, err := Decrypt(testSecret, ct)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(back[:n], plain) {
			t.Fatalf("n=%d: plaintext mangled", n)
		}
		// Zero padding survives, as the reference hands it to parsers.
		for _, b := range back[n:] {
			if b != 0 {
				t.Fatalf("n=%d: padding is not zero: % x", n, back[n:])
			}
		}
	}
}

// The reference cipher is ECB: identical plaintext blocks encrypt to
// identical ciphertext blocks. This pins the mode — a well-meaning
// switch to CBC/CTR would break interop with every deployed node.
func TestCipherIsECB(t *testing.T) {
	plain := append(bytes.Repeat([]byte{0x11}, 16), bytes.Repeat([]byte{0x11}, 16)...)
	ct := mustEncrypt(t, testSecret, plain)
	if !bytes.Equal(ct[:16], ct[16:32]) {
		t.Fatal("identical blocks produced different ciphertext — mode is not ECB")
	}
}

// Only the first half of the shared secret keys the cipher; the MAC
// uses all of it. Two secrets sharing their first 16 bytes must
// encrypt identically but MAC differently.
func TestKeySplitBetweenCipherAndMAC(t *testing.T) {
	other := append([]byte(nil), testSecret...)
	other[31] ^= 0xFF

	plain := []byte("split key")
	if !bytes.Equal(mustEncrypt(t, testSecret, plain), mustEncrypt(t, other, plain)) {
		t.Fatal("cipher used bytes beyond CipherKeySize")
	}
	a := mustSeal(t, testSecret, plain)
	b := mustSeal(t, other, plain)
	if bytes.Equal(a[:CipherMACSize], b[:CipherMACSize]) {
		t.Fatal("MAC ignored the second half of the secret")
	}
}

func TestEncryptThenMACRoundTrip(t *testing.T) {
	plain := []byte("over the air")
	sealed := mustSeal(t, testSecret, plain)

	back, err := MACThenDecrypt(testSecret, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back[:len(plain)], plain) {
		t.Fatalf("got %q", back)
	}

	// Any tamper — MAC or ciphertext — must be rejected.
	for i := range sealed {
		bad := append([]byte(nil), sealed...)
		bad[i] ^= 0x01
		if _, err := MACThenDecrypt(testSecret, bad); !errors.Is(err, ErrBadMAC) {
			t.Fatalf("tamper at byte %d not caught (err=%v)", i, err)
		}
	}

	// Wrong key behaves like the reference's peer probing: bad MAC.
	wrong := append([]byte(nil), testSecret...)
	wrong[0] ^= 1
	if _, err := MACThenDecrypt(wrong, sealed); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("wrong key: err=%v, want ErrBadMAC", err)
	}
}

func TestMACThenDecryptRejectsShortInput(t *testing.T) {
	for _, n := range []int{0, 1, 2} {
		if _, err := MACThenDecrypt(testSecret, make([]byte, n)); err == nil {
			t.Errorf("len=%d accepted", n)
		}
	}
}

// mustEncrypt / mustSeal keep the round-trip tests readable now that the
// primitives validate the secret length and return an error.
func mustEncrypt(t *testing.T, secret, plain []byte) []byte {
	t.Helper()
	ct, err := Encrypt(secret, plain)
	if err != nil {
		t.Fatal(err)
	}
	return ct
}

func mustSeal(t *testing.T, secret, plain []byte) []byte {
	t.Helper()
	sealed, err := EncryptThenMAC(secret, plain)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

// A secret that is not SharedSecretSize bytes must error, never panic —
// the reference always keys these with a 32-byte secret, and a raw
// 16-byte channel PSK would otherwise compute a MAC the firmware rejects.
func TestSymmetricPrimitivesRejectWrongSecretLength(t *testing.T) {
	for _, n := range []int{0, 5, 15, 16, 31, 33} {
		secret := bytes.Repeat([]byte{0x11}, n)
		if _, err := Encrypt(secret, []byte("x")); !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("Encrypt(len %d): err=%v", n, err)
		}
		if _, err := EncryptThenMAC(secret, []byte("x")); !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("EncryptThenMAC(len %d): err=%v", n, err)
		}
		if _, err := Decrypt(secret, make([]byte, CipherBlockSize)); !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("Decrypt(len %d): err=%v", n, err)
		}
		if _, err := MACThenDecrypt(secret, make([]byte, CipherBlockSize+CipherMACSize)); !errors.Is(err, ErrBadKeyLength) {
			t.Errorf("MACThenDecrypt(len %d): err=%v", n, err)
		}
	}
}
