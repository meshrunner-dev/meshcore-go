package meshcore

import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// ErrBadMAC reports a payload whose MAC does not match its ciphertext.
var (
	ErrBadMAC        = errors.New("meshcore: MAC verification failed")
	ErrBadCiphertext = errors.New("meshcore: ciphertext is not block-aligned")
)

// SharedSecretSize is the required length of every secret passed to the
// symmetric primitives. The reference always keys them with a 32-byte
// secret: the cipher uses the first CipherKeySize bytes, the MAC keys
// HMAC over all of it (PUB_KEY_SIZE in Utils.cpp). Passing a shorter
// secret — a raw 16-byte channel PSK, say — would silently compute a
// MAC the firmware rejects, so the primitives require exactly this.
const SharedSecretSize = PubKeySize

// Encrypt enciphers plaintext with AES-128 in ECB mode — each 16-byte
// block independently — keyed by the first CipherKeySize bytes of the
// shared secret, zero-padding the final partial block. The block mode,
// key truncation and padding are the reference protocol's choices
// (MeshCore src/Utils.cpp), reproduced here for interoperability.
// The secret must be SharedSecretSize bytes; the returned length is a
// multiple of CipherBlockSize.
func Encrypt(sharedSecret, plaintext []byte) ([]byte, error) {
	if len(sharedSecret) != SharedSecretSize {
		return nil, ErrBadKeyLength
	}
	block, err := aes.NewCipher(sharedSecret[:CipherKeySize])
	if err != nil {
		panic("meshcore: aes.NewCipher: " + err.Error()) // unreachable: fixed key size
	}
	n := (len(plaintext) + CipherBlockSize - 1) / CipherBlockSize * CipherBlockSize
	out := make([]byte, n)
	copy(out, plaintext) // zero padding is the tail of the fresh buffer
	for i := 0; i < n; i += CipherBlockSize {
		block.Encrypt(out[i:i+CipherBlockSize], out[i:i+CipherBlockSize])
	}
	return out, nil
}

// Decrypt reverses Encrypt. The secret must be SharedSecretSize bytes
// and the ciphertext length a multiple of CipherBlockSize; the
// plaintext keeps any zero padding, exactly as the reference hands
// padded plaintext to its payload parsers.
func Decrypt(sharedSecret, ciphertext []byte) ([]byte, error) {
	if len(sharedSecret) != SharedSecretSize {
		return nil, ErrBadKeyLength
	}
	if len(ciphertext)%CipherBlockSize != 0 {
		return nil, ErrBadCiphertext
	}
	block, err := aes.NewCipher(sharedSecret[:CipherKeySize])
	if err != nil {
		panic("meshcore: aes.NewCipher: " + err.Error()) // unreachable
	}
	out := make([]byte, len(ciphertext))
	for i := 0; i < len(out); i += CipherBlockSize {
		block.Decrypt(out[i:i+CipherBlockSize], ciphertext[i:i+CipherBlockSize])
	}
	return out, nil
}

// EncryptThenMAC enciphers plaintext, then prepends a CipherMACSize
// authentication tag: HMAC-SHA256 over the ciphertext, keyed with the
// FULL SharedSecretSize secret (the cipher uses only its first half),
// truncated. Output layout: MAC ‖ ciphertext. The secret must be
// SharedSecretSize bytes.
func EncryptThenMAC(sharedSecret, plaintext []byte) ([]byte, error) {
	ct, err := Encrypt(sharedSecret, plaintext)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(ct)
	out := make([]byte, 0, CipherMACSize+len(ct))
	out = append(out, mac.Sum(nil)[:CipherMACSize]...)
	out = append(out, ct...)
	return out, nil
}

// MACThenDecrypt verifies the leading MAC and, if valid, deciphers the
// remaining bytes. It returns ErrBadMAC when the tag does not match —
// which, with a 2-byte tag, is also the routine "not for this key"
// signal the reference uses to probe candidate peers.
func MACThenDecrypt(sharedSecret, macAndCiphertext []byte) ([]byte, error) {
	if len(sharedSecret) != SharedSecretSize {
		return nil, ErrBadKeyLength
	}
	if len(macAndCiphertext) <= CipherMACSize {
		return nil, ErrShortFrame
	}
	ct := macAndCiphertext[CipherMACSize:]
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil)[:CipherMACSize], macAndCiphertext[:CipherMACSize]) {
		return nil, ErrBadMAC
	}
	return Decrypt(sharedSecret, ct)
}

// sha256Trunc hashes the fragments in order and truncates to n bytes.
func sha256Trunc(n int, frags ...[]byte) []byte {
	h := sha256.New()
	for _, f := range frags {
		h.Write(f)
	}
	return h.Sum(nil)[:n]
}
