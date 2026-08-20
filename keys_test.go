package meshcore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"
)

// The same node identity travels the ecosystem in three private-key
// serializations; whichever one comes in, the node must come out
// identical.
func TestParsePrivateKeyAllFormats(t *testing.T) {
	seed := bytes.Repeat([]byte{0x5A}, SeedSize)
	ref, err := LocalIdentityFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}

	// 32-byte seed — openHop's identity_key, PyNaCl, stdlib seed.
	li, format, err := ParsePrivateKey(seed)
	if err != nil || format != KeyFormatSeed {
		t.Fatalf("seed: format=%v err=%v", format, err)
	}
	if li.PubKey != ref.PubKey {
		t.Fatal("seed: wrong identity")
	}

	// 64-byte seed ‖ pub — Go ed25519.PrivateKey / libsodium.
	li, format, err = ParsePrivateKey(ed25519.NewKeyFromSeed(seed))
	if err != nil || format != KeyFormatSeedPub {
		t.Fatalf("seed+pub: format=%v err=%v", format, err)
	}
	if li.PubKey != ref.PubKey {
		t.Fatal("seed+pub: wrong identity")
	}

	// 64-byte expanded — the firmware's prv.key (known-good vector).
	li, format, err = ParsePrivateKey(fwTestPrv)
	if err != nil || format != KeyFormatExpanded {
		t.Fatalf("expanded: format=%v err=%v", format, err)
	}
	if !bytes.Equal(li.PubKey[:], fwTestPub) {
		t.Fatal("expanded: wrong identity")
	}

	// The expanded export of a seed-born identity round-trips too.
	li, format, err = ParsePrivateKey(ref.PrvKey())
	if err != nil || format != KeyFormatExpanded || li.PubKey != ref.PubKey {
		t.Fatalf("re-import of expanded export: format=%v err=%v", format, err)
	}

	if _, _, err := ParsePrivateKey(make([]byte, 48)); !errors.Is(err, ErrUnknownKeyFormat) {
		t.Fatalf("48-byte blob: %v", err)
	}
}

// The seed → expanded conversion is one-way; the API must say so
// rather than pretend.
func TestSeedRetentionAndOneWayness(t *testing.T) {
	seed := bytes.Repeat([]byte{0x11}, SeedSize)
	fromSeed, _ := LocalIdentityFromSeed(seed)
	if !bytes.Equal(fromSeed.Seed(), seed) {
		t.Fatal("seed not retained")
	}
	std, ok := fromSeed.StdPrivateKey()
	if !ok || !bytes.Equal(std.Seed(), seed) {
		t.Fatal("stdlib export broken")
	}

	fromExpanded, _ := LocalIdentityFromKeys(fwTestPrv, nil)
	if fromExpanded.Seed() != nil {
		t.Fatal("expanded import claims to know a seed")
	}
	if _, ok := fromExpanded.StdPrivateKey(); ok {
		t.Fatal("expanded import claims a stdlib form")
	}
}

// An expanded key whose scalar half is not clamped would make us and
// the firmware derive different public keys — reject it loudly.
func TestExpandedKeyClampValidation(t *testing.T) {
	for _, mutate := range []func(b []byte){
		func(b []byte) { b[0] |= 0x01 },   // low bits must be clear
		func(b []byte) { b[31] |= 0x80 },  // top bit must be clear
		func(b []byte) { b[31] &^= 0x40 }, // bit 254 must be set
	} {
		bad := append([]byte(nil), fwTestPrv...)
		mutate(bad)
		if _, err := LocalIdentityFromKeys(bad, nil); !errors.Is(err, ErrUnknownKeyFormat) {
			t.Errorf("unclamped scalar accepted (err=%v)", err)
		}
	}
}

func TestGeneratedIdentitiesAreFirmwareImportable(t *testing.T) {
	for range 32 {
		li, err := NewLocalIdentity(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !li.FirmwareImportable() {
			t.Fatalf("generated pub starts %02x", li.PubKey[0])
		}
		if li.Seed() == nil {
			t.Fatal("generated identity lost its seed")
		}
	}
}

func TestPubKeyPrefixMatcher(t *testing.T) {
	m, err := PubKeyPrefixMatcher("1ec7")
	if err != nil {
		t.Fatal(err)
	}
	if !m(fwTestPub) {
		t.Fatal("known prefix not matched")
	}
	if m(bytes.Repeat([]byte{0x1E}, 32)) {
		t.Fatal("wrong second byte matched")
	}

	// Odd nibble count matches the high half of the trailing byte.
	m, err = PubKeyPrefixMatcher("1ec")
	if err != nil {
		t.Fatal(err)
	}
	if !m(fwTestPub) || m([]byte{0x1E, 0xD7, 0}) {
		t.Fatal("odd-nibble matching wrong")
	}

	for _, bad := range []string{"", "zz", "00dead", "ffca", string(bytes.Repeat([]byte{'a'}, 66))} {
		if _, err := PubKeyPrefixMatcher(bad); err == nil {
			t.Errorf("prefix %q accepted", bad)
		}
	}
}

func TestMineIdentity(t *testing.T) {
	match, err := PubKeyPrefixMatcher("a")
	if err != nil {
		t.Fatal(err)
	}
	li, attempts, err := MineIdentity(t.Context(), match)
	if err != nil {
		t.Fatal(err)
	}
	if li.PubKey[0]>>4 != 0xA {
		t.Fatalf("mined pub starts %02x", li.PubKey[0])
	}
	if attempts == 0 || li.Seed() == nil || !li.FirmwareImportable() {
		t.Fatalf("mined identity malformed (attempts=%d)", attempts)
	}

	// A cancelled search reports the context error.
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, _, err := MineIdentity(ctx, func([]byte) bool { return false }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled mining: %v", err)
	}
}

func TestStringers(t *testing.T) {
	cases := []struct {
		got, want string
	}{
		{RouteFlood.String(), "FLOOD"},
		{RouteTransportFlood.String(), "TRANSPORT_FLOOD"},
		{PayloadTypeAdvert.String(), "ADVERT"},
		{PayloadTypeTxtMsg.String(), "TXT_MSG"},
		{KeyFormatSeed.String(), "seed"},
		{KeyFormatExpanded.String(), "expanded"},
		{KeyFormatSeedPub.String(), "seed+pub"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("String() = %q, want %q", c.got, c.want)
		}
	}
}
