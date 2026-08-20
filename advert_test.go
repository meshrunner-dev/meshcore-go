package meshcore

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestAdvertBuildParseVerify(t *testing.T) {
	li, err := LocalIdentityFromKeys(fwTestPrv, nil)
	if err != nil {
		t.Fatal(err)
	}
	emitted := time.Unix(1765000000, 0).UTC()
	app := &AdvertData{
		Type:   AdvTypeRepeater,
		HasLoc: true,
		LatE6:  48858370, // 48.858370
		LonE6:  2294481,
		Name:   "mesh-repeater-01",
	}

	p, err := BuildAdvert(li, emitted, app)
	if err != nil {
		t.Fatal(err)
	}
	if p.PayloadType() != PayloadTypeAdvert {
		t.Fatalf("type=%v", p.PayloadType())
	}

	adv, err := ParseAdvert(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(adv.Identity.PubKey[:], fwTestPub) {
		t.Fatal("identity mismatch")
	}
	if !adv.Timestamp.Equal(emitted) {
		t.Fatalf("timestamp %v, want %v", adv.Timestamp, emitted)
	}
	if adv.Data.Type != AdvTypeRepeater || !adv.Data.HasLoc || adv.Data.Name != "mesh-repeater-01" {
		t.Fatalf("app data mismatch: %+v", adv.Data)
	}
	if adv.Data.Lat() != 48.858370 || adv.Data.Lon() != 2.294481 {
		t.Fatalf("lat/lon conversion: %v, %v", adv.Data.Lat(), adv.Data.Lon())
	}
}

// The signature covers pub_key + timestamp + app_data — flipping any
// bit of any of the three must fail verification.
func TestAdvertTamperDetection(t *testing.T) {
	li, _ := LocalIdentityFromKeys(fwTestPrv, nil)
	p, err := BuildAdvert(li, time.Unix(1765000000, 0), &AdvertData{Type: AdvTypeChat, Name: "n"})
	if err != nil {
		t.Fatal(err)
	}

	for _, offset := range []int{
		0,                  // pub_key
		PubKeySize,         // timestamp
		advertFixedLen,     // app data (flags byte)
		len(p.Payload) - 1, // app data tail (the name)
	} {
		bad := append([]byte(nil), p.Payload...)
		bad[offset] ^= 0x01
		if _, err := ParseAdvert(bad); offset == 0 {
			// Flipping the pub_key may also make the point invalid;
			// either rejection is fine, success is not.
			if err == nil {
				t.Errorf("offset %d: tamper accepted", offset)
			}
		} else if !errors.Is(err, ErrBadSignature) {
			t.Errorf("offset %d: err=%v, want ErrBadSignature", offset, err)
		}
	}
}

func TestAdvertDataEncodeParseRoundTrips(t *testing.T) {
	cases := []AdvertData{
		{Type: AdvTypeChat},
		{Type: AdvTypeRepeater, Name: "R"},
		{Type: AdvTypeRoom, HasLoc: true, LatE6: -33868820, LonE6: 151209290},
		{Type: AdvTypeSensor, Feat1: 0x1234},
		{Type: AdvTypeChat, Feat1: 1, Feat2: 0xFFFF, HasLoc: true, LatE6: 1, LonE6: -1, Name: "full"},
	}
	for i, in := range cases {
		b := in.EncodeAppData()
		if len(b) > MaxAdvertDataSize {
			t.Fatalf("case %d: %d bytes", i, len(b))
		}
		out, err := ParseAdvertData(b)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if *out != in {
			t.Fatalf("case %d: round-trip drift:\n in  %+v\n out %+v", i, in, *out)
		}
	}
}

// A zero feature word is not emitted (its flag stays clear), matching
// the reference builder's `if (_extra1)` — the round-trip therefore
// cannot distinguish "absent" from "zero", by design.
func TestAdvertDataZeroFeatureOmitted(t *testing.T) {
	b := (&AdvertData{Type: AdvTypeChat, Feat1: 0, Name: "x"}).EncodeAppData()
	if b[0]&advFeat1Mask != 0 {
		t.Fatal("zero feature flagged")
	}
	if len(b) != 2 { // flags + "x"
		t.Fatalf("len=%d", len(b))
	}
}

func TestAdvertDataNameTruncatedToFit(t *testing.T) {
	long := &AdvertData{
		Type:   AdvTypeChat,
		HasLoc: true,
		Name:   "abcdefghijklmnopqrstuvwxyz0123456789", // over budget with loc
	}
	b := long.EncodeAppData()
	if len(b) != MaxAdvertDataSize {
		t.Fatalf("len=%d, want exactly MaxAdvertDataSize", len(b))
	}
	out, err := ParseAdvertData(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != "abcdefghijklmnopqrstuvw" { // 32 - 1 - 8 = 23 bytes
		t.Fatalf("name = %q (%d bytes)", out.Name, len(out.Name))
	}
}

// Name truncation must not split a UTF-8 sequence, and a name whose
// first byte is malformed is dropped along with its flag — both per the
// reference's validUtf8PrefixLength.
func TestAdvertDataNameTruncationIsUTF8Aware(t *testing.T) {
	// 11 bottle emoji (4 bytes each); with loc, 23 bytes of room: 5
	// whole emoji fit (20 bytes), the 6th must not be split.
	emoji := "🍾🍾🍾🍾🍾🍾🍾🍾🍾🍾🍾"
	b := (&AdvertData{Type: AdvTypeRoom, HasLoc: true, Name: emoji}).EncodeAppData()
	out, err := ParseAdvertData(b)
	if err != nil {
		t.Fatal(err)
	}
	if out.Name != "🍾🍾🍾🍾🍾" {
		t.Fatalf("name = %q (%d bytes)", out.Name, len(out.Name))
	}

	// Malformed head: the reference emits no name at all.
	b = (&AdvertData{Type: AdvTypeChat, Name: "\xffabc"}).EncodeAppData()
	if len(b) != 1 || b[0]&advNameMask != 0 {
		t.Fatalf("malformed name emitted anyway: % x", b)
	}
}

// The reference caps advert app data at MaxAdvertDataSize before
// verifying the signature (Mesh::onRecvPacket): padding appended past
// 32 bytes must not change the verdict, or a relay could pad a valid
// advert into one the whole mesh refloods but we reject.
func TestParseAdvertClampsAppDataToMax(t *testing.T) {
	li, _ := LocalIdentityFromKeys(fwTestPrv, nil)
	// A full 32-byte app data: type+name flag, then 31 name bytes.
	app := &AdvertData{Type: AdvTypeChat, Name: string(bytes.Repeat([]byte{'x'}, MaxAdvertDataSize-1))}
	p, err := BuildAdvert(li, time.Unix(1765000000, 0), app)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(p.Payload) - advertFixedLen; got != MaxAdvertDataSize {
		t.Fatalf("app data is %d bytes, want a full %d for this test", got, MaxAdvertDataSize)
	}

	// Exact form verifies.
	if _, err := ParseAdvert(p.Payload); err != nil {
		t.Fatalf("exact advert rejected: %v", err)
	}

	// Append padding beyond 32 bytes — the signer never covered it, and
	// the reference clamps it away, so verification must still pass.
	padded := append(append([]byte(nil), p.Payload...), 1, 2, 3, 4, 5, 6, 7, 8)
	adv, err := ParseAdvert(padded)
	if err != nil {
		t.Fatalf("padded advert rejected (clamp missing?): %v", err)
	}
	// The decoded app data is the clamped 32 bytes, not the padded tail.
	if adv.Data.Name != string(bytes.Repeat([]byte{'x'}, MaxAdvertDataSize-1)) {
		t.Fatalf("decoded name reflects padding: %q", adv.Data.Name)
	}
}

// The reference reads the name as a C string, so an embedded NUL ends
// it (AdvertDataHelpers stores the bytes then NUL-terminates; every
// consumer uses strlen). A crafted trailing blob must not smuggle bytes
// into the name past what firmware nodes display.
func TestParseAdvertDataNameStopsAtNUL(t *testing.T) {
	blob := []byte{AdvTypeChat | advNameMask, 'a', 'b', 0x00, 'c', 'd'}
	got, err := ParseAdvertData(blob)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "ab" {
		t.Fatalf("name = %q, want %q", got.Name, "ab")
	}
}

func TestParseAdvertRejectsShortPayload(t *testing.T) {
	if _, err := ParseAdvert(make([]byte, advertFixedLen-1)); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("err=%v", err)
	}
}
