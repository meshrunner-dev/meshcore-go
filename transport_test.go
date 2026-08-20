package meshcore

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// A real #fr region packet from the Paris capture: transport_codes[0]
// is 0x74dc, and TransportKeyForName("fr").Code must reproduce it.
const frRegionFrameHex = "10dc74000040d77f74e3576cfbbda9462fb8b71fde3a99a20583c44d40832be8" +
	"454c262f66ccd46d7a6a5436b3b465486fd21475814b9690c98b9d4c34efac13" +
	"dd7c03c5e0a34544dd7906efbc61acb75fa0acbe58d36c2242afed91ba5c8153" +
	"5a6b28d5835e1ff2130c920552e9026ce924004652393453544d4e204d617474" +
	"686577206f70656e686f"

func TestTransportKeyForName(t *testing.T) {
	// Pinned derivation: SHA-256("#fr")[:16].
	k := TransportKeyForName("fr")
	if got := hex.EncodeToString(k[:]); got != "e31f97b98d8ac10649b6822bf96d9b09" {
		t.Fatalf("#fr key = %s", got)
	}
	// A leading '#' must not be doubled.
	if TransportKeyForName("#fr") != k {
		t.Fatal("leading # doubled")
	}
	if _, err := NewTransportKey(make([]byte, 15)); err == nil {
		t.Fatal("short raw key accepted")
	}
}

func TestTransportCodeAgainstLiveVector(t *testing.T) {
	frame, err := hex.DecodeString(frRegionFrameHex)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePacket(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasTransportCodes() || p.TransportCodes[0] != 0x74dc {
		t.Fatalf("frame transport code = %04x, want 74dc", p.TransportCodes[0])
	}

	k := TransportKeyForName("fr")
	if got := k.Code(p); got != 0x74dc {
		t.Fatalf("Code = %04x, want 74dc (matches the on-wire code)", got)
	}
	if !k.Matches(p) {
		t.Fatal("Matches false on a genuine #fr packet")
	}
	// A different region must not match.
	if TransportKeyForName("paris").Matches(p) {
		t.Fatal("wrong region matched")
	}
	// MatchTransportRegion finds it by index.
	keys := []TransportKey{TransportKeyForName("test"), k, TransportKeyForName("paris")}
	if MatchTransportRegion(p, keys) != 1 {
		t.Fatalf("MatchTransportRegion = %d, want 1", MatchTransportRegion(p, keys))
	}
}

// A packet with no transport codes (plain FLOOD) is unscoped: no region
// key matches it.
func TestTransportMatchesFalseWhenUnscoped(t *testing.T) {
	p := &Packet{Header: MakeHeader(RouteFlood, PayloadTypeGrpTxt, 0), Payload: []byte{1, 2, 3}}
	if TransportKeyForName("fr").Matches(p) {
		t.Fatal("unscoped packet matched a region")
	}
	if MatchTransportRegion(p, []TransportKey{TransportKeyForName("fr")}) != -1 {
		t.Fatal("unscoped packet matched in MatchTransportRegion")
	}
}

// The reserved codes 0x0000 and 0xFFFF are bumped to 0x0001 and 0xFFFE.
// Live traffic hits them only 1 in 65536, so force them: brute-force a
// payload whose raw HMAC prefix is the reserved value, then assert Code
// returns the bumped one.
func TestTransportCodeReservedBump(t *testing.T) {
	k := TransportKeyForName("bump")
	for _, tc := range []struct {
		raw, want uint16
	}{{0x0000, 0x0001}, {0xFFFF, 0xFFFE}} {
		found := false
		for i := range 1 << 22 {
			p := &Packet{Header: MakeHeader(RouteTransportFlood, PayloadTypeGrpTxt, 0)}
			p.Payload = binary.LittleEndian.AppendUint32(nil, uint32(i))
			// Recompute the RAW (un-bumped) code to detect the target.
			mac := hmac.New(sha256.New, k[:])
			mac.Write(append([]byte{byte(p.PayloadType())}, p.Payload...))
			if binary.LittleEndian.Uint16(mac.Sum(nil)[:2]) != tc.raw {
				continue
			}
			if got := k.Code(p); got != tc.want {
				t.Fatalf("raw %04x: Code = %04x, want bumped %04x", tc.raw, got, tc.want)
			}
			found = true
			break
		}
		if !found {
			t.Fatalf("could not force raw code %04x within budget", tc.raw)
		}
	}
}
