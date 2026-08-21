package meshcore

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The example a repeater answers, from the field: CONTROL, direct,
// payload 80 04 <tag>. Pinning it keeps the discovery encoding wire-
// compatible with the reference firmware.
func TestDiscoverReqReferenceBytes(t *testing.T) {
	req, err := BuildDiscoverReq(DiscoverReq{Filter: RepeaterFilter(), Tag: 0x78BACA14})
	if err != nil {
		t.Fatal(err)
	}
	if req.Route() != RouteDirect {
		t.Errorf("route = %v, want direct (zero hop)", req.Route())
	}
	if req.PathHashCount() != 0 {
		t.Errorf("path count = %d, want 0 (zero hop)", req.PathHashCount())
	}
	if got := hex.EncodeToString(req.Payload); got != "800414caba78" {
		t.Errorf("payload = %s, want 800414caba78", got)
	}
}

func TestDiscoverReqRoundTrip(t *testing.T) {
	for _, tc := range []DiscoverReq{
		{Filter: RepeaterFilter(), Tag: 0xDEADBEEF},
		{Filter: 1<<AdvTypeRepeater | 1<<AdvTypeRoom, Tag: 1, Since: 1_700_000_000},
		{Filter: RepeaterFilter(), Tag: 42, PrefixOnly: true},
	} {
		pkt, err := BuildDiscoverReq(tc)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseDiscoverReq(pkt)
		if err != nil {
			t.Fatalf("%+v: %v", tc, err)
		}
		if *got != tc {
			t.Errorf("round trip: got %+v, want %+v", *got, tc)
		}
		if !got.Filter.Includes(AdvTypeRepeater) {
			t.Error("repeater filter does not include repeaters")
		}
	}
}

func TestDiscoverRespRoundTrip(t *testing.T) {
	key := make([]byte, PubKeySize)
	for i := range key {
		key[i] = byte(i + 1)
	}
	resp := DiscoverResp{NodeType: AdvTypeRepeater, SNR: 11.5, Tag: 0x12345678, PubKey: key}
	pkt, err := BuildDiscoverResp(resp, false)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseDiscoverResp(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if got.NodeType != AdvTypeRepeater || got.Tag != resp.Tag || got.SNR != 11.5 {
		t.Errorf("got %+v", got)
	}
	if !bytes.Equal(got.PubKey, key) {
		t.Error("pubkey did not round-trip")
	}

	// Prefix-only replies carry 8 key bytes.
	pkt, err = BuildDiscoverResp(resp, true)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = ParseDiscoverResp(pkt)
	if len(got.PubKey) != 8 || !bytes.Equal(got.PubKey, key[:8]) {
		t.Errorf("prefix reply key = %x", got.PubKey)
	}
}

// SNR survives the quarter-dB byte encoding, and saturates rather than
// wraps at the extremes.
func TestDiscoverRespSNREncoding(t *testing.T) {
	key := make([]byte, PubKeySize)
	for _, snr := range []float64{-8, -0.25, 0, 1.5, 11.75, 30} {
		pkt, _ := BuildDiscoverResp(DiscoverResp{NodeType: AdvTypeRepeater, SNR: snr, PubKey: key}, false)
		got, _ := ParseDiscoverResp(pkt)
		if want := float64(int8(snr*4)) / 4; got.SNR != want {
			t.Errorf("SNR %v encoded to %v, want %v", snr, got.SNR, want)
		}
	}
	// 40 dB would overflow int8 at quarter-dB steps; it must clamp.
	pkt, _ := BuildDiscoverResp(DiscoverResp{NodeType: AdvTypeRepeater, SNR: 40, PubKey: key}, false)
	got, _ := ParseDiscoverResp(pkt)
	if got.SNR != 127.0/4 {
		t.Errorf("SNR clamp = %v, want %v", got.SNR, 127.0/4)
	}
}

// The type nibbles must not be confused: a request is not a response.
func TestDiscoverTypeGuards(t *testing.T) {
	req, _ := BuildDiscoverReq(DiscoverReq{Filter: RepeaterFilter(), Tag: 1})
	if _, err := ParseDiscoverResp(req); err == nil {
		t.Error("parsed a request as a response")
	}
	resp, _ := BuildDiscoverResp(DiscoverResp{NodeType: AdvTypeRepeater, PubKey: make([]byte, PubKeySize)}, false)
	if _, err := ParseDiscoverReq(resp); err == nil {
		t.Error("parsed a response as a request")
	}
	// A non-control packet is neither.
	adv := &Packet{Header: MakeHeader(RouteFlood, PayloadTypeAdvert, PayloadVer1)}
	if _, err := ParseDiscoverReq(adv); err == nil {
		t.Error("parsed an advert as a discovery request")
	}
}
