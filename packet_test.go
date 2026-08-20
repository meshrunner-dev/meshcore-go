package meshcore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"testing"
)

func TestMakeHeaderAndAccessors(t *testing.T) {
	h := MakeHeader(RouteTransportFlood, PayloadTypeGrpTxt, PayloadVer1)
	if h != 0x14 {
		t.Fatalf("MakeHeader = 0x%02x, want 0x14 (as captured on air)", h)
	}
	p := &Packet{Header: h}
	if p.Route() != RouteTransportFlood || p.PayloadType() != PayloadTypeGrpTxt || p.PayloadVer() != PayloadVer1 {
		t.Fatalf("accessors: route=%v type=%v ver=%v", p.Route(), p.PayloadType(), p.PayloadVer())
	}
	if !p.IsRouteFlood() || p.IsRouteDirect() || !p.HasTransportCodes() {
		t.Fatalf("route predicates wrong for TRANSPORT_FLOOD")
	}
}

// The frame shape observed on air (evidences/case_3.md): a GRP_TXT
// TRANSPORT_FLOOD packet on a 2-byte-path-hash mesh, first as
// originated (empty path) and then as relayed once (one hash, 882f).
// The logs record the first 16 bytes and the repeater-decoded fields;
// the payload tail here is synthetic padding to the logged lengths.
func TestFieldFrameShape(t *testing.T) {
	prefix, _ := hex.DecodeString("14db9e0000406ae9a1734cb70d88e671")
	frame := slices.Concat(prefix, make([]byte, 41-len(prefix)))

	p, err := ParsePacket(frame)
	if err != nil {
		t.Fatal(err)
	}
	if p.Route() != RouteTransportFlood || p.PayloadType() != PayloadTypeGrpTxt {
		t.Fatalf("route=%v type=%v", p.Route(), p.PayloadType())
	}
	if p.TransportCodes[0] != 0x9EDB || p.TransportCodes[1] != 0x0000 {
		t.Fatalf("transport codes = %04X,%04X, want 9EDB,0000 (little-endian)", p.TransportCodes[0], p.TransportCodes[1])
	}
	if p.PathHashSize() != 2 || p.PathHashCount() != 0 || len(p.Payload) != 35 {
		t.Fatalf("size=%d count=%d payload=%d, repeater logged 2/0/35",
			p.PathHashSize(), p.PathHashCount(), len(p.Payload))
	}

	relayedPrefix, _ := hex.DecodeString("14db9e000041882f6ae9a1734cb70d88")
	relayed := slices.Concat(relayedPrefix, make([]byte, 43-len(relayedPrefix)))
	q, err := ParsePacket(relayed)
	if err != nil {
		t.Fatal(err)
	}
	if q.PathHashSize() != 2 || q.PathHashCount() != 1 || !bytes.Equal(q.Path, []byte{0x88, 0x2f}) || len(q.Payload) != 35 {
		t.Fatalf("relayed: size=%d count=%d path=%x payload=%d, repeater logged 2/1/882f/35",
			q.PathHashSize(), q.PathHashCount(), q.Path, len(q.Payload))
	}
}

func TestGoldenWireVector(t *testing.T) {
	p := &Packet{
		Header:         MakeHeader(RouteTransportFlood, PayloadTypeGrpTxt, PayloadVer1),
		TransportCodes: [2]uint16{0x9EDB, 0x0000},
		Payload:        []byte("abc"),
	}
	p.SetPathHashSizeAndCount(2, 1)
	p.Path = []byte{0x88, 0x2f}

	want := []byte{0x14, 0xdb, 0x9e, 0x00, 0x00, 0x41, 0x88, 0x2f, 'a', 'b', 'c'}
	got, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("encoded % x, want % x", got, want)
	}
	if p.RawLength() != len(want) {
		t.Fatalf("RawLength=%d, want %d", p.RawLength(), len(want))
	}

	q, err := ParsePacket(got)
	if err != nil {
		t.Fatal(err)
	}
	back, err := q.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, want) {
		t.Fatalf("round-trip drifted: % x", back)
	}
}

func TestRoundTripEveryRouteType(t *testing.T) {
	for _, route := range []RouteType{RouteTransportFlood, RouteFlood, RouteDirect, RouteTransportDirect} {
		p := &Packet{
			Header:  MakeHeader(route, PayloadTypeTxtMsg, PayloadVer1),
			Payload: []byte{1, 2, 3, 4, 5},
		}
		if route == RouteTransportFlood || route == RouteTransportDirect {
			p.TransportCodes = [2]uint16{0x1234, 0x5678}
		}
		p.SetPathHashSizeAndCount(1, 3)
		p.Path = []byte{0xAA, 0xBB, 0xCC}

		raw, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("%v: %v", route, err)
		}
		q, err := ParsePacket(raw)
		if err != nil {
			t.Fatalf("%v: %v", route, err)
		}
		if q.Route() != route || !bytes.Equal(q.Path, p.Path) || !bytes.Equal(q.Payload, p.Payload) {
			t.Fatalf("%v: round-trip mismatch", route)
		}
		if q.HasTransportCodes() != p.HasTransportCodes() || q.TransportCodes != p.TransportCodes {
			t.Fatalf("%v: transport codes mismatch: %v vs %v", route, q.TransportCodes, p.TransportCodes)
		}
	}
}

func TestValidPathLen(t *testing.T) {
	cases := []struct {
		pathLen uint8
		ok      bool
	}{
		{0x00, true},       // size 1, count 0
		{0x3F, true},       // size 1, count 63 → 63 bytes
		{0x41, true},       // size 2, count 1 (the field capture)
		{0x40 | 32, true},  // size 2, count 32 → 64 bytes, exactly MaxPathSize
		{0x40 | 33, false}, // size 2, count 33 → 66 bytes, over
		{0x80 | 21, true},  // size 3, count 21 → 63 bytes
		{0x80 | 22, false}, // size 3, count 22 → 66 bytes
		{0xC0, false},      // size 4: reserved, even with count 0
		{0xC0 | 1, false},  // size 4: reserved
	}
	for _, c := range cases {
		if got := ValidPathLen(c.pathLen); got != c.ok {
			t.Errorf("ValidPathLen(0x%02x) = %v, want %v", c.pathLen, got, c.ok)
		}
	}
}

func TestParseRejections(t *testing.T) {
	tests := []struct {
		name  string
		frame []byte
		want  error
	}{
		{"empty frame", nil, ErrShortFrame},
		{"header only", []byte{0x14}, ErrShortFrame},
		{"truncated transport codes", []byte{0x14, 0xdb, 0x9e}, ErrShortFrame},
		{"missing path bytes", []byte{0x15, 0x41, 0x88}, ErrShortFrame},      // FLOOD, size2/count1, one path byte
		{"reserved hash size", []byte{0x15, 0xC0, 0x01}, ErrInvalidPathLen},  // size code 3
		{"no payload", []byte{0x15, 0x00}, ErrEmptyPayload},                  // reference: i >= len
		{"no payload after path", []byte{0x15, 0x01, 0xAA}, ErrEmptyPayload}, // path consumed everything
		{"payload too large", append([]byte{0x15, 0x00}, make([]byte, MaxPacketPayload+1)...), ErrPayloadTooLarge},
	}
	for _, tc := range tests {
		if _, err := ParsePacket(tc.frame); !errors.Is(err, tc.want) {
			t.Errorf("%s: err=%v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestMarshalRejectsUntransportablePackets(t *testing.T) {
	empty := &Packet{Header: MakeHeader(RouteFlood, PayloadTypeAdvert, PayloadVer1)}
	if _, err := empty.MarshalBinary(); !errors.Is(err, ErrEmptyPayload) {
		t.Errorf("empty payload: err=%v, want ErrEmptyPayload", err)
	}

	big := &Packet{Header: 0x15, Payload: make([]byte, MaxPacketPayload+1)}
	if _, err := big.MarshalBinary(); !errors.Is(err, ErrPayloadTooLarge) {
		t.Errorf("oversized payload: err=%v, want ErrPayloadTooLarge", err)
	}

	short := &Packet{Header: 0x15, Payload: []byte{1}}
	short.SetPathHashSizeAndCount(2, 3) // describes 6 bytes
	short.Path = []byte{0xAA, 0xBB}     // holds 2
	if _, err := short.MarshalBinary(); !errors.Is(err, ErrPathTooLarge) {
		t.Errorf("short path: err=%v, want ErrPathTooLarge", err)
	}
}

func TestMaxSizeFrameRoundTrips(t *testing.T) {
	p := &Packet{
		Header:         MakeHeader(RouteTransportDirect, PayloadTypeRawCustom, PayloadVer1),
		TransportCodes: [2]uint16{0xFFFF, 0xFFFF},
		Payload:        bytes.Repeat([]byte{0x5A}, MaxPacketPayload),
	}
	p.SetPathHashSizeAndCount(2, 32) // exactly MaxPathSize bytes
	p.Path = bytes.Repeat([]byte{0x11}, MaxPathSize)

	raw, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 2+4+MaxPathSize+MaxPacketPayload || len(raw) > MaxTransUnit {
		t.Fatalf("raw length %d", len(raw))
	}
	if _, err := ParsePacket(raw); err != nil {
		t.Fatal(err)
	}
}

// The hash preimage is: payload type, then — for TRACE only — the path
// descriptor as two little-endian bytes (the reference hashes its
// uint16 field whole), then the payload; SHA-256 truncated to 8 bytes.
func TestPacketHashPreimage(t *testing.T) {
	trace := &Packet{
		Header:  MakeHeader(RouteDirect, PayloadTypeTrace, PayloadVer1),
		PathLen: 5, // five SNR bytes collected
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	sum := sha256.Sum256(append([]byte{uint8(PayloadTypeTrace), 5, 0}, trace.Payload...))
	if got := trace.Hash(); !bytes.Equal(got[:], sum[:MaxHashSize]) {
		t.Fatalf("TRACE hash = %x, want %x", got, sum[:MaxHashSize])
	}

	text := &Packet{
		Header:  MakeHeader(RouteFlood, PayloadTypeTxtMsg, PayloadVer1),
		Payload: []byte("hello"),
	}
	sum = sha256.Sum256(append([]byte{uint8(PayloadTypeTxtMsg)}, text.Payload...))
	if got := text.Hash(); !bytes.Equal(got[:], sum[:MaxHashSize]) {
		t.Fatalf("TXT hash = %x, want %x", got, sum[:MaxHashSize])
	}
}

// A rebroadcast arrives with a longer accumulated path but must hash
// identically — dedup depends on it. TRACE is the deliberate exception.
func TestHashIgnoresPathExceptForTrace(t *testing.T) {
	a := &Packet{Header: MakeHeader(RouteFlood, PayloadTypeGrpTxt, PayloadVer1), Payload: []byte("msg")}
	b := &Packet{Header: MakeHeader(RouteFlood, PayloadTypeGrpTxt, PayloadVer1), Payload: []byte("msg")}
	b.SetPathHashSizeAndCount(2, 3)
	b.Path = []byte{1, 2, 3, 4, 5, 6}
	if a.Hash() != b.Hash() {
		t.Fatal("non-TRACE hash must not depend on the path")
	}

	t1 := &Packet{Header: MakeHeader(RouteDirect, PayloadTypeTrace, PayloadVer1), PathLen: 1, Payload: []byte("t")}
	t2 := &Packet{Header: MakeHeader(RouteDirect, PayloadTypeTrace, PayloadVer1), PathLen: 2, Payload: []byte("t")}
	if t1.Hash() == t2.Hash() {
		t.Fatal("TRACE hash must change with the path descriptor")
	}
}
