package meshcore

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// The reference always writes exactly PathHashSize per address hash
// (copyHashTo). A builder handed a wider hash used to emit a frame its
// own parser then rejected as a bad MAC; it must refuse up front.
func TestBuildersRejectWrongHashLength(t *testing.T) {
	wide := []byte{0x1E, 0xC7} // 2 bytes, not PathHashSize
	ok := []byte{0x1E}

	if _, err := BuildDatagram(PayloadTypeTxtMsg, wide, ok, testSecret, []byte("x")); !errors.Is(err, ErrBadHashLength) {
		t.Errorf("BuildDatagram wide dest: %v", err)
	}
	if _, err := BuildDatagram(PayloadTypeTxtMsg, ok, wide, testSecret, []byte("x")); !errors.Is(err, ErrBadHashLength) {
		t.Errorf("BuildDatagram wide src: %v", err)
	}
	if _, err := BuildAnonDatagram(wide, fwTestPub, testSecret, []byte("x")); !errors.Is(err, ErrBadHashLength) {
		t.Errorf("BuildAnonDatagram wide dest: %v", err)
	}
	if _, err := BuildPathReturn(wide, ok, testSecret, 1, []byte{0x99}, 0, nil); !errors.Is(err, ErrBadHashLength) {
		t.Errorf("BuildPathReturn wide dest: %v", err)
	}
	badCh := &GroupChannel{Hash: wide, Secret: testSecret}
	if _, err := BuildGroupDatagram(PayloadTypeGrpTxt, badCh, []byte("x")); !errors.Is(err, ErrBadHashLength) {
		t.Errorf("BuildGroupDatagram wide channel hash: %v", err)
	}
}

// Everything the Parse* helpers return must be a copy, not a view into
// the input — matching ParsePacket. Writing to a returned field must
// not reach back into the source payload.
func TestParseEnvelopesDoNotAliasInput(t *testing.T) {
	ch, _ := NewGroupChannel(testSecret)
	p, err := BuildDatagram(PayloadTypeTxtMsg, []byte{0x1E}, []byte{0x88}, testSecret, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Clone(p.Payload)

	d, _ := ParseDatagram(p.Payload)
	d.DestHash[0] ^= 0xFF
	d.SrcHash[0] ^= 0xFF
	d.Sealed[0] ^= 0xFF
	if !bytes.Equal(p.Payload, payload) {
		t.Fatal("ParseDatagram aliases its input")
	}

	a, _ := BuildAnonDatagram([]byte{0x42}, fwTestPub, testSecret, []byte("x"))
	saved := bytes.Clone(a.Payload)
	an, _ := ParseAnonDatagram(a.Payload)
	an.SenderPub[0] ^= 0xFF
	an.Sealed[0] ^= 0xFF
	if !bytes.Equal(a.Payload, saved) {
		t.Fatal("ParseAnonDatagram aliases its input")
	}

	g, _ := BuildGroupDatagram(PayloadTypeGrpTxt, ch, []byte("x"))
	savedG := bytes.Clone(g.Payload)
	gd, _ := ParseGroupDatagram(g.Payload)
	gd.ChannelHash[0] ^= 0xFF
	gd.Sealed[0] ^= 0xFF
	if !bytes.Equal(g.Payload, savedG) {
		t.Fatal("ParseGroupDatagram aliases its input")
	}
}

// A relay keeps the received packet and forwards a copy with its own
// hash appended. Mutating the copy's path must not corrupt the
// original, and vice versa — even though ParsePacket may leave spare
// capacity in the Path backing array.
func TestPathMutationDoesNotAliasCopies(t *testing.T) {
	raw, err := (&Packet{
		Header:  MakeHeader(RouteFlood, PayloadTypeGrpTxt, 0),
		PathLen: 1, Path: []byte{0xAA}, Payload: []byte{1},
	}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	orig, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}

	fwd := *orig // a shallow copy shares the Path backing array
	if err := fwd.AppendPathHash([]byte{0xBB}); err != nil {
		t.Fatal(err)
	}
	if orig.PathHashCount() != 1 || !bytes.Equal(orig.Path, []byte{0xAA}) {
		t.Fatalf("append on the copy disturbed the original: % x", orig.Path)
	}
	if err := orig.AppendPathHash([]byte{0xCC}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fwd.Path, []byte{0xAA, 0xBB}) {
		t.Fatalf("the copy was corrupted by the original's append: % x", fwd.Path)
	}
	if !bytes.Equal(orig.Path, []byte{0xAA, 0xCC}) {
		t.Fatalf("original path wrong: % x", orig.Path)
	}

	// ConsumeNextHop must not compact through a shared array either.
	src, _ := ParsePacket(raw)
	src.SetPathHashSizeAndCount(1, 1)
	twin := *src
	if _, err := twin.ConsumeNextHop(); err != nil {
		t.Fatal(err)
	}
	if src.PathHashCount() != 1 || !bytes.Equal(src.Path, []byte{0xAA}) {
		t.Fatalf("consume on the copy disturbed the original: % x", src.Path)
	}
}

func TestParseDatagramRoundTrip(t *testing.T) {
	plain := []byte("hello addressed world")
	p, err := BuildDatagram(PayloadTypeTxtMsg, []byte{0x1E}, []byte{0x88}, testSecret, plain)
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseDatagram(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if d.DestHash[0] != 0x1E || d.SrcHash[0] != 0x88 {
		t.Fatalf("hashes: %x %x", d.DestHash, d.SrcHash)
	}
	back, err := d.Open(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back[:len(plain)], plain) {
		t.Fatalf("got %q", back)
	}

	// The reference treats dest ‖ src ‖ MAC with no ciphertext byte as
	// an incomplete data packet.
	if _, err := ParseDatagram(make([]byte, 2+CipherMACSize)); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("incomplete accepted: %v", err)
	}
}

func TestParseAnonDatagramRoundTrip(t *testing.T) {
	p, err := BuildAnonDatagram([]byte{0x42}, fwTestPub, testSecret, []byte("login"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseAnonDatagram(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if d.DestHash[0] != 0x42 || !bytes.Equal(d.SenderPub, fwTestPub) {
		t.Fatal("envelope fields wrong")
	}
	if _, err := d.Open(testSecret); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseAnonDatagram(make([]byte, 1+PubKeySize+CipherMACSize)); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("incomplete accepted: %v", err)
	}
}

func TestParseGroupDatagramRoundTrip(t *testing.T) {
	ch, err := NewGroupChannel(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	p, err := BuildGroupDatagram(PayloadTypeGrpTxt, ch, []byte("salut"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := ParseGroupDatagram(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if d.ChannelHash[0] != ch.Hash[0] {
		t.Fatal("channel hash mismatch")
	}
	back, err := d.Open(ch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back[:5], []byte("salut")) {
		t.Fatalf("got %q", back)
	}
}

// A 16-byte PSK keys the MAC as PSK ‖ 16 zero bytes while its channel
// hash covers only the 16 real bytes — the reference stores channel
// secrets in a zero-filled 32-byte array but hashes the PSK's real
// length. Both halves of that asymmetry are locked here.
func TestGroupChannelPSK16Semantics(t *testing.T) {
	psk := bytes.Repeat([]byte{0xA5}, 16)
	ch, err := NewGroupChannel(psk)
	if err != nil {
		t.Fatal(err)
	}

	wantHash := sha256.Sum256(psk) // over 16 bytes, not 32
	if ch.Hash[0] != wantHash[0] {
		t.Fatalf("hash %x, want %x", ch.Hash[0], wantHash[0])
	}

	padded := make([]byte, 32)
	copy(padded, psk)
	if !bytes.Equal(ch.Secret, padded) {
		t.Fatalf("secret not zero-padded: %x", ch.Secret)
	}

	// Sealed with the padded secret (as the firmware does), the channel
	// must open it.
	sealed, err := EncryptThenMAC(padded, []byte("public channel msg"))
	if err != nil {
		t.Fatal(err)
	}
	d := &GroupDatagram{ChannelHash: ch.Hash, Sealed: sealed}
	if _, err := d.Open(ch); err != nil {
		t.Fatalf("cannot open firmware-sealed data: %v", err)
	}

	if _, err := NewGroupChannel(make([]byte, 24)); !errors.Is(err, ErrBadKeyLength) {
		t.Fatalf("odd PSK size accepted: %v", err)
	}
}

func TestPathReturnRoundTrip(t *testing.T) {
	path := []byte{0x11, 0x22, 0x33}
	p, err := BuildPathReturn([]byte{0x0A}, []byte{0x0B}, testSecret, 3, path, 0x02, []byte("extra data"))
	if err != nil {
		t.Fatal(err)
	}
	if p.PayloadType() != PayloadTypePath {
		t.Fatalf("type=%v", p.PayloadType())
	}

	d, err := ParseDatagram(p.Payload)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := d.Open(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := DecodePathReturn(plain)
	if err != nil {
		t.Fatal(err)
	}
	if pr.PathLen != 3 || !bytes.Equal(pr.Path, path) || pr.ExtraType != 0x02 {
		t.Fatalf("decoded %+v", pr)
	}
	if !bytes.Equal(pr.Extra[:10], []byte("extra data")) {
		t.Fatalf("extra %q", pr.Extra)
	}
	// Padding beyond the extra must be zeros (block cipher padding).
	for _, b := range pr.Extra[10:] {
		if b != 0 {
			t.Fatalf("padding not zero: % x", pr.Extra)
		}
	}
}

// Without extra, the reference appends a dummy 0xFF type and 4 random
// bytes so the packet hash stays unique.
func TestPathReturnFillerUniquenessAndBounds(t *testing.T) {
	build := func() *Packet {
		p, err := BuildPathReturn([]byte{1}, []byte{2}, testSecret, 1, []byte{0x99}, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b := build().Hash(), build().Hash()
	if a == b {
		t.Fatal("two empty-extra path returns hash identically — filler missing?")
	}

	d, _ := ParseDatagram(build().Payload)
	plain, _ := d.Open(testSecret)
	pr, err := DecodePathReturn(plain)
	if err != nil {
		t.Fatal(err)
	}
	if pr.ExtraType != 0x0F { // 0xFF masked to the low nibble
		t.Fatalf("filler type = %#x", pr.ExtraType)
	}

	// Reference bound: path bytes + extra + 5 must fit MAX_COMBINED_PATH.
	if _, err := BuildPathReturn([]byte{1}, []byte{2}, testSecret, 1, []byte{0x99},
		1, make([]byte, maxCombinedPath-1-5+1)); !errors.Is(err, ErrPayloadFull) {
		t.Fatalf("oversized path return: %v", err)
	}
	if _, err := BuildPathReturn([]byte{1}, []byte{2}, testSecret, 0xC1, make([]byte, 4), 0, nil); !errors.Is(err, ErrInvalidPathLen) {
		t.Fatalf("reserved descriptor accepted: %v", err)
	}

	// A decrypted PATH with a bad descriptor is rejected, as the
	// reference receiver does.
	if _, err := DecodePathReturn([]byte{0xC1, 0, 0, 0, 0, 0}); !errors.Is(err, ErrBadPathEncoding) {
		t.Fatalf("bad inner descriptor: %v", err)
	}
}

func TestParseAckAndMultipart(t *testing.T) {
	crc := AckCRC([]byte("msg"), fwTestPub)
	ack, err := BuildAck([]byte{byte(crc), byte(crc >> 8), byte(crc >> 16), byte(crc >> 24)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAck(ack.Payload)
	if err != nil || got != crc {
		t.Fatalf("ParseAck=%08X err=%v, want %08X", got, err, crc)
	}
	if _, err := ParseAck([]byte{1, 2, 3}); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("short ack: %v", err)
	}

	multi, err := BuildMultiAck([]byte{0xDE, 0xAD, 0xBE, 0xEF}, 3)
	if err != nil {
		t.Fatal(err)
	}
	mp, err := ParseMultipart(multi.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if mp.Remaining != 3 || mp.Inner != PayloadTypeAck || !bytes.Equal(mp.Data, []byte{0xDE, 0xAD, 0xBE, 0xEF}) {
		t.Fatalf("multipart: %+v", mp)
	}
}

func TestParseTrace(t *testing.T) {
	p, err := BuildTrace(0xA1B2C3D4, 0x12345678, 0x01)
	if err != nil {
		t.Fatal(err)
	}
	// Route hashes ride in the payload (2-byte entries for flags&3 == 1);
	// traversed hops append SNR bytes to the packet path.
	p.Payload = append(p.Payload, 0x1E, 0xC7, 0x56, 0xB0)
	p.Path = []byte{0xF8, 0x14} // -2 dB and +5 dB, in quarter-dB units
	p.SetPathHashCount(2)

	tr, err := ParseTrace(p)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Tag != 0xA1B2C3D4 || tr.AuthCode != 0x12345678 || tr.Flags != 0x01 {
		t.Fatalf("header fields: %+v", tr)
	}
	if tr.HashWidth != 2 {
		t.Fatalf("hash width %d", tr.HashWidth)
	}
	if !bytes.Equal(tr.Route, []byte{0x1E, 0xC7, 0x56, 0xB0}) {
		t.Fatalf("route % x", tr.Route)
	}
	if tr.SNRx4[0] != -8 || tr.SNRx4[1] != 20 {
		t.Fatalf("SNRs %v", tr.SNRx4)
	}

	if _, err := ParseTrace(&Packet{Header: MakeHeader(RouteDirect, PayloadTypeAck, 0)}); !errors.Is(err, ErrBadPayloadType) {
		t.Fatalf("non-trace accepted: %v", err)
	}
}

func TestPathRelayHelpers(t *testing.T) {
	p := &Packet{Header: MakeHeader(RouteFlood, PayloadTypeGrpTxt, 0), Payload: []byte{1}}

	// Flood relay: append hop hashes one by one.
	for _, h := range []byte{0xAA, 0xBB, 0xCC} {
		if err := p.AppendPathHash([]byte{h}); err != nil {
			t.Fatal(err)
		}
	}
	if p.PathHashCount() != 3 || !bytes.Equal(p.Path, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("path % x (count %d)", p.Path, p.PathHashCount())
	}
	if err := p.AppendPathHash([]byte{1, 2}); !errors.Is(err, ErrInvalidPathLen) {
		t.Fatalf("wrong-size hash accepted: %v", err)
	}

	// The wire form must reflect the mutated path.
	raw, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	q, err := ParsePacket(raw)
	if err != nil {
		t.Fatal(err)
	}

	// Direct consumption: pop hops front to back.
	hop, err := q.ConsumeNextHop()
	if err != nil || hop[0] != 0xAA {
		t.Fatalf("hop % x err=%v", hop, err)
	}
	if q.PathHashCount() != 2 || !bytes.Equal(q.Path, []byte{0xBB, 0xCC}) {
		t.Fatalf("after pop: % x (count %d)", q.Path, q.PathHashCount())
	}
	q.ConsumeNextHop()
	q.ConsumeNextHop()
	if _, err := q.ConsumeNextHop(); err == nil {
		t.Fatal("popped an empty path")
	}

	// Append refuses to overflow the 6-bit hash count (63 for 1-byte
	// hashes — one below MaxPathSize, where the count would wrap).
	full := &Packet{Payload: []byte{1}}
	for range 63 {
		if err := full.AppendPathHash([]byte{0x77}); err != nil {
			t.Fatal(err)
		}
	}
	if err := full.AppendPathHash([]byte{0x77}); !errors.Is(err, ErrPathTooLarge) {
		t.Fatalf("64th hop accepted: %v", err)
	}
	if full.PathHashCount() != 63 {
		t.Fatalf("count %d after refusal", full.PathHashCount())
	}
}
