package meshcore

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func TestBuildDatagramEnvelope(t *testing.T) {
	plain := []byte("hello direct world")
	p, err := BuildDatagram(PayloadTypeTxtMsg, []byte{0x1E}, []byte{0x88}, testSecret, plain)
	if err != nil {
		t.Fatal(err)
	}
	if p.PayloadType() != PayloadTypeTxtMsg {
		t.Fatalf("type=%v", p.PayloadType())
	}
	// Envelope: dest hash | src hash | MAC | ciphertext.
	if p.Payload[0] != 0x1E || p.Payload[1] != 0x88 {
		t.Fatalf("hashes: % x", p.Payload[:2])
	}
	back, err := MACThenDecrypt(testSecret, p.Payload[2:])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back[:len(plain)], plain) {
		t.Fatalf("got %q", back)
	}

	if _, err := BuildDatagram(PayloadTypeAdvert, []byte{1}, []byte{2}, testSecret, plain); err == nil {
		t.Fatal("ADVERT accepted as datagram type")
	}
}

func TestBuildAnonDatagramCarriesSenderKey(t *testing.T) {
	p, err := BuildAnonDatagram([]byte{0x42}, fwTestPub, testSecret, []byte("login"))
	if err != nil {
		t.Fatal(err)
	}
	if p.PayloadType() != PayloadTypeAnonReq {
		t.Fatalf("type=%v", p.PayloadType())
	}
	if p.Payload[0] != 0x42 || !bytes.Equal(p.Payload[1:1+PubKeySize], fwTestPub) {
		t.Fatal("envelope layout wrong")
	}
	if _, err := MACThenDecrypt(testSecret, p.Payload[1+PubKeySize:]); err != nil {
		t.Fatal(err)
	}

	if _, err := BuildAnonDatagram([]byte{0x42}, fwTestPub[:16], testSecret, []byte("x")); err == nil {
		t.Fatal("short sender key accepted")
	}
}

func TestGroupChannelHashAndDatagram(t *testing.T) {
	secret := bytes.Repeat([]byte{0x77}, 32)
	ch, err := NewGroupChannel(secret)
	if err != nil {
		t.Fatal(err)
	}

	// The channel hash is SHA-256(secret) truncated, per the reference.
	want := sha256.Sum256(secret)
	if !bytes.Equal(ch.Hash, want[:PathHashSize]) {
		t.Fatalf("hash=%x, want %x", ch.Hash, want[:PathHashSize])
	}

	p, err := BuildGroupDatagram(PayloadTypeGrpTxt, ch, []byte("salut la chaine"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Payload[0] != ch.Hash[0] {
		t.Fatal("channel hash missing from envelope")
	}
	if _, err := MACThenDecrypt(ch.Secret, p.Payload[PathHashSize:]); err != nil {
		t.Fatal(err)
	}

	if _, err := BuildGroupDatagram(PayloadTypeTxtMsg, ch, []byte("x")); err == nil {
		t.Fatal("TXT_MSG accepted as group type")
	}
}

func TestAckAndMultiAck(t *testing.T) {
	crc := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	ack, err := BuildAck(crc)
	if err != nil {
		t.Fatal(err)
	}
	if ack.PayloadType() != PayloadTypeAck || !bytes.Equal(ack.Payload, crc) {
		t.Fatalf("ack: type=%v payload=% x", ack.PayloadType(), ack.Payload)
	}

	multi, err := BuildMultiAck(crc, 2)
	if err != nil {
		t.Fatal(err)
	}
	if multi.PayloadType() != PayloadTypeMultipart {
		t.Fatalf("type=%v", multi.PayloadType())
	}
	// Prefix byte: remaining count in the high nibble, inner type low.
	if multi.Payload[0] != (2<<4 | uint8(PayloadTypeAck)) {
		t.Fatalf("prefix=0x%02x", multi.Payload[0])
	}
	if !bytes.Equal(multi.Payload[1:], crc) {
		t.Fatal("wrapped CRC mangled")
	}
}

func TestBuildTraceLayout(t *testing.T) {
	p, err := BuildTrace(0xA1B2C3D4, 0x12345678, 0x01)
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0xD4, 0xC3, 0xB2, 0xA1, 0x78, 0x56, 0x34, 0x12, 0x01}
	if !bytes.Equal(p.Payload, want) {
		t.Fatalf("payload % x, want % x (uint32s little-endian)", p.Payload, want)
	}
	if p.PayloadType() != PayloadTypeTrace {
		t.Fatalf("type=%v", p.PayloadType())
	}
}

// AckCRC pins the reply-correlation preimage: SHA-256 of the decrypted
// message bytes followed by the SENDER's public key, truncated to 4
// bytes, read little-endian. Both ends must derive the same value.
func TestAckCRCPreimage(t *testing.T) {
	message := []byte("\x01\x02\x03\x04\x00hello")
	sum := sha256.Sum256(append(append([]byte(nil), message...), fwTestPub...))
	want := binary.LittleEndian.Uint32(sum[:4])

	if got := AckCRC(message, fwTestPub); got != want {
		t.Fatalf("AckCRC=0x%08X want 0x%08X", got, want)
	}
	if AckCRC(message, fwTestPub) == AckCRC(message[:len(message)-1], fwTestPub) {
		t.Fatal("CRC insensitive to message content")
	}
}

func TestPayloadBuildersRespectFrameLimits(t *testing.T) {
	// 168 bytes of plaintext → 176 ciphertext + 2 MAC + 2 hashes = 180 ✓
	if _, err := BuildDatagram(PayloadTypeReq, []byte{1}, []byte{2}, testSecret,
		bytes.Repeat([]byte{9}, 168)); err != nil {
		t.Fatalf("near-limit datagram refused: %v", err)
	}
	// 184 plaintext → 192 ciphertext alone exceeds MaxPacketPayload.
	if _, err := BuildDatagram(PayloadTypeReq, []byte{1}, []byte{2}, testSecret,
		bytes.Repeat([]byte{9}, MaxPacketPayload)); !errors.Is(err, ErrPayloadFull) {
		t.Fatalf("oversized datagram: err=%v", err)
	}
	if _, err := BuildRawCustom(nil); !errors.Is(err, ErrEmptyPayload) {
		t.Fatalf("empty raw: err=%v", err)
	}
}

// Every builder defaults the route to FLOOD (the send layer picks the
// final route), and the packet must already be transportable: header
// type set, payload marshallable.
func TestBuildersProduceTransportablePackets(t *testing.T) {
	ch, err := NewGroupChannel(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	builders := map[string]func() (*Packet, error){
		"datagram": func() (*Packet, error) {
			return BuildDatagram(PayloadTypeReq, []byte{1}, []byte{2}, testSecret, []byte("d"))
		},
		"anon":     func() (*Packet, error) { return BuildAnonDatagram([]byte{1}, fwTestPub, testSecret, []byte("a")) },
		"group":    func() (*Packet, error) { return BuildGroupDatagram(PayloadTypeGrpData, ch, []byte("g")) },
		"ack":      func() (*Packet, error) { return BuildAck([]byte{1, 2, 3, 4}) },
		"multiack": func() (*Packet, error) { return BuildMultiAck([]byte{1, 2, 3, 4}, 1) },
		"trace":    func() (*Packet, error) { return BuildTrace(1, 2, 0) },
		"raw":      func() (*Packet, error) { return BuildRawCustom([]byte{0xFF}) },
		"control":  func() (*Packet, error) { return BuildControl([]byte{0x80}) },
	}
	for name, build := range builders {
		p, err := build()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		raw, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("%s: marshal: %v", name, err)
		}
		if _, err := ParsePacket(raw); err != nil {
			t.Fatalf("%s: reparse: %v", name, err)
		}
		if p.Route() != RouteFlood {
			t.Errorf("%s: route = %v, want the FLOOD default", name, p.Route())
		}
	}
}

func TestChannelDerivations(t *testing.T) {
	// Public: the well-known PSK, hash 0x11 (verified against live traffic).
	pub := NewPublicChannel()
	if got := hex.EncodeToString(pub.Hash); got != "11" {
		t.Fatalf("Public channel hash = %s, want 11", got)
	}

	// Hashtag: PSK = SHA256("#"+tag)[:16] — pinned formula.
	sum := sha256.Sum256([]byte("#test"))
	wantHash := sha256.Sum256(sum[:16])
	ch := NewHashtagChannel("test")
	if !bytes.Equal(ch.Hash, wantHash[:PathHashSize]) {
		t.Fatalf("#test hash = %x, want %x", ch.Hash, wantHash[:PathHashSize])
	}
	// A leading '#' must not be doubled.
	if !bytes.Equal(NewHashtagChannel("#test").Hash, ch.Hash) {
		t.Fatal("leading # doubled")
	}
	// The tag is case-sensitive (the apps do not fold case).
	if bytes.Equal(NewHashtagChannel("Test").Hash, ch.Hash) {
		t.Fatal("hashtag derivation folded case")
	}

	// Base64 PSK round-trips through NewGroupChannelFromBase64.
	fromB64, err := NewGroupChannelFromBase64(PublicChannelPSKBase64)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fromB64.Secret, pub.Secret) {
		t.Fatal("base64 PSK decode mismatch")
	}
	if _, err := NewGroupChannelFromBase64("not base64!!"); err == nil {
		t.Fatal("bad base64 accepted")
	}
}
