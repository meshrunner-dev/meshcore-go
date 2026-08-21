package meshcore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestAdminFraming(t *testing.T) {
	framed := FrameAdmin(0x11223344, []byte("hello"))
	if !bytes.Equal(framed, []byte{0x44, 0x33, 0x22, 0x11, 'h', 'e', 'l', 'l', 'o'}) {
		t.Fatalf("framed = %x", framed)
	}
	ts, body, err := UnframeAdmin(framed)
	if err != nil || ts != 0x11223344 || string(body) != "hello" {
		t.Fatalf("ts=%#x body=%q err=%v", ts, body, err)
	}
	if _, _, err := UnframeAdmin([]byte{1, 2, 3}); !errors.Is(err, ErrShortAdminFrame) {
		t.Errorf("short frame: %v", err)
	}
}

// The full login flow: a client's ANON_REQ reaches the repeater, which
// derives the same shared secret from the sender's public key, opens
// the request, reads the anti-replay timestamp and password, and
// replies with a RESPONSE the client can open.
func TestLoginRoundTrip(t *testing.T) {
	client, err := NewLocalIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	repeater, err := NewLocalIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Client side: build the login.
	const ts = 1_700_000_042
	pkt, clientSecret, err := BuildLoginReq(client, repeater.PubKey[:], ts, "s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if pkt.PayloadType() != PayloadTypeAnonReq {
		t.Fatalf("login is a %v, want ANON_REQ", pkt.PayloadType())
	}

	// Repeater side: parse the anon datagram, derive the secret from
	// the sender's key in the clear, open, and check the framing.
	wire, _ := pkt.MarshalBinary()
	got, _ := ParsePacket(wire)
	anon, err := ParseAnonDatagram(got.Payload)
	if err != nil {
		t.Fatal(err)
	}
	repeaterSecret, err := repeater.SharedSecret(anon.SenderPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(repeaterSecret, clientSecret) {
		t.Fatal("the two sides derived different shared secrets")
	}
	plain, err := anon.Open(repeaterSecret)
	if err != nil {
		t.Fatal(err)
	}
	gotTS, body, err := UnframeAdmin(plain)
	// The cipher pads to a block; the password is read up to its NUL.
	if i := bytes.IndexByte(body, 0); i >= 0 {
		body = body[:i]
	}
	if err != nil || gotTS != ts || string(body) != "s3cret" {
		t.Fatalf("login plaintext: ts=%d body=%q err=%v", gotTS, body, err)
	}

	// Repeater replies; client opens the response.
	resp, err := BuildResponse(client.PubKey[:PathHashSize], repeater.PubKey[:PathHashSize],
		repeaterSecret, ts, []byte{RespServerLoginOK, 0x01 /* is_admin */})
	if err != nil {
		t.Fatal(err)
	}
	rwire, _ := resp.MarshalBinary()
	rgot, _ := ParsePacket(rwire)
	dg, err := ParseDatagram(rgot.Payload)
	if err != nil {
		t.Fatal(err)
	}
	rplain, err := dg.Open(clientSecret)
	if err != nil {
		t.Fatal(err)
	}
	_, rbody, _ := UnframeAdmin(rplain)
	if len(rbody) < 1 || rbody[0] != RespServerLoginOK {
		t.Fatalf("response body = %x, want a login-OK", rbody)
	}
}

// A command REQ after login round-trips under the same secret.
func TestRequestRoundTrip(t *testing.T) {
	client, _ := NewLocalIdentity(rand.Reader)
	repeater, _ := NewLocalIdentity(rand.Reader)
	secret, _ := client.SharedSecret(repeater.PubKey[:])

	pkt, err := BuildRequest(client, repeater.PubKey[:], secret, 1_700_000_100, []byte{ReqTypeGetStatus})
	if err != nil {
		t.Fatal(err)
	}
	if pkt.PayloadType() != PayloadTypeReq {
		t.Fatalf("request is a %v, want REQ", pkt.PayloadType())
	}
	dg, _ := ParseDatagram(pkt.Payload)
	plain, err := dg.Open(secret)
	if err != nil {
		t.Fatal(err)
	}
	ts, body, _ := UnframeAdmin(plain)
	// A one-byte command comes back padded; only its first byte matters.
	if ts != 1_700_000_100 || len(body) == 0 || body[0] != ReqTypeGetStatus {
		t.Fatalf("command: ts=%d body=%x", ts, body)
	}
}
