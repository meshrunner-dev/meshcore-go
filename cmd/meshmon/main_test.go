package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"meshrunner.dev/pkg/meshcore"
)

func TestExtractFrame(t *testing.T) {
	frame := []byte{0x11, 0x00, 0xAA, 0xBB}
	hexFrame := hex.EncodeToString(frame)

	// JSON with a raw hex field (the packet-capture form).
	js := []byte(`{"type":"PACKET","raw":"` + hexFrame + `","snr":"12"}`)
	if got, ok := extractFrame(js); !ok || string(got) != string(frame) {
		t.Fatalf("JSON raw: got %x ok=%v", got, ok)
	}
	// JSON telemetry with no frame field.
	if _, ok := extractFrame([]byte(`{"status":"online","battery_mv":4000}`)); ok {
		t.Fatal("telemetry JSON yielded a frame")
	}
	// Leading whitespace before JSON.
	if _, ok := extractFrame([]byte("  \n" + string(js))); !ok {
		t.Fatal("leading whitespace broke JSON detection")
	}
	// Raw binary frame as the payload body.
	if got, ok := extractFrame(frame); !ok || string(got) != string(frame) {
		t.Fatalf("raw body: got %x ok=%v", got, ok)
	}
	if _, ok := extractFrame(nil); ok {
		t.Fatal("empty payload yielded a frame")
	}
}

// The generated JWT must be a MeshCore-style token whose Ed25519
// signature verifies under the identity's own key — proving meshmon
// can authenticate as a mesh observer.
func TestMeshcoreJWTVerifies(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	id, err := meshcore.LocalIdentityFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1765000000, 0)

	user, token := meshcoreJWT(id, "letsmesh", 5*time.Minute, now)
	if user != "v1_"+hex.EncodeToString(id.PubKey[:]) {
		t.Fatalf("username = %q", user)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}
	// Header and payload are base64url (no padding); signature is hex.
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || string(hdr) != `{"alg":"Ed25519","typ":"JWT"}` {
		t.Fatalf("header = %s err=%v", hdr, err)
	}
	var claims struct {
		PublicKey string `json:"publicKey"`
		Aud       string `json:"aud"`
		Iat       int64  `json:"iat"`
		Exp       int64  `json:"exp"`
	}
	pl, _ := base64.RawURLEncoding.DecodeString(parts[1])
	if err := json.Unmarshal(pl, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Aud != "letsmesh" || claims.Iat != now.Unix() || claims.Exp != now.Add(5*time.Minute).Unix() {
		t.Fatalf("claims: %+v", claims)
	}
	if claims.PublicKey != strings.ToUpper(hex.EncodeToString(id.PubKey[:])) {
		t.Fatal("publicKey claim not the uppercase key")
	}

	sig, err := hex.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature not hex: %v", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !id.Verify(sig, []byte(signingInput)) {
		t.Fatal("JWT signature does not verify under the identity key")
	}
}

func TestDeduper(t *testing.T) {
	d := newDeduper(3)
	var a, b, c, e [8]byte
	a[0], b[0], c[0], e[0] = 1, 2, 3, 4

	if d.seen(a) {
		t.Fatal("first sight reported as seen")
	}
	if !d.seen(a) {
		t.Fatal("second sight not deduped")
	}
	d.seen(b)
	d.seen(c)
	// Window is full (a,b,c); adding e evicts a, so a is fresh again.
	if d.seen(e) {
		t.Fatal("e wrongly seen")
	}
	if d.seen(a) {
		t.Fatal("a should have been evicted and seen fresh")
	}
	// Re-adding a evicted b (the oldest slot); c is still in the window.
	if !d.seen(c) {
		t.Fatal("c should still be remembered")
	}
}
