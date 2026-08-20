package meshcore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
)

// goldenRecord is one line of a testdata/golden file — vectors produced
// by the MeshCore reference implementation. The schema is documented in
// testdata/README.md and is the contract with the generator harness.
type goldenRecord struct {
	Test      string `json:"test"`
	Frame     string `json:"frame"`
	Hash      string `json:"hash"`
	Prv       string `json:"prv"`
	PrvA      string `json:"prv_a"`
	Pub       string `json:"pub"`
	PubB      string `json:"pub_b"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
	Secret    string `json:"secret"`
	Plain     string `json:"plain"`
	In        string `json:"in"`
	Out       string `json:"out"`
	Payload   string `json:"payload"`
	Valid     *bool  `json:"valid"`

	// path_return fields — the reference receiver's own extraction.
	PathLen   *uint8 `json:"path_len"`
	Path      string `json:"path"`
	ExtraType uint8  `json:"extra_type"`
	Extra     string `json:"extra"`

	// channel fields.
	PSK string `json:"psk"`

	// advert_appdata fields — the reference parser's own reading.
	AppData string `json:"appdata"`
	Canon   bool   `json:"canon"`
	AdvType uint8  `json:"adv_type"`
	HasLoc  bool   `json:"has_loc"`
	Lat     int32  `json:"lat"`
	Lon     int32  `json:"lon"`
	Feat1   uint16 `json:"feat1"`
	Feat2   uint16 `json:"feat2"`
	NameHex string `json:"name_hex"`
}

// wantValid reads the record's verdict; a missing valid field means true.
func (r *goldenRecord) wantValid() bool { return r.Valid == nil || *r.Valid }

// TestGoldenVectors replays every reference-produced vector under
// testdata/golden. An unknown kind fails on purpose: generator and
// consumer must stay in lockstep.
func TestGoldenVectors(t *testing.T) {
	var files []string
	for _, pat := range []string{"*.ndjson", "*.ndjson.gz"} {
		m, err := filepath.Glob(filepath.Join("testdata", "golden", pat))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Skip("no golden vectors in testdata/golden yet")
	}

	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			n := 0
			for line := range ndjsonLines(t, path) {
				n++
				var rec goldenRecord
				if err := json.Unmarshal(line, &rec); err != nil {
					t.Fatalf("record %d: invalid JSON: %v", n, err)
				}
				runGolden(t, n, &rec)
			}
			t.Logf("%d vectors replayed", n)
		})
	}
}

func runGolden(t *testing.T, n int, rec *goldenRecord) {
	t.Helper()
	h := func(field, s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("record %d: field %q: %v", n, field, err)
		}
		return b
	}

	switch rec.Test {
	case "packet_roundtrip":
		frame := h("frame", rec.Frame)
		p, err := ParsePacket(frame)
		if err != nil {
			t.Errorf("record %d: parse: %v", n, err)
			return
		}
		back, err := p.MarshalBinary()
		if err != nil {
			t.Errorf("record %d: re-encode: %v", n, err)
			return
		}
		if !bytes.Equal(back, frame) {
			t.Errorf("record %d: round-trip drift:\n got % x\nwant % x", n, back, frame)
		}

	case "packet_hash":
		p, err := ParsePacket(h("frame", rec.Frame))
		if err != nil {
			t.Errorf("record %d: parse: %v", n, err)
			return
		}
		got := p.Hash()
		if !bytes.Equal(got[:], h("hash", rec.Hash)) {
			t.Errorf("record %d: hash = %x, firmware says %s", n, got, rec.Hash)
		}

	case "sign":
		li, err := LocalIdentityFromKeys(h("prv", rec.Prv), nil)
		if err != nil {
			t.Errorf("record %d: load key: %v", n, err)
			return
		}
		if got := li.Sign(h("message", rec.Message)); !bytes.Equal(got, h("signature", rec.Signature)) {
			t.Errorf("record %d: signature mismatch", n)
		}

	case "shared_secret":
		li, err := LocalIdentityFromKeys(h("prv_a", rec.PrvA), nil)
		if err != nil {
			t.Errorf("record %d: load key: %v", n, err)
			return
		}
		got, err := li.SharedSecret(h("pub_b", rec.PubB))
		if err != nil {
			t.Errorf("record %d: %v", n, err)
			return
		}
		if !bytes.Equal(got, h("secret", rec.Secret)) {
			t.Errorf("record %d: shared secret mismatch", n)
		}

	case "encrypt_then_mac":
		got, err := EncryptThenMAC(h("secret", rec.Secret), h("plain", rec.Plain))
		if err != nil {
			t.Errorf("record %d: %v", n, err)
			return
		}
		if !bytes.Equal(got, h("out", rec.Out)) {
			t.Errorf("record %d: encrypt-then-MAC mismatch:\n got % x\nwant %s", n, got, rec.Out)
		}

	case "advert_verify":
		_, err := ParseAdvert(h("payload", rec.Payload))
		if valid := err == nil; valid != rec.wantValid() {
			t.Errorf("record %d: advert verify = %v (err=%v), reference says %v", n, valid, err, rec.wantValid())
		}

	case "packet_parse":
		_, err := ParsePacket(h("frame", rec.Frame))
		if valid := err == nil; valid != rec.wantValid() {
			t.Errorf("record %d: parse verdict = %v (err=%v), reference says %v (frame=%s)",
				n, valid, err, rec.wantValid(), rec.Frame)
		}

	case "verify":
		id, err := IdentityFromBytes(h("pub", rec.Pub))
		if err != nil {
			t.Errorf("record %d: load pub: %v", n, err)
			return
		}
		if got := id.Verify(h("signature", rec.Signature), h("message", rec.Message)); got != rec.wantValid() {
			t.Errorf("record %d: verify = %v, reference says %v", n, got, rec.wantValid())
		}

	case "mac_then_decrypt":
		got, err := MACThenDecrypt(h("secret", rec.Secret), h("in", rec.In))
		if valid := err == nil; valid != rec.wantValid() {
			t.Errorf("record %d: MAC verdict = %v (err=%v), reference says %v", n, valid, err, rec.wantValid())
			return
		}
		if err == nil && !bytes.Equal(got, h("plain", rec.Plain)) {
			t.Errorf("record %d: decrypted\n got  % x\nwant % x", n, got, h("plain", rec.Plain))
		}

	case "path_return":
		// Mirror the receiver pipeline; any stage may reject when the
		// reference says invalid.
		pr, err := func() (*PathReturn, error) {
			d, err := ParseDatagram(h("payload", rec.Payload))
			if err != nil {
				return nil, err
			}
			plain, err := d.Open(h("secret", rec.Secret))
			if err != nil {
				return nil, err
			}
			return DecodePathReturn(plain)
		}()
		if valid := err == nil; valid != rec.wantValid() {
			t.Errorf("record %d: path return verdict = %v (err=%v), reference says %v", n, valid, err, rec.wantValid())
			return
		}
		if err != nil {
			return
		}
		if rec.PathLen == nil || pr.PathLen != *rec.PathLen ||
			!bytes.Equal(pr.Path, h("path", rec.Path)) ||
			pr.ExtraType != rec.ExtraType ||
			!bytes.Equal(pr.Extra, h("extra", rec.Extra)) {
			t.Errorf("record %d: path return drift:\n got %+v\n ref path_len=%v path=%s extra_type=%d extra=%s",
				n, pr, rec.PathLen, rec.Path, rec.ExtraType, rec.Extra)
		}

	case "channel":
		ch, err := NewGroupChannel(h("psk", rec.PSK))
		if err != nil {
			t.Errorf("record %d: NewGroupChannel: %v", n, err)
			return
		}
		if !bytes.Equal(ch.Hash, h("hash", rec.Hash)) {
			t.Errorf("record %d: channel hash %x, reference says %s", n, ch.Hash, rec.Hash)
		}
		plain, err := MACThenDecrypt(ch.Secret, h("in", rec.In))
		if err != nil {
			t.Errorf("record %d: cannot open firmware-sealed channel data: %v", n, err)
			return
		}
		if !bytes.Equal(plain, h("plain", rec.Plain)) {
			t.Errorf("record %d: channel plaintext mismatch", n)
		}

	case "advert_appdata":
		appData := h("appdata", rec.AppData)
		parsed, err := ParseAdvertData(appData)
		if valid := err == nil; valid != rec.wantValid() {
			t.Errorf("record %d: app-data verdict = %v (err=%v), reference says %v (appdata=%s)",
				n, valid, err, rec.wantValid(), rec.AppData)
			return
		}
		if err != nil {
			return
		}
		want := AdvertData{
			Type:   rec.AdvType,
			HasLoc: rec.HasLoc,
			LatE6:  rec.Lat,
			LonE6:  rec.Lon,
			Feat1:  rec.Feat1,
			Feat2:  rec.Feat2,
			Name:   string(h("name_hex", rec.NameHex)),
		}
		if *parsed != want {
			t.Errorf("record %d: app-data drift:\n got  %+v\n want %+v", n, *parsed, want)
			return
		}
		if rec.Canon { // builder-produced blobs must re-encode byte-identically
			if back := parsed.EncodeAppData(); !bytes.Equal(back, appData) {
				t.Errorf("record %d: re-encode drift:\n got  % x\n want %s", n, back, rec.AppData)
			}
		}

	default:
		t.Fatalf("record %d: unknown golden kind %q — update golden_test.go "+
			"and testdata/README.md together", n, rec.Test)
	}
}
