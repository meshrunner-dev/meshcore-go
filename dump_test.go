package meshcore

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func fieldFramePacket(t *testing.T) *Packet {
	t.Helper()
	frame, _ := hex.DecodeString("14db9e000041882f6ae9a1734cb70d8861626364656667")
	p, err := ParsePacket(frame)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPacketStringOneLine(t *testing.T) {
	p := fieldFramePacket(t)
	want := "GRP_TXT TRANSPORT_FLOOD ver=0 transport=9edb:0000 path=1×2B:882f payload=15B hash=b43738ad31c3a15b"
	if got := p.String(); got != want {
		t.Fatalf("String:\n got  %s\n want %s", got, want)
	}
	// fmt integration: %v must produce the same line.
	if got := fmt.Sprintf("%v", p); got != want {
		t.Fatalf("%%v drifted: %s", got)
	}
}

func TestPacketSummaryAndRawHex(t *testing.T) {
	p := fieldFramePacket(t)
	if got, want := p.Summary(), "GRP_TXT 23B 14db9e000041882f…"; got != want {
		t.Fatalf("Summary: %s", got)
	}
	raw, _ := p.MarshalBinary()
	if p.RawHex() != hex.EncodeToString(raw) {
		t.Fatal("RawHex does not match the wire form")
	}
}

// Every line of a framed dump must have the same on-screen width and
// carry the box-drawing borders.
func TestDumpFrameAlignment(t *testing.T) {
	for _, dump := range []string{
		fieldFramePacket(t).Dump(),
		(&AdvertData{Type: AdvTypeRepeater, HasLoc: true, Name: "node"}).Dump(),
		(&Trace{Tag: 1, AuthCode: 2, HashWidth: 2, Route: []byte{1, 2, 3, 4}, SNRx4: []int8{-8, 20}}).Dump(),
	} {
		lines := strings.Split(dump, "\n")
		if len(lines) < 3 {
			t.Fatalf("dump too short:\n%s", dump)
		}
		width := utf8.RuneCountInString(lines[0])
		for i, l := range lines {
			if utf8.RuneCountInString(l) != width {
				t.Fatalf("line %d width %d != %d:\n%s", i, utf8.RuneCountInString(l), width, dump)
			}
		}
		if !strings.HasPrefix(lines[0], "┌─ ") || !strings.HasPrefix(lines[len(lines)-1], "└") {
			t.Fatalf("missing frame borders:\n%s", dump)
		}
	}
}

func TestDecodedObjectStrings(t *testing.T) {
	li, _ := LocalIdentityFromKeys(fwTestPrv, nil)
	ap, err := BuildAdvert(li, time.Unix(1765000000, 0).UTC(),
		&AdvertData{Type: AdvTypeChat, Name: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	adv, err := ParseAdvert(ap.Payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, part := range []string{"ADVERT", "from=1ec77175…0c10", `name="Alice"`, "ts=2025-12-06T"} {
		if !strings.Contains(adv.String(), part) {
			t.Errorf("advert %q lacks %q", adv.String(), part)
		}
	}

	d := &Datagram{DestHash: []byte{0x1E}, SrcHash: []byte{0x88}, Sealed: make([]byte, 27)}
	if got, want := d.String(), "DATAGRAM dest=1e src=88 sealed=27B"; got != want {
		t.Errorf("datagram: %s", got)
	}

	tr := &Trace{Tag: 0xA1B2C3D4, AuthCode: 0x12345678, Flags: 1, HashWidth: 2,
		Route: []byte{1, 2, 3, 4}, SNRx4: []int8{-8, 20}}
	for _, part := range []string{"TRACE", "tag=a1b2c3d4", "route=2×2B", "snr_db=[-2.00 +5.00]"} {
		if !strings.Contains(tr.String(), part) {
			t.Errorf("trace %q lacks %q", tr.String(), part)
		}
	}

	m := &Multipart{Remaining: 2, Inner: PayloadTypeAck, Data: []byte{1, 2, 3, 4}}
	if got, want := m.String(), "MULTIPART remaining=2 inner=ACK data=4B"; got != want {
		t.Errorf("multipart: %s", got)
	}
}

// Formatting a LocalIdentity or GroupChannel with any fmt verb must
// never reveal key material — the whole point of their String/GoString.
func TestSecretsAreRedactedInAllFmtVerbs(t *testing.T) {
	li, _ := LocalIdentityFromKeys(fwTestPrv, nil)
	prvHex := hex.EncodeToString(fwTestPrv)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, out := range []string{fmt.Sprintf(verb, li), fmt.Sprintf(verb, *li)} {
			for i := 0; i+8 <= len(prvHex); i += 8 {
				if strings.Contains(strings.ToLower(out), prvHex[i:i+8]) {
					t.Fatalf("verb %s leaks private key fragment %s: %s", verb, prvHex[i:i+8], out)
				}
			}
		}
	}

	psk := []byte{0xA5, 0xA5, 0xA5, 0xA5, 0xB6, 0xB6, 0xB6, 0xB6, 0xC7, 0xC7, 0xC7, 0xC7, 0xD8, 0xD8, 0xD8, 0xD8}
	ch, _ := NewGroupChannel(psk)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, out := range []string{fmt.Sprintf(verb, ch), fmt.Sprintf(verb, *ch)} {
			if strings.Contains(strings.ToLower(out), "a5a5a5a5") {
				t.Fatalf("verb %s leaks the channel PSK: %s", verb, out)
			}
		}
	}
}

func TestSafeText(t *testing.T) {
	// Legitimate content is preserved verbatim.
	for _, ok := range []string{"Alice", "café ☕", "FR78 🍾", "🇫🇷", "a👨‍👩‍👧b"} {
		if got := safeText(ok); got != ok {
			t.Errorf("safeText(%q) = %q, want unchanged", ok, got)
		}
	}
	// Dangerous characters are replaced, never passed through.
	for _, bad := range []struct{ in string }{
		{"\x1b[31mred"},     // ANSI escape
		{"clear\x1b[2J"},    // screen-clear
		{"a\x07b"},          // BEL
		{"tab\tend"},        // control
		{"spoof\u202etxet"}, // right-to-left override
		{"c1\x85here"},      // C1 control (NEL)
	} {
		out := safeText(bad.in)
		for _, r := range []rune{'\x1b', '\x07', '\t', '\u0085', '\u202e'} {
			if strings.ContainsRune(out, r) {
				t.Errorf("safeText(%q) leaked %U: %q", bad.in, r, out)
			}
		}
		if !strings.ContainsRune(out, '\ufffd') {
			t.Errorf("safeText(%q) = %q, expected a replacement char", bad.in, out)
		}
	}
}

// An ADVERT packet's Dump must carry the node type and name in a field,
// with the name sanitised — an advert is untrusted network input.
func TestPacketDumpShowsAdvertName(t *testing.T) {
	li, _ := LocalIdentityFromKeys(fwTestPrv, nil)

	// Legitimate name with emoji is shown.
	p, err := BuildAdvert(li, time.Unix(1765000000, 0),
		&AdvertData{Type: AdvTypeRepeater, Name: "FR75 Café ☕"})
	if err != nil {
		t.Fatal(err)
	}
	dump := p.Dump()
	if !strings.Contains(dump, "advert") || !strings.Contains(dump, "REPEATER") ||
		!strings.Contains(dump, "FR75 Café ☕") {
		t.Fatalf("advert name/type missing from dump:\n%s", dump)
	}

	// A name attempting ANSI injection must not put a raw escape byte in
	// the rendered dump.
	q, err := BuildAdvert(li, time.Unix(1765000000, 0),
		&AdvertData{Type: AdvTypeChat, Name: "x\x1b[31m\x1b[2J"})
	if err != nil {
		t.Fatal(err)
	}
	if d := q.Dump(); strings.ContainsRune(d, '\x1b') {
		t.Fatalf("dump contains a raw ESC byte:\n%q", d)
	}
}
