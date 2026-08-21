package meshcore

import (
	"encoding/hex"
	"testing"
	"time"
)

func TestTextPlaintextReferenceBytes(t *testing.T) {
	at := time.Unix(0x11223344, 0)
	// Plain: [ts LE][flags=0]["hi"].
	if got := hex.EncodeToString(BuildTextPlaintext(at, TxtTypePlain, "hi")); got != "44332211006869" {
		t.Errorf("plain = %s, want 44332211006869", got)
	}
	// CLI: the type rides in bits 2+, so flags = 1<<2 = 0x04.
	if got := hex.EncodeToString(BuildTextPlaintext(at, TxtTypeCLIData, "hi")); got != "44332211046869" {
		t.Errorf("cli = %s, want 44332211046869", got)
	}
}

func TestTextPlaintextRoundTrip(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	for _, tc := range []struct {
		typ     uint8
		text    string
		attempt int
	}{
		{TxtTypePlain, "hello world", 0},
		{TxtTypeCLIData, "get status", 2},
		{TxtTypePlain, "retry me", 7}, // >3: extended attempt tail
		{TxtTypePlain, "", 0},
	} {
		plain := BuildTextPlaintextAttempt(at, tc.typ, tc.text, tc.attempt)
		got, err := ParseTextPlaintext(plain)
		if err != nil {
			t.Fatalf("%+v: %v", tc, err)
		}
		if got.Type != tc.typ || got.Text != tc.text {
			t.Errorf("%+v: got type=%d text=%q", tc, got.Type, got.Text)
		}
		if !got.Timestamp.Equal(at) {
			t.Errorf("%+v: timestamp %v", tc, got.Timestamp)
		}
		if int(got.Attempt) != tc.attempt {
			t.Errorf("%+v: attempt = %d, want %d", tc, got.Attempt, tc.attempt)
		}
	}
}

// A cipher block pads the plaintext with zeros; the text must still end
// at its NUL and no phantom attempt must be read from the padding.
func TestTextPlaintextCipherPadding(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	plain := BuildTextPlaintext(at, TxtTypePlain, "hi") // attempt 0, no tail
	padded := make([]byte, len(plain), len(plain)+6)    // simulate block padding
	copy(padded, plain)
	padded = append(padded, 0, 0, 0, 0, 0, 0)
	got, err := ParseTextPlaintext(padded)
	if err != nil {
		t.Fatal(err)
	}
	if got.Text != "hi" || got.Attempt != 0 {
		t.Errorf("padded parse: text=%q attempt=%d", got.Text, got.Attempt)
	}
}

// The ACK the reference expects is computed over timestamp‖flags‖text —
// the message head only, NOT the [0x00][attempt] retransmission tail. So
// the CRC over the head must differ from one taken over head+tail,
// proving the tail is excluded.
func TestTextPlaintextAckCRCExcludesTail(t *testing.T) {
	at := time.Unix(1_700_000_000, 0)
	pub := make([]byte, PubKeySize)
	full := BuildTextPlaintextAttempt(at, TxtTypePlain, "ack me", 5) // head + tail
	headLen := 5 + len("ack me")
	if AckCRC(full[:headLen], pub) == AckCRC(full, pub) {
		t.Error("ACK CRC did not change when the tail was included — tail not excluded")
	}
}

func TestGroupTextRoundTrip(t *testing.T) {
	at := time.Unix(1_700_000_500, 0)
	plain := BuildGroupText(at, "alice", "hey everyone")
	// [ts LE][flags=0]["alice: hey everyone"].
	if got := hex.EncodeToString(plain[:5]); got[8:10] != "00" {
		t.Errorf("group flags byte not zero: %s", got)
	}
	got, err := ParseGroupText(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sender != "alice" || got.Text != "hey everyone" || !got.Timestamp.Equal(at) {
		t.Errorf("got %+v", got)
	}
}

func TestGroupTextRejectsSubtype(t *testing.T) {
	plain := BuildGroupText(time.Unix(1, 0), "a", "b")
	plain[4] = 1 << 2 // a non-plain subtype
	if _, err := ParseGroupText(plain); err == nil {
		t.Error("accepted an unsupported group text subtype")
	}
}
