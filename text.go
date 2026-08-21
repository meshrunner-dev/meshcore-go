package meshcore

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// The decrypted plaintext of a text message, peer or group, begins with
// a 4-byte little-endian timestamp and a flags byte, then the text. The
// flags byte carries the message subtype in its upper six bits and, for
// peer messages, a retransmission counter in its low two.

// Text message subtypes (the flags byte's upper six bits).
const (
	TxtTypePlain       uint8 = 0 // a plain text message
	TxtTypeCLIData     uint8 = 1 // a CLI command
	TxtTypeSignedPlain uint8 = 2 // plain text, signed by the sender
)

// TextPlaintext is the decrypted content of a TXT_MSG (the plaintext
// behind a peer Datagram).
type TextPlaintext struct {
	Timestamp time.Time
	Type      uint8 // one of TxtType*
	Attempt   uint8 // retransmission counter
	Text      string
}

// BuildTextPlaintext builds the plaintext of a plain or CLI text
// message: timestamp, a flags byte carrying the subtype, then the text.
// Seal it with BuildDatagram(PayloadTypeTxtMsg, …).
func BuildTextPlaintext(sentAt time.Time, txtType uint8, text string) []byte {
	return BuildTextPlaintextAttempt(sentAt, txtType, text, 0)
}

// BuildTextPlaintextAttempt is BuildTextPlaintext with a retransmission
// counter. Attempts 0-3 ride in the low two bits of the flags byte;
// beyond that the byte wraps, so a [0x00][attempt] tail is appended to
// keep each retransmission's packet hash distinct — matching the
// reference composeMsgPacket. The expected ACK (see AckCRC) is computed
// over the timestamp‖flags‖text, NOT the tail, so recompute it per
// attempt.
func BuildTextPlaintextAttempt(sentAt time.Time, txtType uint8, text string, attempt int) []byte {
	out := make([]byte, 5, 5+len(text)+2)
	binary.LittleEndian.PutUint32(out, uint32(sentAt.Unix()))
	out[4] = byte(attempt&0x03) | txtType<<2
	out = append(out, text...)
	if attempt > 3 {
		out = append(out, 0x00, byte(attempt))
	}
	return out
}

// ParseTextPlaintext decodes a TXT_MSG plaintext. The body may be zero-
// padded by the cipher block, so the text ends at its first NUL; a
// non-zero byte past that NUL is the extended retransmission counter.
func ParseTextPlaintext(plain []byte) (*TextPlaintext, error) {
	if len(plain) < 5 {
		return nil, ErrShortFrame
	}
	flags := plain[4]
	m := &TextPlaintext{
		Timestamp: time.Unix(int64(binary.LittleEndian.Uint32(plain[:4])), 0),
		Type:      flags >> 2,
		Attempt:   flags & 0x03,
	}
	body := plain[5:]
	// A signed message carries a 4-byte prefix (the sender's sync time)
	// ahead of the text.
	if m.Type == TxtTypeSignedPlain && len(body) >= 4 {
		body = body[4:]
	}
	text, tail := splitCString(body)
	m.Text = text
	if len(tail) >= 1 && tail[0] != 0 {
		m.Attempt = tail[0]
	}
	return m, nil
}

// GroupTextPlaintext is the decrypted content of a GRP_TXT — a channel
// message whose text is prefixed with the sender's name.
type GroupTextPlaintext struct {
	Timestamp time.Time
	Sender    string
	Text      string
}

// BuildGroupText builds a GRP_TXT plaintext: timestamp, a zero flags
// byte (plain is the only group subtype the reference accepts), then
// "sender: text". Seal it with BuildGroupDatagram(PayloadTypeGrpTxt, …).
func BuildGroupText(sentAt time.Time, sender, text string) []byte {
	out := make([]byte, 5, 5+len(sender)+2+len(text))
	binary.LittleEndian.PutUint32(out, uint32(sentAt.Unix()))
	out[4] = 0 // TXT_TYPE_PLAIN — the reference drops any other group type
	out = append(out, sender...)
	out = append(out, ':', ' ')
	return append(out, text...)
}

// ParseGroupText decodes a GRP_TXT plaintext, splitting the "sender: text"
// body. A missing separator leaves Sender empty and the whole body as
// Text.
func ParseGroupText(plain []byte) (*GroupTextPlaintext, error) {
	if len(plain) < 5 {
		return nil, ErrShortFrame
	}
	if plain[4]>>2 != 0 {
		return nil, fmt.Errorf("%w: group text subtype %d", ErrBadPayloadType, plain[4]>>2)
	}
	m := &GroupTextPlaintext{
		Timestamp: time.Unix(int64(binary.LittleEndian.Uint32(plain[:4])), 0),
	}
	body, _ := splitCString(plain[5:])
	if sender, text, found := strings.Cut(body, ": "); found {
		m.Sender, m.Text = sender, text
	} else {
		m.Text = body
	}
	return m, nil
}

// splitCString returns the bytes before the first NUL as a string, and
// whatever follows that NUL. With no NUL, the whole slice is the string
// and the remainder is empty.
func splitCString(b []byte) (string, []byte) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:]
		}
	}
	return string(b), nil
}
