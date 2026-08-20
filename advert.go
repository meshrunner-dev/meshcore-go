package meshcore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"
)

// Advert application-data flags. The low nibble of the first byte is
// the node type; the high nibble flags optional fields.
// Reference: MeshCore src/helpers/AdvertDataHelpers.{h,cpp}.
const (
	AdvTypeNone     = 0
	AdvTypeChat     = 1
	AdvTypeRepeater = 2
	AdvTypeRoom     = 3
	AdvTypeSensor   = 4

	advLatLonMask = 0x10
	advFeat1Mask  = 0x20
	advFeat2Mask  = 0x40
	advNameMask   = 0x80
)

// AdvertData is the decoded application payload of an ADVERT: node type,
// optional location (stored as integer millionths of a degree, the wire
// unit), two optional feature words and an optional name.
type AdvertData struct {
	Type   uint8
	HasLoc bool
	LatE6  int32 // degrees × 1e6
	LonE6  int32
	Feat1  uint16 // present when non-zero
	Feat2  uint16
	Name   string
}

// Lat returns the latitude in degrees.
func (a *AdvertData) Lat() float64 { return float64(a.LatE6) / 1e6 }

// Lon returns the longitude in degrees.
func (a *AdvertData) Lon() float64 { return float64(a.LonE6) / 1e6 }

// utf8SeqLen returns the encoded length a UTF-8 sequence must have
// given its first byte, or 0 for a byte that cannot start one.
func utf8SeqLen(first byte) int {
	switch {
	case first <= 0x7F:
		return 1
	case first >= 0xC2 && first <= 0xDF:
		return 2
	case first >= 0xE0 && first <= 0xEF:
		return 3
	case first >= 0xF0 && first <= 0xF4:
		return 4
	default:
		return 0
	}
}

// utf8SeqWellFormed reports whether the seqLen-byte sequence at offset
// is complete and well formed — continuation bytes present, and the
// overlong/surrogate ranges excluded.
func utf8SeqWellFormed(s string, offset, seqLen int) bool {
	for i := 1; i < seqLen; i++ {
		if offset+i >= len(s) || s[offset+i]&0xC0 != 0x80 {
			return false
		}
	}
	if seqLen < 2 {
		return true
	}
	first, second := s[offset], s[offset+1]
	if seqLen == 3 && ((first == 0xE0 && second < 0xA0) || (first == 0xED && second > 0x9F)) {
		return false
	}
	if seqLen == 4 && ((first == 0xF0 && second < 0x90) || (first == 0xF4 && second > 0x8F)) {
		return false
	}
	return true
}

// validUTF8PrefixLength returns the longest prefix of complete,
// well-formed UTF-8 sequences that fits in maxBytes. Scanning stops at
// the first malformed byte or NUL, mirroring the reference's
// validUtf8PrefixLength (helpers/UTF8Helpers.h) exactly.
func validUTF8PrefixLength(s string, maxBytes int) int {
	offset := 0
	for offset < len(s) && s[offset] != 0 {
		seqLen := utf8SeqLen(s[offset])
		if seqLen == 0 || offset+seqLen > maxBytes || !utf8SeqWellFormed(s, offset, seqLen) {
			return offset
		}
		offset += seqLen
	}
	return offset
}

// EncodeAppData serialises the advert app data. Field order on the wire
// is fixed: flag byte, then lat/lon, feat1, feat2, name — each present
// only when its flag is set. A feature word is emitted only when
// non-zero, matching the reference builder. The name is truncated to
// the room remaining without splitting a UTF-8 sequence; if no valid
// prefix fits (e.g. the name starts with a malformed byte), the name
// and its flag are omitted entirely, as the reference does.
func (a *AdvertData) EncodeAppData() []byte {
	out := make([]byte, 1, MaxAdvertDataSize)
	out[0] = a.Type & 0x0F

	if a.HasLoc {
		out[0] |= advLatLonMask
		out = binary.LittleEndian.AppendUint32(out, uint32(a.LatE6))
		out = binary.LittleEndian.AppendUint32(out, uint32(a.LonE6))
	}
	if a.Feat1 != 0 {
		out[0] |= advFeat1Mask
		out = binary.LittleEndian.AppendUint16(out, a.Feat1)
	}
	if a.Feat2 != 0 {
		out[0] |= advFeat2Mask
		out = binary.LittleEndian.AppendUint16(out, a.Feat2)
	}
	if a.Name != "" {
		if n := validUTF8PrefixLength(a.Name, MaxAdvertDataSize-len(out)); n > 0 {
			out[0] |= advNameMask
			out = append(out, a.Name[:n]...)
		}
	}
	// The fixed fields never exceed 13 bytes and the name is truncated
	// to the room that remains, so the result always fits.
	return out
}

// ParseAdvertData decodes advert app data. The name, when flagged, is
// the entire remainder of the buffer.
func ParseAdvertData(b []byte) (*AdvertData, error) {
	if len(b) < 1 {
		return nil, ErrShortFrame
	}
	a := &AdvertData{}
	flags := b[0]
	a.Type = flags & 0x0F
	i := 1

	if flags&advLatLonMask != 0 {
		if len(b) < i+8 {
			return nil, ErrShortFrame
		}
		a.HasLoc = true
		a.LatE6 = int32(binary.LittleEndian.Uint32(b[i:]))
		a.LonE6 = int32(binary.LittleEndian.Uint32(b[i+4:]))
		i += 8
	}
	if flags&advFeat1Mask != 0 {
		if len(b) < i+2 {
			return nil, ErrShortFrame
		}
		a.Feat1 = binary.LittleEndian.Uint16(b[i:])
		i += 2
	}
	if flags&advFeat2Mask != 0 {
		if len(b) < i+2 {
			return nil, ErrShortFrame
		}
		a.Feat2 = binary.LittleEndian.Uint16(b[i:])
		i += 2
	}
	if flags&advNameMask != 0 && i < len(b) {
		// The reference stores the name then NUL-terminates it, and
		// every consumer reads it as a C string (AdvertDataHelpers,
		// BaseChatMesh): the effective name ends at the first embedded
		// NUL. Match that so a crafted trailing blob cannot smuggle
		// bytes past what firmware nodes display.
		name := b[i:]
		if z := bytes.IndexByte(name, 0); z >= 0 {
			name = name[:z]
		}
		a.Name = string(name)
	}
	return a, nil
}

// Advert payload layout: pub_key (32) ‖ timestamp (uint32 LE, 4) ‖
// signature (64) ‖ app_data (0..32). The signature covers
// pub_key ‖ timestamp ‖ app_data — the signed message deliberately
// omits the signature bytes themselves.
const advertFixedLen = PubKeySize + 4 + SignatureSize

// BuildAdvert creates a signed ADVERT packet from this identity. The
// packet's route defaults to FLOOD; the send layer picks the final
// route (clearing PH_ROUTE_MASK before setting DIRECT or zero-hop).
// emittedAt is the advert timestamp (UNIX seconds).
func BuildAdvert(id *LocalIdentity, emittedAt time.Time, app *AdvertData) (*Packet, error) {
	appData := app.EncodeAppData()
	ts := uint32(emittedAt.Unix())

	// The signed message is pub_key ‖ timestamp ‖ app_data.
	msg := make([]byte, 0, PubKeySize+4+len(appData))
	msg = append(msg, id.PubKey[:]...)
	msg = binary.LittleEndian.AppendUint32(msg, ts)
	msg = append(msg, appData...)
	sig := id.Sign(msg)

	payload := make([]byte, 0, advertFixedLen+len(appData))
	payload = append(payload, id.PubKey[:]...)
	payload = binary.LittleEndian.AppendUint32(payload, ts)
	payload = append(payload, sig...)
	payload = append(payload, appData...)

	return &Packet{
		Header:  MakeHeader(RouteFlood, PayloadTypeAdvert, PayloadVer1),
		Payload: payload,
	}, nil
}

// Advert is a verified, decoded ADVERT.
type Advert struct {
	Identity  Identity
	Timestamp time.Time
	Data      *AdvertData
}

// ParseAdvert decodes an ADVERT payload and verifies its signature.
// It returns ErrBadSignature if verification fails; the packet is
// otherwise structurally valid.
func ParseAdvert(payload []byte) (*Advert, error) {
	if len(payload) < advertFixedLen {
		return nil, ErrShortFrame
	}
	var id Identity
	copy(id.PubKey[:], payload[:PubKeySize])
	ts := binary.LittleEndian.Uint32(payload[PubKeySize:])
	sig := payload[PubKeySize+4 : advertFixedLen]

	// The reference caps the app data at MaxAdvertDataSize before both
	// the signature check and downstream parsing (Mesh::onRecvPacket):
	// anything past 32 bytes is padding a signer never covered, so a
	// relay that appends bytes to a valid advert must not change the
	// verdict. Matching this cap is required for interop — otherwise a
	// padded advert the whole mesh refloods gets rejected here.
	appData := payload[advertFixedLen:]
	if len(appData) > MaxAdvertDataSize {
		appData = appData[:MaxAdvertDataSize]
	}

	msg := make([]byte, 0, PubKeySize+4+len(appData))
	msg = append(msg, payload[:PubKeySize+4]...)
	msg = append(msg, appData...)
	if !id.Verify(sig, msg) {
		return nil, ErrBadSignature
	}

	data, err := ParseAdvertData(appData)
	if err != nil {
		return nil, err
	}
	return &Advert{
		Identity:  id,
		Timestamp: time.Unix(int64(ts), 0).UTC(),
		Data:      data,
	}, nil
}

// ErrBadSignature reports an advert whose signature does not verify.
var ErrBadSignature = errors.New("meshcore: advert signature invalid")
