package meshcore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrBadPathEncoding reports a PATH payload whose decrypted path
// descriptor is invalid.
var ErrBadPathEncoding = errors.New("meshcore: bad path encoding in PATH payload")

// Datagram is the addressed envelope of a PATH, REQ, RESPONSE or
// TXT_MSG payload: dest hash ‖ src hash ‖ MAC ‖ ciphertext. Splitting
// is separate from opening so a receiver can match DestHash (and look
// up src candidates) before spending a decrypt attempt per shared
// secret, as the reference does.
type Datagram struct {
	DestHash []byte
	SrcHash  []byte
	Sealed   []byte // MAC ‖ ciphertext
}

// ParseDatagram splits an addressed datagram payload.
func ParseDatagram(payload []byte) (*Datagram, error) {
	if len(payload) <= 2*PathHashSize+CipherMACSize {
		return nil, ErrShortFrame
	}
	return &Datagram{
		DestHash: bytes.Clone(payload[:PathHashSize]),
		SrcHash:  bytes.Clone(payload[PathHashSize : 2*PathHashSize]),
		Sealed:   bytes.Clone(payload[2*PathHashSize:]),
	}, nil
}

// Open authenticates and decrypts the sealed data. The plaintext keeps
// its zero padding, as the reference hands it to payload parsers.
func (d *Datagram) Open(secret []byte) ([]byte, error) {
	return MACThenDecrypt(secret, d.Sealed)
}

// AnonDatagram is the envelope of an ANON_REQ payload: dest hash ‖
// sender public key ‖ MAC ‖ ciphertext. The receiver derives the
// shared secret from SenderPub.
type AnonDatagram struct {
	DestHash  []byte
	SenderPub []byte
	Sealed    []byte
}

// ParseAnonDatagram splits an ANON_REQ payload.
func ParseAnonDatagram(payload []byte) (*AnonDatagram, error) {
	if len(payload) <= PathHashSize+PubKeySize+CipherMACSize {
		return nil, ErrShortFrame
	}
	return &AnonDatagram{
		DestHash:  bytes.Clone(payload[:PathHashSize]),
		SenderPub: bytes.Clone(payload[PathHashSize : PathHashSize+PubKeySize]),
		Sealed:    bytes.Clone(payload[PathHashSize+PubKeySize:]),
	}, nil
}

// Open authenticates and decrypts the sealed data.
func (d *AnonDatagram) Open(secret []byte) ([]byte, error) {
	return MACThenDecrypt(secret, d.Sealed)
}

// GroupDatagram is the envelope of a GRP_TXT or GRP_DATA payload:
// channel hash ‖ MAC ‖ ciphertext.
type GroupDatagram struct {
	ChannelHash []byte
	Sealed      []byte
}

// ParseGroupDatagram splits a group datagram payload.
func ParseGroupDatagram(payload []byte) (*GroupDatagram, error) {
	if len(payload) <= PathHashSize+CipherMACSize {
		return nil, ErrShortFrame
	}
	return &GroupDatagram{
		ChannelHash: bytes.Clone(payload[:PathHashSize]),
		Sealed:      bytes.Clone(payload[PathHashSize:]),
	}, nil
}

// Open authenticates and decrypts the sealed data with the channel
// secret.
func (d *GroupDatagram) Open(ch *GroupChannel) ([]byte, error) {
	return MACThenDecrypt(ch.Secret, d.Sealed)
}

// PathReturn is the decrypted content of a PATH payload: the sender's
// observed path back, plus an optional piggybacked payload. Extra may
// carry trailing zero padding from the block cipher — the reference
// receiver passes it on padded, so ExtraType's owner must tolerate it.
type PathReturn struct {
	PathLen   uint8 // encoded descriptor, as in Packet.PathLen
	Path      []byte
	ExtraType uint8 // low nibble only; upper bits are reserved
	Extra     []byte
}

// DecodePathReturn interprets an opened (decrypted) PATH datagram, as
// the reference receiver does: descriptor byte, path bytes, then an
// extra-type byte and the padded remainder.
//
// It implements the firmware 1.17+ receiver, which rejects a reserved
// path descriptor (ErrBadPathEncoding); receivers before 1.17 lacked
// that guard and read straight through such a descriptor. This is the
// one path-return behavior that varies by firmware version.
func DecodePathReturn(plain []byte) (*PathReturn, error) {
	if len(plain) < 2 {
		return nil, ErrShortFrame
	}
	pathLen := plain[0]
	if !ValidPathLen(pathLen) {
		return nil, ErrBadPathEncoding
	}
	pathBytes := int(pathLen&63) * (int(pathLen>>6) + 1)
	if 1+pathBytes+1 > len(plain) {
		return nil, ErrShortFrame
	}
	return &PathReturn{
		PathLen:   pathLen,
		Path:      bytes.Clone(plain[1 : 1+pathBytes]),
		ExtraType: plain[1+pathBytes] & 0x0F,
		Extra:     bytes.Clone(plain[2+pathBytes:]),
	}, nil
}

// ParseAck extracts the 4-byte CRC of an ACK payload, little-endian —
// the value AckCRC computes on the sending side.
func ParseAck(payload []byte) (uint32, error) {
	if len(payload) < 4 {
		return 0, ErrShortFrame
	}
	return binary.LittleEndian.Uint32(payload), nil
}

// Multipart is a decoded MULTIPART wrapper: the prefix byte packs the
// remaining-parts count (high nibble) and the inner payload type (low
// nibble); Data is the inner payload.
type Multipart struct {
	Remaining uint8
	Inner     PayloadType
	Data      []byte
}

// ParseMultipart splits a MULTIPART payload.
func ParseMultipart(payload []byte) (*Multipart, error) {
	if len(payload) < 2 {
		return nil, ErrShortFrame
	}
	return &Multipart{
		Remaining: payload[0] >> 4,
		Inner:     PayloadType(payload[0] & 0x0F),
		Data:      bytes.Clone(payload[1:]),
	}, nil
}

// Trace is a decoded TRACE packet. The requested route rides in the
// payload (RouteHashes, node-hash entries of HashWidth bytes each);
// the traversed hops record their SNR in the packet path, in quarter
// dB units (SNRx4, one signed byte per hop).
type Trace struct {
	Tag       uint32
	AuthCode  uint32
	Flags     uint8
	HashWidth int // 1 << (Flags & 0x03), per firmware v1.11+
	Route     []byte
	SNRx4     []int8
}

// ParseTrace decodes a TRACE packet (payload and path together).
func ParseTrace(p *Packet) (*Trace, error) {
	if p.PayloadType() != PayloadTypeTrace {
		return nil, fmt.Errorf("ParseTrace: %w", ErrBadPayloadType)
	}
	if len(p.Payload) < 9 {
		return nil, ErrShortFrame
	}
	flags := p.Payload[8]
	snrs := make([]int8, len(p.Path))
	for i, b := range p.Path {
		snrs[i] = int8(b)
	}
	return &Trace{
		Tag:       binary.LittleEndian.Uint32(p.Payload),
		AuthCode:  binary.LittleEndian.Uint32(p.Payload[4:]),
		Flags:     flags,
		HashWidth: 1 << (flags & 0x03),
		Route:     bytes.Clone(p.Payload[9:]),
		SNRx4:     snrs,
	}, nil
}
