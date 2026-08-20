package meshcore

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Wire-format errors returned by Packet parsing and encoding.
var (
	ErrShortFrame      = errors.New("meshcore: frame too short")
	ErrInvalidPathLen  = errors.New("meshcore: invalid path_len encoding")
	ErrEmptyPayload    = errors.New("meshcore: empty payload")
	ErrPayloadTooLarge = errors.New("meshcore: payload exceeds MaxPacketPayload")
	ErrPathTooLarge    = errors.New("meshcore: path exceeds encoded length")
)

// Packet is the fundamental transmission unit.
//
// Wire layout: header (1 byte) | transport codes (2 × uint16
// little-endian, only for TRANSPORT_* routes) | path_len (1 byte) |
// path (hash count × hash size bytes) | payload (all remaining bytes).
//
// Transport codes travel little-endian: the reference firmware
// memcpy()s its uint16 fields on little-endian MCUs, which makes LE the
// de facto wire order.
//
// Reference: MeshCore src/Packet.{h,cpp}.
type Packet struct {
	// Header packs the route type, payload type and payload version.
	// Use MakeHeader and the accessors rather than raw bit twiddling.
	Header uint8

	// PathLen is the encoded path descriptor, not a byte count:
	// bits 0-5 hold the hash count, bits 6-7 hold (hash size - 1).
	// A hash-size code of 3 (4-byte hashes) is reserved and invalid.
	PathLen uint8

	// TransportCodes are carried only by TRANSPORT_* routes and are
	// zero otherwise.
	TransportCodes [2]uint16

	// Path semantics depend on the route type: it accumulates node
	// hashes on FLOOD routes, is consumed hop by hop on DIRECT routes,
	// is empty on zero-hop packets, and collects one SNR byte per hop
	// on TRACE packets (whose intended route rides in the payload).
	Path []byte

	Payload []byte
}

// Route returns the packet's routing mode.
func (p *Packet) Route() RouteType { return RouteType(p.Header & headerRouteMask) }

// PayloadType returns the packet's payload discriminator.
func (p *Packet) PayloadType() PayloadType {
	return PayloadType((p.Header >> headerTypeShift) & headerTypeMask)
}

// PayloadVer returns the packet's payload version.
func (p *Packet) PayloadVer() PayloadVersion {
	return PayloadVersion((p.Header >> headerVerShift) & headerVerMask)
}

// IsRouteFlood reports whether the packet floods (plain or transport).
func (p *Packet) IsRouteFlood() bool {
	r := p.Route()
	return r == RouteFlood || r == RouteTransportFlood
}

// IsRouteDirect reports whether the packet follows a supplied path.
func (p *Packet) IsRouteDirect() bool {
	r := p.Route()
	return r == RouteDirect || r == RouteTransportDirect
}

// HasTransportCodes reports whether the wire form carries the 4-byte
// transport code block.
func (p *Packet) HasTransportCodes() bool {
	r := p.Route()
	return r == RouteTransportFlood || r == RouteTransportDirect
}

// PathHashSize returns the per-hop hash width in bytes (1-3; 4 is
// reserved).
func (p *Packet) PathHashSize() int { return int(p.PathLen>>6) + 1 }

// PathHashCount returns the number of hashes recorded in the path.
func (p *Packet) PathHashCount() int { return int(p.PathLen & 63) }

// PathByteLen returns the number of path bytes on the wire.
func (p *Packet) PathByteLen() int { return p.PathHashCount() * p.PathHashSize() }

// SetPathHashCount updates the hash count, preserving the hash size.
func (p *Packet) SetPathHashCount(n int) {
	p.PathLen = p.PathLen&^63 | uint8(n)&63
}

// SetPathHashSizeAndCount sets both halves of the path descriptor.
func (p *Packet) SetPathHashSizeAndCount(size, count int) {
	p.PathLen = uint8(size-1)<<6 | uint8(count)&63
}

// AppendPathHash appends one node hash to the path — the flood-relay
// step (Mesh::routeRecvPacket). The hash must be exactly PathHashSize
// bytes; the grown path must still fit MaxPathSize and the 6-bit count
// field (63 — one below MaxPathSize for 1-byte hashes, where the
// reference's length check alone would let the count wrap to zero).
func (p *Packet) AppendPathHash(hash []byte) error {
	size := p.PathHashSize()
	if len(hash) != size {
		return ErrInvalidPathLen
	}
	if next := p.PathHashCount() + 1; next > 63 || next*size > MaxPathSize {
		return ErrPathTooLarge
	}
	// Grow into a fresh array: appending in place would write through
	// any copy of this Packet that shares the Path backing array (e.g.
	// a relay keeping the received packet while forwarding a copy).
	grown := make([]byte, 0, len(p.Path)+len(hash))
	grown = append(grown, p.Path...)
	grown = append(grown, hash...)
	p.Path = grown
	p.SetPathHashCount(p.PathHashCount() + 1)
	return nil
}

// ConsumeNextHop removes and returns the first hash of a direct path —
// the step a repeater takes after matching it against its own hash
// (Mesh::removeSelfFromPath).
func (p *Packet) ConsumeNextHop() ([]byte, error) {
	size := p.PathHashSize()
	if p.PathHashCount() == 0 || len(p.Path) < size {
		return nil, ErrShortFrame
	}
	hop := append([]byte(nil), p.Path[:size]...)
	// Reslice into a fresh array rather than compacting in place, which
	// would overwrite the Path backing array shared with any copy.
	p.Path = append([]byte(nil), p.Path[size:]...)
	p.SetPathHashCount(p.PathHashCount() - 1)
	return hop, nil
}

// ValidPathLen reports whether an encoded path descriptor is
// well-formed: the reserved 4-byte hash size is refused, and the
// described path must fit MaxPathSize.
func ValidPathLen(pathLen uint8) bool {
	count := int(pathLen & 63)
	size := int(pathLen>>6) + 1
	if size == 4 {
		return false // reserved
	}
	return count*size <= MaxPathSize
}

// RawLength returns the encoded length of the packet in bytes.
func (p *Packet) RawLength() int {
	n := 2 + p.PathByteLen() + len(p.Payload)
	if p.HasTransportCodes() {
		n += 4
	}
	return n
}

// AppendTo appends the wire form of the packet to dst and returns the
// extended slice. It validates the same invariants UnmarshalBinary
// enforces, so every encoded packet round-trips.
func (p *Packet) AppendTo(dst []byte) ([]byte, error) {
	if !ValidPathLen(p.PathLen) {
		return dst, ErrInvalidPathLen
	}
	if bl := p.PathByteLen(); len(p.Path) < bl {
		return dst, fmt.Errorf("%w: path_len describes %d bytes, path holds %d",
			ErrPathTooLarge, bl, len(p.Path))
	}
	if len(p.Payload) == 0 {
		// The reference parser refuses frames without payload bytes,
		// so emitting one would produce an untransportable packet.
		return dst, ErrEmptyPayload
	}
	if len(p.Payload) > MaxPacketPayload {
		return dst, ErrPayloadTooLarge
	}

	dst = append(dst, p.Header)
	if p.HasTransportCodes() {
		dst = binary.LittleEndian.AppendUint16(dst, p.TransportCodes[0])
		dst = binary.LittleEndian.AppendUint16(dst, p.TransportCodes[1])
	}
	dst = append(dst, p.PathLen)
	dst = append(dst, p.Path[:p.PathByteLen()]...)
	dst = append(dst, p.Payload...)
	return dst, nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (p *Packet) MarshalBinary() ([]byte, error) {
	return p.AppendTo(make([]byte, 0, p.RawLength()))
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler. It mirrors the
// reference parser: a frame must carry at least one payload byte, the
// path descriptor must be well-formed, and the payload must fit
// MaxPacketPayload. Path and Payload are copies of the input.
func (p *Packet) UnmarshalBinary(src []byte) error {
	i := 0
	if len(src) < 1 {
		return ErrShortFrame
	}
	p.Header = src[i]
	i++

	if p.HasTransportCodes() {
		if len(src) < i+4 {
			return ErrShortFrame
		}
		p.TransportCodes[0] = binary.LittleEndian.Uint16(src[i:])
		p.TransportCodes[1] = binary.LittleEndian.Uint16(src[i+2:])
		i += 4
	} else {
		p.TransportCodes[0], p.TransportCodes[1] = 0, 0
	}

	if len(src) < i+1 {
		return ErrShortFrame
	}
	p.PathLen = src[i]
	i++
	if !ValidPathLen(p.PathLen) {
		return ErrInvalidPathLen
	}

	bl := p.PathByteLen()
	if len(src) < i+bl {
		return ErrShortFrame
	}
	p.Path = append([]byte(nil), src[i:i+bl]...)
	i += bl

	if i >= len(src) {
		return ErrEmptyPayload
	}
	if len(src)-i > MaxPacketPayload {
		return ErrPayloadTooLarge
	}
	p.Payload = append([]byte(nil), src[i:]...)
	return nil
}

// ParsePacket decodes a wire frame into a new Packet.
func ParsePacket(src []byte) (*Packet, error) {
	p := &Packet{}
	if err := p.UnmarshalBinary(src); err != nil {
		return nil, err
	}
	return p, nil
}

// Hash returns the packet hash used for deduplication and ACK
// correlation: SHA-256 over the payload type, then — for TRACE packets
// only — the path descriptor, then the payload, truncated to
// MaxHashSize bytes.
//
// The TRACE descriptor is hashed as two little-endian bytes: the
// reference hashes its uint16 path_len field whole, so the second byte
// is always zero on the wire but still part of the preimage. TRACE
// packets fold the descriptor in because they may legitimately revisit
// a node on their return path; every other type must hash identically
// however long its accumulated path has grown.
func (p *Packet) Hash() [MaxHashSize]byte {
	h := sha256.New()
	h.Write([]byte{uint8(p.PayloadType())})
	if p.PayloadType() == PayloadTypeTrace {
		h.Write([]byte{p.PathLen, 0})
	}
	h.Write(p.Payload)
	var out [MaxHashSize]byte
	copy(out[:], h.Sum(nil))
	return out
}
