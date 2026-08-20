package meshcore

// Wire-format limits. Reference: MeshCore src/MeshCore.h.
const (
	// MaxHashSize is the truncated length, in bytes, of a packet hash.
	MaxHashSize = 8
	// MaxPacketPayload is the largest payload a packet may carry.
	MaxPacketPayload = 184
	// MaxPathSize is the largest path field, in bytes (hashes × hash size).
	MaxPathSize = 64
	// MaxTransUnit is the largest encoded packet the radio layer accepts.
	MaxTransUnit = 255
)

// RouteType is the 2-bit routing mode carried in a packet header.
// Reference: MeshCore src/Packet.h.
type RouteType uint8

const (
	// RouteTransportFlood floods and carries transport codes.
	RouteTransportFlood RouteType = 0x00
	// RouteFlood floods; the path accumulates one node hash per hop.
	RouteFlood RouteType = 0x01
	// RouteDirect follows a supplied path, consumed one hop at a time.
	RouteDirect RouteType = 0x02
	// RouteTransportDirect is direct routing with transport codes.
	RouteTransportDirect RouteType = 0x03
)

func (r RouteType) String() string {
	switch r {
	case RouteTransportFlood:
		return "TRANSPORT_FLOOD"
	case RouteFlood:
		return "FLOOD"
	case RouteDirect:
		return "DIRECT"
	case RouteTransportDirect:
		return "TRANSPORT_DIRECT"
	}
	return "UNKNOWN"
}

// PayloadType is the 4-bit payload discriminator carried in a packet header.
// Reference: MeshCore src/Packet.h.
type PayloadType uint8

// Payload type discriminators, as defined by the reference firmware.
const (
	PayloadTypeReq       PayloadType = 0x00 // request (dest/src hashes, MAC)
	PayloadTypeResponse  PayloadType = 0x01 // response to REQ or ANON_REQ
	PayloadTypeTxtMsg    PayloadType = 0x02 // plain text message
	PayloadTypeAck       PayloadType = 0x03 // acknowledgement (CRC of the acked packet)
	PayloadTypeAdvert    PayloadType = 0x04 // node advertising its identity
	PayloadTypeGrpTxt    PayloadType = 0x05 // unverified group text message
	PayloadTypeGrpData   PayloadType = 0x06 // unverified group datagram
	PayloadTypeAnonReq   PayloadType = 0x07 // request with an ephemeral public key
	PayloadTypePath      PayloadType = 0x08 // returned path
	PayloadTypeTrace     PayloadType = 0x09 // path trace collecting per-hop SNR
	PayloadTypeMultipart PayloadType = 0x0A // one packet of a set
	PayloadTypeControl   PayloadType = 0x0B // control/discovery
	PayloadTypeRawCustom PayloadType = 0x0F // application-defined raw bytes
)

func (t PayloadType) String() string {
	switch t {
	case PayloadTypeReq:
		return "REQ"
	case PayloadTypeResponse:
		return "RESPONSE"
	case PayloadTypeTxtMsg:
		return "TXT_MSG"
	case PayloadTypeAck:
		return "ACK"
	case PayloadTypeAdvert:
		return "ADVERT"
	case PayloadTypeGrpTxt:
		return "GRP_TXT"
	case PayloadTypeGrpData:
		return "GRP_DATA"
	case PayloadTypeAnonReq:
		return "ANON_REQ"
	case PayloadTypePath:
		return "PATH"
	case PayloadTypeTrace:
		return "TRACE"
	case PayloadTypeMultipart:
		return "MULTIPART"
	case PayloadTypeControl:
		return "CONTROL"
	case PayloadTypeRawCustom:
		return "RAW_CUSTOM"
	}
	return "UNKNOWN"
}

// PayloadVersion is the 2-bit payload version carried in a packet header.
type PayloadVersion uint8

// Payload versions; only version 1 is defined by the reference.
const (
	// PayloadVer1 uses 1-byte src/dest hashes and 2-byte MACs.
	PayloadVer1 PayloadVersion = 0x00
	PayloadVer2 PayloadVersion = 0x01 // reserved
	PayloadVer3 PayloadVersion = 0x02 // reserved
	PayloadVer4 PayloadVersion = 0x03 // reserved
)

// Header bit layout: route (bits 0-1), payload type (bits 2-5),
// payload version (bits 6-7).
const (
	headerRouteMask = 0x03
	headerTypeShift = 2
	headerTypeMask  = 0x0F
	headerVerShift  = 6
	headerVerMask   = 0x03
)

// MakeHeader packs a route, payload type and payload version into the
// single-byte packet header.
func MakeHeader(route RouteType, ptype PayloadType, ver PayloadVersion) uint8 {
	return uint8(route)&headerRouteMask |
		(uint8(ptype)&headerTypeMask)<<headerTypeShift |
		(uint8(ver)&headerVerMask)<<headerVerShift
}

// Identity and cipher sizes. Reference: MeshCore src/MeshCore.h.
const (
	// PubKeySize is the Ed25519 public key length.
	PubKeySize = 32
	// PrvKeySize is the expanded private key length: the clamped
	// scalar followed by the signing prefix (orlp/ed25519 layout, as
	// stored and exchanged by the reference firmware).
	PrvKeySize = 64
	// SeedSize is the private key seed length.
	SeedSize = 32
	// SignatureSize is the Ed25519 signature length.
	SignatureSize = 64
	// MaxAdvertDataSize bounds the application data in an ADVERT.
	MaxAdvertDataSize = 32
	// CipherKeySize is the AES key length: the first half of a
	// 32-byte shared secret.
	CipherKeySize = 16
	// CipherBlockSize is the AES block length.
	CipherBlockSize = 16
	// CipherMACSize is the truncated HMAC-SHA256 length prepended to
	// ciphertext (protocol V1).
	CipherMACSize = 2
	// PathHashSize is the node-hash prefix length used by payload
	// envelopes (protocol V1). The packet path may use wider hashes;
	// this constant governs the dest/src bytes inside payloads.
	PathHashSize = 1
)
