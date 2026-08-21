package meshcore

import (
	"encoding/binary"
	"errors"
)

// A node is administered over encrypted datagrams: an ANON_REQ carries
// the first, contactless login (the sender's public key travels in the
// clear so the recipient can derive the shared secret); a REQ carries
// each subsequent command from the now-known contact; a RESPONSE
// carries every reply. All three are sealed with the ECDH shared
// secret between the two identities.
//
// Every admin plaintext — request or response — begins with a 4-byte
// little-endian timestamp. On a request it is anti-replay state: the
// recipient rejects a timestamp it has already seen from that contact.
// On a response it is the server's clock, or the request's timestamp
// echoed back as a matching tag. Deriving meaning from it is caller
// policy; the framing is fixed.

// Admin request types (the first body byte after the timestamp). A
// login request instead carries a password string (or nothing).
const (
	ReqTypeGetStatus = 0x01
	ReqTypeKeepAlive = 0x02
)

// RespServerLoginOK is the first body byte of a successful login reply.
const RespServerLoginOK = 0x00

// ErrShortAdminFrame reports a plaintext too short to hold the
// mandatory timestamp prefix.
var ErrShortAdminFrame = errors.New("meshcore: admin frame shorter than its timestamp prefix")

// FrameAdmin prefixes body with the 4-byte timestamp every admin
// request and response carries.
func FrameAdmin(timestamp uint32, body []byte) []byte {
	out := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(out, timestamp)
	return append(out, body...)
}

// UnframeAdmin splits a decrypted admin plaintext into its timestamp and
// the body after it. The body is returned as-is, which for the
// reference cipher means it may be zero-padded up to a 16-byte block
// boundary: the plaintext length is not carried on the wire, so the
// caller interprets the body per command — a password is read up to its
// first NUL, a typed command by its known length.
func UnframeAdmin(plain []byte) (uint32, []byte, error) {
	if len(plain) < 4 {
		return 0, nil, ErrShortAdminFrame
	}
	return binary.LittleEndian.Uint32(plain[:4]), plain[4:], nil
}

// BuildLoginReq builds an ANON_REQ login to a repeater. The shared
// secret is derived from this identity and the repeater's public key
// and returned, because the caller needs it to open the response. The
// plaintext is the timestamp followed by the password (which may be
// empty). The packet floods by default; set the route to direct for a
// zero-hop login to a neighbour.
func BuildLoginReq(id *LocalIdentity, repeaterPub []byte, timestamp uint32, password string) (*Packet, []byte, error) {
	if len(repeaterPub) != PubKeySize {
		return nil, nil, ErrBadKeyLength
	}
	secret, err := id.SharedSecret(repeaterPub)
	if err != nil {
		return nil, nil, err
	}
	pkt, err := BuildAnonDatagram(repeaterPub[:PathHashSize], id.PubKey[:], secret,
		FrameAdmin(timestamp, []byte(password)))
	if err != nil {
		return nil, nil, err
	}
	return pkt, secret, nil
}

// BuildRequest builds a REQ command datagram to a known contact, sealed
// with the shared secret established at login. body is the command; its
// first byte is a ReqType or an application-defined command.
func BuildRequest(id *LocalIdentity, destPub, secret []byte, timestamp uint32, body []byte) (*Packet, error) {
	if len(destPub) < PathHashSize {
		return nil, ErrBadKeyLength
	}
	return BuildDatagram(PayloadTypeReq, destPub[:PathHashSize], id.PubKey[:PathHashSize], secret,
		FrameAdmin(timestamp, body))
}

// BuildResponse builds a RESPONSE datagram back to a contact, sealed
// with the same shared secret. timestamp is the responder's clock, or
// the request's timestamp echoed as a tag.
func BuildResponse(destHash, srcHash, secret []byte, timestamp uint32, body []byte) (*Packet, error) {
	return BuildDatagram(PayloadTypeResponse, destHash, srcHash, secret, FrameAdmin(timestamp, body))
}
