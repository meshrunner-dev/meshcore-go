package meshcore

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// ErrPayloadFull reports encrypted content that would overflow a packet.
var (
	ErrPayloadFull    = errors.New("meshcore: encoded payload exceeds MaxPacketPayload")
	ErrBadPayloadType = errors.New("meshcore: payload type not valid for this builder")
	// ErrBadHashLength reports a dest/src/channel hash that is not
	// PathHashSize bytes; the reference always writes exactly that.
	ErrBadHashLength = errors.New("meshcore: hash is not PathHashSize bytes")
)

// GroupChannel is a shared-key channel. The hash is the leading byte(s)
// of SHA-256(secret) and prefixes every group packet so receivers can
// pick candidate channels; the secret keys the payload cipher and MAC.
type GroupChannel struct {
	Hash []byte // PathHashSize bytes

	// Secret is always 32 bytes on the crypto path: the reference
	// stores channel secrets in a zero-filled 32-byte array, so a
	// 16-byte PSK effectively keys the MAC as PSK ‖ 16 zero bytes
	// (and the cipher as its first 16 bytes). The channel hash, by
	// contrast, is computed over the PSK's real length.
	Secret []byte
}

// NewGroupChannel derives a channel from its PSK — 16 bytes (the
// common companion-app channels) or 32. The hash is SHA-256 over the
// PSK's real length truncated to PathHashSize; the crypto secret is
// the PSK zero-padded to 32 bytes, both exactly as the reference
// (BaseChatMesh addChannel / Mesh createGroupDatagram).
func NewGroupChannel(psk []byte) (*GroupChannel, error) {
	if len(psk) != CipherKeySize && len(psk) != 2*CipherKeySize {
		return nil, ErrBadKeyLength
	}
	secret := make([]byte, 2*CipherKeySize)
	copy(secret, psk)
	return &GroupChannel{
		Hash:   sha256Trunc(PathHashSize, psk),
		Secret: secret,
	}, nil
}

// NewGroupChannelFromBase64 derives a channel from a base64-encoded PSK
// (16 or 32 raw bytes) — the form in which secret channels are shared
// between companion apps.
func NewGroupChannelFromBase64(pskBase64 string) (*GroupChannel, error) {
	psk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pskBase64))
	if err != nil {
		return nil, fmt.Errorf("meshcore: bad channel PSK base64: %w", err)
	}
	return NewGroupChannel(psk)
}

// PublicChannelPSKBase64 is the well-known pre-shared key of the
// "Public" channel that ships pre-configured on every MeshCore node.
const PublicChannelPSKBase64 = "izOH6cXN6mrJ5e26oRXNcg=="

// NewPublicChannel returns the well-known "Public" channel.
func NewPublicChannel() *GroupChannel {
	ch, err := NewGroupChannelFromBase64(PublicChannelPSKBase64)
	if err != nil {
		panic("meshcore: built-in Public PSK is invalid: " + err.Error()) // unreachable
	}
	return ch
}

// NewHashtagChannel derives a public hashtag channel from its tag, as
// the MeshCore companion apps do: the PSK is SHA-256("#"+tag)[:16].
// This is a client convention, not part of the on-wire protocol
// (MeshCore's own C++ keys every channel from an explicit PSK) — it is
// reproduced here because it is what "joining #test by name" means in
// the apps, and it is verified against live traffic in the corpus test.
// A leading '#' in tag is accepted and not doubled; the tag is used
// verbatim otherwise (the apps do not fold case).
func NewHashtagChannel(tag string) *GroupChannel {
	tag = strings.TrimPrefix(tag, "#")
	sum := sha256.Sum256([]byte("#" + tag))
	ch, err := NewGroupChannel(sum[:CipherKeySize])
	if err != nil {
		panic("meshcore: 16-byte hashtag PSK rejected: " + err.Error()) // unreachable
	}
	return ch
}

// BuildDatagram creates an addressed, encrypted packet (TXT_MSG, REQ or
// RESPONSE). Payload layout: dest hash ‖ src hash ‖ MAC ‖ ciphertext,
// where the hashes are PathHashSize prefixes and the ciphertext is
// EncryptThenMAC(secret, data). The route defaults to FLOOD; the send
// layer picks the final route before transmitting.
func BuildDatagram(ptype PayloadType, destHash, srcHash, secret, data []byte) (*Packet, error) {
	switch ptype {
	case PayloadTypeTxtMsg, PayloadTypeReq, PayloadTypeResponse:
	default:
		return nil, fmt.Errorf("BuildDatagram: %w", ErrBadPayloadType)
	}
	if len(destHash) != PathHashSize || len(srcHash) != PathHashSize {
		return nil, ErrBadHashLength
	}
	sealed, err := EncryptThenMAC(secret, data)
	if err != nil {
		return nil, err
	}
	return newPayloadPacket(ptype, append(envelope(destHash, srcHash), sealed...))
}

// BuildAnonDatagram creates an ANON_REQ: dest hash ‖ sender pub_key ‖
// MAC ‖ ciphertext. The sender's full public key travels in the clear
// so the recipient can derive the shared secret without a prior contact.
func BuildAnonDatagram(destHash, senderPubKey, secret, data []byte) (*Packet, error) {
	if len(destHash) != PathHashSize {
		return nil, ErrBadHashLength
	}
	if len(senderPubKey) != PubKeySize {
		return nil, ErrBadKeyLength
	}
	sealed, err := EncryptThenMAC(secret, data)
	if err != nil {
		return nil, err
	}
	env := make([]byte, 0, PathHashSize+PubKeySize+len(sealed))
	env = append(env, destHash...)
	env = append(env, senderPubKey...)
	env = append(env, sealed...)
	return newPayloadPacket(PayloadTypeAnonReq, env)
}

// BuildGroupDatagram creates a GRP_TXT or GRP_DATA packet: channel hash
// ‖ MAC ‖ ciphertext, keyed by the channel secret.
func BuildGroupDatagram(ptype PayloadType, ch *GroupChannel, data []byte) (*Packet, error) {
	switch ptype {
	case PayloadTypeGrpTxt, PayloadTypeGrpData:
	default:
		return nil, fmt.Errorf("BuildGroupDatagram: %w", ErrBadPayloadType)
	}
	if len(ch.Hash) != PathHashSize {
		return nil, ErrBadHashLength
	}
	sealed, err := EncryptThenMAC(ch.Secret, data)
	if err != nil {
		return nil, err
	}
	env := make([]byte, 0, PathHashSize+len(sealed))
	env = append(env, ch.Hash...)
	env = append(env, sealed...)
	return newPayloadPacket(ptype, env)
}

// maxCombinedPath bounds the plaintext of a PATH payload
// (MAX_COMBINED_PATH in the reference).
const maxCombinedPath = MaxPacketPayload - CipherMACSize - CipherBlockSize

// BuildPathReturn creates a PATH packet returning an observed path to
// its sender: dest hash ‖ src hash ‖ EncryptThenMAC(path_len ‖ path ‖
// extra). When extra is non-empty it is prefixed by extraType; when
// empty, the reference appends a dummy type byte (0xFF) and 4 random
// bytes so the packet hash stays unique — this does the same, from
// crypto/rand. The route defaults to FLOOD; the send layer picks the
// final route before transmitting.
func BuildPathReturn(
	destHash, srcHash, secret []byte, pathLen uint8, path []byte, extraType uint8, extra []byte,
) (*Packet, error) {
	if len(destHash) != PathHashSize || len(srcHash) != PathHashSize {
		return nil, ErrBadHashLength
	}
	if !ValidPathLen(pathLen) {
		return nil, ErrInvalidPathLen
	}
	pathBytes := int(pathLen&63) * (int(pathLen>>6) + 1)
	if pathBytes != len(path) {
		return nil, ErrInvalidPathLen
	}
	if pathBytes+len(extra)+5 > maxCombinedPath {
		return nil, ErrPayloadFull
	}

	data := make([]byte, 0, 1+pathBytes+1+len(extra))
	data = append(data, pathLen)
	data = append(data, path...)
	if len(extra) > 0 {
		data = append(data, extraType)
		data = append(data, extra...)
	} else {
		var filler [4]byte
		if _, err := rand.Read(filler[:]); err != nil {
			return nil, err
		}
		data = append(data, 0xFF)
		data = append(data, filler[:]...)
	}

	sealed, err := EncryptThenMAC(secret, data)
	if err != nil {
		return nil, err
	}
	return newPayloadPacket(PayloadTypePath, append(envelope(destHash, srcHash), sealed...))
}

// BuildAck creates an ACK carrying the given CRC bytes (usually 4, or 6
// for the extended form).
func BuildAck(ackCRC []byte) (*Packet, error) {
	return newPayloadPacket(PayloadTypeAck, append([]byte(nil), ackCRC...))
}

// BuildMultiAck wraps an ACK as one of a redundant set: a prefix byte
// (remaining count in the high nibble, ACK type in the low nibble)
// followed by the CRC bytes.
func BuildMultiAck(ackCRC []byte, remaining uint8) (*Packet, error) {
	env := make([]byte, 0, 1+len(ackCRC))
	env = append(env, remaining<<4|uint8(PayloadTypeAck))
	env = append(env, ackCRC...)
	return newPayloadPacket(PayloadTypeMultipart, env)
}

// BuildRawCustom creates a RAW_CUSTOM packet from opaque bytes.
func BuildRawCustom(data []byte) (*Packet, error) {
	return newPayloadPacket(PayloadTypeRawCustom, append([]byte(nil), data...))
}

// BuildControl creates a CONTROL/discovery packet from opaque bytes.
func BuildControl(data []byte) (*Packet, error) {
	return newPayloadPacket(PayloadTypeControl, append([]byte(nil), data...))
}

// BuildTrace creates a TRACE packet: tag (uint32 LE) ‖ auth code
// (uint32 LE) ‖ flags. The route to trace is appended to the payload
// by the send layer, and each relay appends its SNR byte to the path.
func BuildTrace(tag, authCode uint32, flags uint8) (*Packet, error) {
	env := make([]byte, 0, 9)
	env = binary.LittleEndian.AppendUint32(env, tag)
	env = binary.LittleEndian.AppendUint32(env, authCode)
	env = append(env, flags)
	return newPayloadPacket(PayloadTypeTrace, env)
}

// AckCRC computes the 4-byte ACK a recipient must return for a received
// text message: SHA-256(message ‖ senderPubKey) truncated to 4 bytes,
// where message is the decrypted datagram content (timestamp, attempt,
// text). The sender precomputes the same value keyed on its own public
// key to correlate the reply.
//
// Reference: MeshCore BaseChatMesh composeMsgPacket / onMessageRecv.
func AckCRC(message, senderPubKey []byte) uint32 {
	return binary.LittleEndian.Uint32(sha256Trunc(4, message, senderPubKey))
}

// envelope returns dest ‖ src for an addressed payload.
func envelope(destHash, srcHash []byte) []byte {
	env := make([]byte, 0, len(destHash)+len(srcHash))
	env = append(env, destHash...)
	env = append(env, srcHash...)
	return env
}

// newPayloadPacket assembles a route-unset packet, refusing anything
// that would not fit a single frame.
func newPayloadPacket(ptype PayloadType, payload []byte) (*Packet, error) {
	if len(payload) == 0 {
		return nil, ErrEmptyPayload
	}
	if len(payload) > MaxPacketPayload {
		return nil, ErrPayloadFull
	}
	return &Packet{
		Header:  MakeHeader(RouteFlood, ptype, PayloadVer1),
		Payload: payload,
	}, nil
}
