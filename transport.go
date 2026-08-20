package meshcore

// Transport regions scope flood routing. A sender attaches a 2-byte
// transport code (transport_codes[0]) derived from a region key; a
// repeater decides whether to forward by recomputing that code and
// comparing. The repeater itself stays crypto-free: it supplies a
// region name or stored key, gets a TransportKey, and calls Matches.
//
// Reference: MeshCore src/helpers/TransportKeyStore.{h,cpp} and
// src/helpers/RegionMap.cpp.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

// TransportKey is a 16-byte region key.
type TransportKey [16]byte

// TransportKeyForName derives the auto (hashtag) region key from a
// region name: SHA-256("#"+name)[:16], as the reference does for '#'
// and bare (implicit hashtag) region names (TransportKeyStore
// getAutoKeyFor via RegionMap getTransportKeysFor). A leading '#' is
// accepted and not doubled. Private ('$') regions use externally
// stored keys instead — wrap those with NewTransportKey.
func TransportKeyForName(name string) TransportKey {
	sum := sha256.Sum256([]byte("#" + strings.TrimPrefix(name, "#")))
	var k TransportKey
	copy(k[:], sum[:])
	return k
}

// NewTransportKey wraps a raw 16-byte region key (the keys behind
// private '$' regions, held outside this library).
func NewTransportKey(raw []byte) (TransportKey, error) {
	var k TransportKey
	if len(raw) != len(k) {
		return k, ErrBadKeyLength
	}
	copy(k[:], raw)
	return k, nil
}

// Code returns the transport code a packet carries when its sender
// scopes it to this region: HMAC-SHA256(key, payload_type ‖ payload)
// truncated to 2 bytes and read little-endian, with 0x0000 and 0xFFFF
// reserved (bumped to 0x0001 and 0xFFFE — those two values mark the
// "unscoped" and broadcast cases on the wire).
// Reference: TransportKey::calcTransportCode.
func (k TransportKey) Code(p *Packet) uint16 {
	mac := hmac.New(sha256.New, k[:])
	mac.Write([]byte{byte(p.PayloadType())})
	mac.Write(p.Payload)
	code := binary.LittleEndian.Uint16(mac.Sum(nil)[:2])
	switch code {
	case 0x0000:
		return 0x0001
	case 0xFFFF:
		return 0xFFFE
	default:
		return code
	}
}

// Matches reports whether the packet is scoped to this region: it
// carries transport codes and its transport_codes[0] equals this key's
// Code. This is the repeater's forwarding-decision primitive. It is
// false for plain FLOOD/DIRECT packets, which carry no transport codes
// and are simply unscoped.
func (k TransportKey) Matches(p *Packet) bool {
	return p.HasTransportCodes() && p.TransportCodes[0] == k.Code(p)
}

// IsZero reports whether the key is all zero — the "null"/unscoped
// sentinel the reference uses (TransportKey::isNull).
func (k TransportKey) IsZero() bool {
	return k == TransportKey{}
}

// MatchTransportRegion returns the index of the first key whose Code
// matches the packet, or -1. A repeater keeps its region table's keys
// in one slice and maps the returned index back to its own region
// metadata — deciding forwarding without touching any crypto.
func MatchTransportRegion(p *Packet, keys []TransportKey) int {
	if !p.HasTransportCodes() {
		return -1
	}
	for i := range keys {
		if p.TransportCodes[0] == keys[i].Code(p) {
			return i
		}
	}
	return -1
}
