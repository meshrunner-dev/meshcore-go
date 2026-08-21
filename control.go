package meshcore

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Node discovery rides on CONTROL packets. A node broadcasts a
// DISCOVER_REQ, direct-routed with an empty path so no repeater relays
// it, and every node matching the request answers — also zero hop —
// with its public key and the signal-to-noise ratio at which it heard
// the request. Sweeping transmit power upward and collecting the
// answers maps who can hear you, and how well.
//
// The reference gates this on CONTROL ‖ DIRECT ‖ the top bit of the
// first payload byte (Mesh.cpp): both command bytes below carry it.
const (
	ctlNodeDiscoverReq  = 0x80 // request; low bit selects a short-key reply
	ctlNodeDiscoverResp = 0x90 // response; low nibble carries the node type
	ctlTypeMask         = 0xF0
)

// Discovery errors.
var (
	ErrNotControl      = errors.New("meshcore: not a CONTROL packet")
	ErrNotDiscoverReq  = errors.New("meshcore: not a discovery request")
	ErrNotDiscoverResp = errors.New("meshcore: not a discovery response")
)

// AdvTypeFilter selects which node types answer a discovery request: bit
// N set means advert type N should respond (see AdvType* constants).
type AdvTypeFilter uint8

// RepeaterFilter matches only repeaters — the common discovery target.
func RepeaterFilter() AdvTypeFilter { return 1 << AdvTypeRepeater }

// Includes reports whether nodes of advType should answer.
func (f AdvTypeFilter) Includes(advType uint8) bool { return f&(1<<advType) != 0 }

// DiscoverReq is a node discovery request.
type DiscoverReq struct {
	// Filter selects the responding node types.
	Filter AdvTypeFilter

	// Tag is an arbitrary value echoed in every response, so a caller
	// can match answers to the request that prompted them.
	Tag uint32

	// Since, when non-zero, asks only nodes whose discovery state
	// changed at or after this UNIX time to respond.
	Since uint32

	// PrefixOnly requests an 8-byte key prefix instead of the full
	// public key in each response — smaller replies, coarser identity.
	PrefixOnly bool
}

// BuildDiscoverReq builds a DISCOVER_REQ. It is direct-routed with an
// empty path — zero hop — so repeaters answer it but never relay it.
func BuildDiscoverReq(req DiscoverReq) (*Packet, error) {
	cmd := byte(ctlNodeDiscoverReq)
	if req.PrefixOnly {
		cmd |= 0x01
	}
	payload := make([]byte, 0, 6+4)
	payload = append(payload, cmd, byte(req.Filter))
	payload = binary.LittleEndian.AppendUint32(payload, req.Tag)
	if req.Since != 0 {
		payload = binary.LittleEndian.AppendUint32(payload, req.Since)
	}
	p := &Packet{
		Header:  MakeHeader(RouteDirect, PayloadTypeControl, PayloadVer1),
		Payload: payload,
	}
	return p, nil
}

// ParseDiscoverReq decodes a DISCOVER_REQ, for a node deciding whether
// and how to answer.
func ParseDiscoverReq(p *Packet) (*DiscoverReq, error) {
	if p.PayloadType() != PayloadTypeControl {
		return nil, ErrNotControl
	}
	if len(p.Payload) < 6 || p.Payload[0]&ctlTypeMask != ctlNodeDiscoverReq {
		return nil, ErrNotDiscoverReq
	}
	req := &DiscoverReq{
		PrefixOnly: p.Payload[0]&0x01 != 0,
		Filter:     AdvTypeFilter(p.Payload[1]),
		Tag:        binary.LittleEndian.Uint32(p.Payload[2:6]),
	}
	if len(p.Payload) >= 10 {
		req.Since = binary.LittleEndian.Uint32(p.Payload[6:10])
	}
	return req, nil
}

// DiscoverResp is a node's answer to a discovery request.
type DiscoverResp struct {
	// NodeType is the responder's advert type (AdvTypeRepeater, …).
	NodeType uint8

	// SNR is the signal-to-noise ratio, in dB, at which the responder
	// heard the request — a direct measure of the inbound link.
	SNR float64

	// Tag echoes the request's tag.
	Tag uint32

	// PubKey identifies the responder: the full 32-byte key, or an
	// 8-byte prefix when the request asked for one.
	PubKey []byte
}

// BuildDiscoverResp builds a node's DISCOVER_RESP. It is zero hop, like
// the request. prefixOnly must match what the request asked for.
func BuildDiscoverResp(resp DiscoverResp, prefixOnly bool) (*Packet, error) {
	key := resp.PubKey
	if prefixOnly {
		if len(key) < 8 {
			return nil, fmt.Errorf("%w: key prefix needs 8 bytes", ErrBadKeyLength)
		}
		key = key[:8]
	} else if len(key) != PubKeySize {
		return nil, ErrBadKeyLength
	}
	payload := make([]byte, 0, 6+len(key))
	payload = append(payload, ctlNodeDiscoverResp|resp.NodeType&0x0F, encodeSNR(resp.SNR))
	payload = binary.LittleEndian.AppendUint32(payload, resp.Tag)
	payload = append(payload, key...)
	p := &Packet{
		Header:  MakeHeader(RouteDirect, PayloadTypeControl, PayloadVer1),
		Payload: payload,
	}
	return p, nil
}

// ParseDiscoverResp decodes a DISCOVER_RESP.
func ParseDiscoverResp(p *Packet) (*DiscoverResp, error) {
	if p.PayloadType() != PayloadTypeControl {
		return nil, ErrNotControl
	}
	if len(p.Payload) < 6 || p.Payload[0]&ctlTypeMask != ctlNodeDiscoverResp {
		return nil, ErrNotDiscoverResp
	}
	return &DiscoverResp{
		NodeType: p.Payload[0] & 0x0F,
		SNR:      decodeSNR(p.Payload[1]),
		Tag:      binary.LittleEndian.Uint32(p.Payload[2:6]),
		PubKey:   append([]byte(nil), p.Payload[6:]...),
	}, nil
}

// The reference stores SNR as a signed byte of quarter-dB steps.
func encodeSNR(dB float64) byte {
	q := dB * 4
	switch {
	case q > 127:
		q = 127
	case q < -128:
		q = -128
	}
	return byte(int8(q))
}

func decodeSNR(b byte) float64 { return float64(int8(b)) / 4 }
