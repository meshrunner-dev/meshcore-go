package meshcore

// Pretty-printing for the protocol objects, in three levels of detail:
//
//   - String — one line, for trace logs; every type is a fmt.Stringer,
//     so %v does the right thing in log statements;
//   - Summary (Packet) — minimal: payload type, wire size and the head
//     of the raw frame;
//   - Dump — a framed, multi-line view with a hex dump, for debugging.
//
// Secret-bearing types (LocalIdentity, GroupChannel) implement String
// and GoString as redacted forms: formatting them with %v, %+v or %#v
// never reveals key material.

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ---- shared renderers ------------------------------------------------

type field struct{ k, v string }

// oneline renders the title then each key=value pair, for trace logs.
func oneline(title string, fs []field) string {
	var b strings.Builder
	b.WriteString(title)
	for _, f := range fs {
		b.WriteByte(' ')
		b.WriteString(f.k)
		b.WriteByte('=')
		b.WriteString(f.v)
	}
	return b.String()
}

// frame renders a boxed, multi-line view; raw, when non-empty, is
// appended as a hex dump. Values may span lines with \n.
func frame(title string, fs []field, raw []byte) string {
	labelWidth := 0
	for _, f := range fs {
		if n := utf8.RuneCountInString(f.k); n > labelWidth {
			labelWidth = n
		}
	}
	rows := make([]string, 0, len(fs)+2+len(raw)/16)
	for _, f := range fs {
		for i, part := range strings.Split(f.v, "\n") {
			label := ""
			if i == 0 {
				label = f.k
			}
			rows = append(rows, fmt.Sprintf("%-*s  %s", labelWidth, label, part))
		}
	}
	if len(raw) > 0 {
		rows = append(rows, "")
		dump := strings.TrimRight(hex.Dump(raw), "\n")
		rows = append(rows, strings.Split(dump, "\n")...)
	}

	inner := utf8.RuneCountInString(title) + 2
	for _, r := range rows {
		if n := utf8.RuneCountInString(r); n > inner {
			inner = n
		}
	}
	var b strings.Builder
	b.WriteString("┌─ ")
	b.WriteString(title)
	b.WriteByte(' ')
	b.WriteString(strings.Repeat("─", inner-utf8.RuneCountInString(title)-1))
	b.WriteString("┐\n")
	for _, r := range rows {
		b.WriteString("│ ")
		b.WriteString(r)
		b.WriteString(strings.Repeat(" ", inner-utf8.RuneCountInString(r)))
		b.WriteString(" │\n")
	}
	b.WriteString("└")
	b.WriteString(strings.Repeat("─", inner+2))
	b.WriteString("┘")
	return b.String()
}

// sealedKey labels the MAC-and-ciphertext blob in envelope fields.
const sealedKey = "sealed"

// shortHex renders up to limit bytes as hex, ellipsised beyond.
func shortHex(b []byte, limit int) string {
	if len(b) <= limit {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:limit]) + "…"
}

// safeText neutralises a string that came off the wire before it is
// printed to a terminal: control and escape characters (which could
// inject ANSI sequences), C1 controls and bidirectional format
// characters (which could spoof the display) are replaced with U+FFFD.
// Legitimate printable Unicode is kept — including emoji, whose
// zero-width joiners and variation selectors are preserved so compound
// sequences render whole.
func safeText(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\u200d', r >= '\ufe00' && r <= '\ufe0f':
			b.WriteRune(r) // ZWJ, variation selectors: keep emoji intact
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			b.WriteRune('\ufffd')
		}
	}
	return b.String()
}

// advTypeName is the node-type label for an advert.
func advTypeName(t uint8) string {
	names := [...]string{"NONE", "CHAT", "REPEATER", "ROOM", "SENSOR"}
	if int(t) < len(names) {
		return names[t]
	}
	return strconv.Itoa(int(t))
}

// advertName decodes an ADVERT packet's node type and name (without
// verifying the signature — a monitor wants to see forged adverts too)
// and returns a sanitised "TYPE \"name\"" label, or "" if the payload
// is not a structurally valid advert.
func (p *Packet) advertName() string {
	if p.PayloadType() != PayloadTypeAdvert || len(p.Payload) < advertFixedLen {
		return ""
	}
	ad, err := ParseAdvertData(p.Payload[advertFixedLen:])
	if err != nil {
		return ""
	}
	label := advTypeName(ad.Type)
	if ad.Name != "" {
		label += " " + strconv.Quote(safeText(ad.Name))
	}
	return label
}

// ---- Packet ----------------------------------------------------------

func (p *Packet) fields() []field {
	fs := []field{{"ver", strconv.Itoa(int(p.PayloadVer()))}}
	if p.HasTransportCodes() {
		fs = append(fs, field{"transport", fmt.Sprintf("%04x:%04x", p.TransportCodes[0], p.TransportCodes[1])})
	}
	path := fmt.Sprintf("%d×%dB", p.PathHashCount(), p.PathHashSize())
	if n := p.PathByteLen(); n > 0 && n <= 8 && n <= len(p.Path) {
		path += ":" + hex.EncodeToString(p.Path[:n])
	}
	fs = append(fs, field{"path", path})
	fs = append(fs, field{"payload", fmt.Sprintf("%dB", len(p.Payload))})
	h := p.Hash()
	fs = append(fs, field{"hash", hex.EncodeToString(h[:])})
	if name := p.advertName(); name != "" {
		fs = append(fs, field{"advert", name})
	}
	return fs
}

// String renders the packet on one line for trace logs:
// payload type, route, version, path shape, payload size and dedup hash.
func (p *Packet) String() string {
	return oneline(fmt.Sprintf("%s %s", p.PayloadType(), p.Route()), p.fields())
}

// Summary is the minimal form: payload type, wire size and the first
// bytes of the raw frame.
func (p *Packet) Summary() string {
	raw, err := p.MarshalBinary()
	if err != nil {
		return fmt.Sprintf("%s <unencodable: %v>", p.PayloadType(), err)
	}
	return fmt.Sprintf("%s %dB %s", p.PayloadType(), len(raw), shortHex(raw, 8))
}

// Dump renders a framed, multi-line view of the packet with a full hex
// dump of its wire form.
func (p *Packet) Dump() string {
	raw, err := p.MarshalBinary()
	fs := p.fields()
	if err != nil {
		fs = append(fs, field{"raw", "<unencodable: " + err.Error() + ">"})
	} else {
		fs = append(fs, field{"raw", fmt.Sprintf("%dB", len(raw))})
	}
	return frame(fmt.Sprintf("%s %s", p.PayloadType(), p.Route()), fs, raw)
}

// RawHex returns the wire form as a lowercase hex string, or an error
// note when the packet cannot encode.
func (p *Packet) RawHex() string {
	raw, err := p.MarshalBinary()
	if err != nil {
		return "<unencodable: " + err.Error() + ">"
	}
	return hex.EncodeToString(raw)
}

// ---- decoded payload objects -----------------------------------------

func (a *Advert) fields() []field {
	data := a.Data.fields()
	fs := make([]field, 0, 2+len(data))
	fs = append(fs,
		field{"from", a.Identity.String()},
		field{"ts", a.Timestamp.Format(time.RFC3339)})
	return append(fs, data...)
}

// String renders the advert on one line: sender, timestamp and app data.
func (a *Advert) String() string { return oneline("ADVERT", a.fields()) }

// Dump renders a framed view of the advert, with a hex dump of its
// re-encoded app data.
func (a *Advert) Dump() string { return frame("ADVERT", a.fields(), a.Data.EncodeAppData()) }

func (a *AdvertData) fields() []field {
	fs := []field{{"type", advTypeName(a.Type)}}
	if a.Name != "" {
		fs = append(fs, field{"name", strconv.Quote(safeText(a.Name))})
	}
	if a.HasLoc {
		fs = append(fs, field{"loc", fmt.Sprintf("%.6f,%.6f", a.Lat(), a.Lon())})
	}
	if a.Feat1 != 0 {
		fs = append(fs, field{"feat1", fmt.Sprintf("0x%04x", a.Feat1)})
	}
	if a.Feat2 != 0 {
		fs = append(fs, field{"feat2", fmt.Sprintf("0x%04x", a.Feat2)})
	}
	return fs
}

// String renders the app data on one line.
func (a *AdvertData) String() string { return oneline("ADVERT_DATA", a.fields()) }

// Dump renders a framed view of the app data with its encoded bytes.
func (a *AdvertData) Dump() string { return frame("ADVERT_DATA", a.fields(), a.EncodeAppData()) }

func (d *Datagram) fields() []field {
	return []field{
		{"dest", hex.EncodeToString(d.DestHash)},
		{"src", hex.EncodeToString(d.SrcHash)},
		{sealedKey, fmt.Sprintf("%dB", len(d.Sealed))},
	}
}

// String renders the envelope on one line.
func (d *Datagram) String() string { return oneline("DATAGRAM", d.fields()) }

// Dump renders a framed view with a hex dump of the sealed data.
func (d *Datagram) Dump() string { return frame("DATAGRAM", d.fields(), d.Sealed) }

func (d *AnonDatagram) fields() []field {
	sender := Identity{}
	copy(sender.PubKey[:], d.SenderPub)
	return []field{
		{"dest", hex.EncodeToString(d.DestHash)},
		{"sender", sender.String()},
		{sealedKey, fmt.Sprintf("%dB", len(d.Sealed))},
	}
}

// String renders the envelope on one line.
func (d *AnonDatagram) String() string { return oneline("ANON_REQ", d.fields()) }

// Dump renders a framed view with a hex dump of the sealed data.
func (d *AnonDatagram) Dump() string { return frame("ANON_REQ", d.fields(), d.Sealed) }

func (d *GroupDatagram) fields() []field {
	return []field{
		{"channel", hex.EncodeToString(d.ChannelHash)},
		{sealedKey, fmt.Sprintf("%dB", len(d.Sealed))},
	}
}

// String renders the envelope on one line.
func (d *GroupDatagram) String() string { return oneline("GROUP", d.fields()) }

// Dump renders a framed view with a hex dump of the sealed data.
func (d *GroupDatagram) Dump() string { return frame("GROUP", d.fields(), d.Sealed) }

func (pr *PathReturn) fields() []field {
	return []field{
		{"path", fmt.Sprintf("%d×%dB:%s", pr.PathLen&63, (pr.PathLen>>6)+1, hex.EncodeToString(pr.Path))},
		{"extra_type", fmt.Sprintf("0x%02x", pr.ExtraType)},
		{"extra", fmt.Sprintf("%dB", len(pr.Extra))},
	}
}

// String renders the decoded path return on one line.
func (pr *PathReturn) String() string { return oneline("PATH_RETURN", pr.fields()) }

// Dump renders a framed view with a hex dump of the extra bytes.
func (pr *PathReturn) Dump() string { return frame("PATH_RETURN", pr.fields(), pr.Extra) }

func (m *Multipart) fields() []field {
	return []field{
		{"remaining", strconv.Itoa(int(m.Remaining))},
		{"inner", m.Inner.String()},
		{"data", fmt.Sprintf("%dB", len(m.Data))},
	}
}

// String renders the wrapper on one line.
func (m *Multipart) String() string { return oneline("MULTIPART", m.fields()) }

// Dump renders a framed view with a hex dump of the inner payload.
func (m *Multipart) Dump() string { return frame("MULTIPART", m.fields(), m.Data) }

func (tr *Trace) fields() []field {
	snrs := make([]string, len(tr.SNRx4))
	for i, s := range tr.SNRx4 {
		snrs[i] = fmt.Sprintf("%+.2f", float64(s)/4)
	}
	return []field{
		{"tag", fmt.Sprintf("%08x", tr.Tag)},
		{"auth", fmt.Sprintf("%08x", tr.AuthCode)},
		{"flags", fmt.Sprintf("0x%02x", tr.Flags)},
		{"route", fmt.Sprintf("%d×%dB", len(tr.Route)/max(tr.HashWidth, 1), tr.HashWidth)},
		{"snr_db", "[" + strings.Join(snrs, " ") + "]"},
	}
}

// String renders the trace on one line.
func (tr *Trace) String() string { return oneline("TRACE", tr.fields()) }

// Dump renders a framed view with a hex dump of the requested route.
func (tr *Trace) Dump() string { return frame("TRACE", tr.fields(), tr.Route) }

// ---- identities & channels: short and REDACTED forms -----------------

// String renders the identity as a short node id: the leading and
// trailing bytes of the public key.
func (id Identity) String() string {
	return hex.EncodeToString(id.PubKey[:4]) + "…" + hex.EncodeToString(id.PubKey[30:])
}

// String identifies the local identity WITHOUT revealing any private
// material — %v and %+v on a LocalIdentity are safe in logs.
func (li LocalIdentity) String() string {
	return "LocalIdentity(" + li.Identity.String() + ")"
}

// GoString redacts %#v the same way String redacts %v.
func (li LocalIdentity) GoString() string { return li.String() }

// String identifies the channel by its hash WITHOUT revealing the
// secret — %v and %+v on a GroupChannel are safe in logs.
func (ch GroupChannel) String() string {
	return "GroupChannel(" + hex.EncodeToString(ch.Hash) + ")"
}

// GoString redacts %#v the same way String redacts %v.
func (ch GroupChannel) GoString() string { return ch.String() }
