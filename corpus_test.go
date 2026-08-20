package meshcore

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"iter"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// mqttRecord is one line of a testdata/mqtt capture: a raw MQTT message
// as observed on a meshcore broker. The payload of `…/packets` topics
// is itself JSON (mqttPacket), carried in b64.
type mqttRecord struct {
	TS    string `json:"ts"`
	Topic string `json:"topic"`
	B64   string `json:"b64"`
}

// mqttPacket is the inner payload published by capture clients
// (meshcore firmware, meshcoretomqtt, meshcore-packet-capture, …) for
// each frame heard on air. `raw` is the full frame in hex; `hash` is
// the 8-byte dedup hash as computed by the reporting client, and
// `packet_type`/`payload_len` its own parse of the frame — clients
// carry them as JSON strings.
type mqttPacket struct {
	Type       string `json:"type"`
	Raw        string `json:"raw"`
	Hash       string `json:"hash"`
	PacketType string `json:"packet_type"`
	PayloadLen string `json:"payload_len"`
}

// TestMQTTCorpus replays field captures dropped under testdata/mqtt:
// nearly every reported frame must parse (field captures contain the
// odd RF-corrupted frame) and survive an encode round-trip, and — when
// the reporter attached a dedup hash AND its own parse of the frame
// agrees with ours — hash to the same 8 bytes it computed. The
// agreement gate matters: some clients (meshcore-packet-capture) hash
// their own, sometimes wrong, view of the frame.
func TestMQTTCorpus(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "mqtt", "*.ndjson.gz"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no captures in testdata/mqtt yet")
	}

	for _, path := range files {
		t.Run(filepath.Base(path), func(t *testing.T) {
			var frames, empty, unparseable, hashChecked, hashSkipped int
			for line := range ndjsonLines(t, path) {
				var rec mqttRecord
				if err := json.Unmarshal(line, &rec); err != nil {
					t.Fatalf("invalid capture line: %v", err)
				}
				parts := strings.Split(rec.Topic, "/")
				if parts[len(parts)-1] != "packets" {
					continue
				}
				payload, err := base64.StdEncoding.DecodeString(rec.B64)
				if err != nil {
					t.Fatalf("%s: bad b64: %v", rec.TS, err)
				}
				var pkt mqttPacket
				// Retained status blobs also live on packets topics;
				// only type=PACKET entries carry a frame.
				if json.Unmarshal(payload, &pkt) != nil || pkt.Type != "PACKET" {
					continue
				}
				if pkt.Raw == "" {
					empty++ // reporter event without a frame
					continue
				}

				frame, err := hex.DecodeString(pkt.Raw)
				if err != nil {
					t.Fatalf("%s: raw is not hex: %v", rec.TS, err)
				}
				p, err := ParsePacket(frame)
				if err != nil {
					unparseable++
					t.Logf("%s: unparseable frame (%v): %s", rec.TS, err, pkt.Raw)
					continue
				}
				frames++

				back, err := p.MarshalBinary()
				if err != nil || !bytes.Equal(back, frame) {
					t.Errorf("%s: round-trip drift (err=%v, raw=%s)", rec.TS, err, pkt.Raw)
				}

				if len(pkt.Hash) != 2*MaxHashSize {
					continue
				}
				repType, err1 := strconv.Atoi(pkt.PacketType)
				repLen, err2 := strconv.Atoi(pkt.PayloadLen)
				if err1 != nil || err2 != nil ||
					repType != int(p.PayloadType()) || repLen != len(p.Payload) {
					hashSkipped++ // reporter's own parse is off; its hash is untrustworthy
					continue
				}
				want, err := hex.DecodeString(pkt.Hash)
				if err != nil {
					t.Fatalf("%s: hash is not hex: %v", rec.TS, err)
				}
				if got := p.Hash(); !bytes.Equal(got[:], want) {
					t.Errorf("%s: hash %x, reporter says %s (raw=%s)",
						rec.TS, got, pkt.Hash, pkt.Raw)
				}
				hashChecked++
			}

			t.Logf("%d frames parsed, %d hashes cross-checked (%d empty, %d unparseable, %d hashes skipped on reporter disagreement)",
				frames, hashChecked, empty, unparseable, hashSkipped)
			if frames == 0 {
				t.Fatal("no frame in capture — schema drift? see testdata/README.md")
			}
			if unparseable*100 > frames {
				t.Errorf("%d/%d frames unparseable — beyond field-noise levels", unparseable, frames)
			}
			if hashChecked == 0 {
				t.Error("no hash cross-checked — the capture format changed?")
			}
		})
	}
}

// ndjsonLines yields the lines of a gzipped-or-plain NDJSON file.
// It takes testing.TB so fuzz targets can use it to seed their corpus.
func ndjsonLines(tb testing.TB, path string) iter.Seq[[]byte] {
	tb.Helper()
	return func(yield func([]byte) bool) {
		f, err := os.Open(path)
		if err != nil {
			tb.Fatal(err)
		}
		defer f.Close()

		var r io.Reader = f
		if strings.HasSuffix(path, ".gz") {
			gz, err := gzip.NewReader(f)
			if err != nil {
				tb.Fatal(err)
			}
			defer gz.Close()
			r = gz
		}

		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			if line := bytes.TrimSpace(sc.Bytes()); len(line) > 0 {
				if !yield(line) {
					return
				}
			}
		}
		if err := sc.Err(); err != nil {
			tb.Fatal(err)
		}
	}
}

// TestMQTTChannelDerivations proves the channel-key derivations against
// live traffic: NewPublicChannel and NewHashtagChannel must open real
// GRP_TXT frames from the captures — the MAC (not the 1-byte channel
// hash, which collides) is the authority. This is how the app-side
// hashtag convention SHA256("#"+tag)[:16] was reverse-engineered and is
// how it stays pinned.
func TestMQTTChannelDerivations(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "mqtt", "*.ndjson.gz"))
	if len(files) == 0 {
		t.Skip("no captures in testdata/mqtt yet")
	}

	// Candidate channels a Paris capture is expected to carry.
	channels := map[string]*GroupChannel{
		"Public": NewPublicChannel(),
		"#test":  NewHashtagChannel("test"),
		"#fr":    NewHashtagChannel("fr"),
	}
	opened := map[string]int{}

	for _, path := range files {
		for line := range ndjsonLines(t, path) {
			var rec mqttRecord
			if json.Unmarshal(line, &rec) != nil {
				continue
			}
			parts := strings.Split(rec.Topic, "/")
			if parts[len(parts)-1] != "packets" {
				continue
			}
			payload, err := base64.StdEncoding.DecodeString(rec.B64)
			if err != nil {
				continue
			}
			var pkt mqttPacket
			if json.Unmarshal(payload, &pkt) != nil || pkt.Type != "PACKET" || pkt.Raw == "" {
				continue
			}
			frame, err := hex.DecodeString(pkt.Raw)
			if err != nil {
				continue
			}
			p, err := ParsePacket(frame)
			if err != nil || p.PayloadType() != PayloadTypeGrpTxt {
				continue
			}
			gd, err := ParseGroupDatagram(p.Payload)
			if err != nil {
				continue
			}
			for name, ch := range channels {
				if ch.Hash[0] != gd.ChannelHash[0] {
					continue
				}
				if _, err := gd.Open(ch); err == nil { // MAC validates ⇒ this channel
					opened[name]++
				}
			}
		}
	}

	t.Logf("GRP_TXT opened by derived channel keys: %v", opened)
	// The derivations are only meaningful if they actually decrypt live
	// traffic; require each expected channel to have opened some frames.
	for _, name := range []string{"Public", "#test", "#fr"} {
		if opened[name] == 0 {
			t.Errorf("channel %s opened no frames — derivation broken or capture lacks it", name)
		}
	}
}

// TestMQTTTransportRegions proves the transport-region primitive against
// live traffic: TransportKeyForName("fr").Matches must recognise the
// real #fr-scoped floods in the capture. As with channels, the code
// (HMAC over type‖payload) is the authority, not a guess.
func TestMQTTTransportRegions(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join("testdata", "mqtt", "*.ndjson.gz"))
	if len(files) == 0 {
		t.Skip("no captures in testdata/mqtt yet")
	}
	fr := TransportKeyForName("fr")
	var scoped, matched int

	for _, path := range files {
		for line := range ndjsonLines(t, path) {
			var rec mqttRecord
			if json.Unmarshal(line, &rec) != nil {
				continue
			}
			parts := strings.Split(rec.Topic, "/")
			if parts[len(parts)-1] != "packets" {
				continue
			}
			payload, err := base64.StdEncoding.DecodeString(rec.B64)
			if err != nil {
				continue
			}
			var pkt mqttPacket
			if json.Unmarshal(payload, &pkt) != nil || pkt.Type != "PACKET" || pkt.Raw == "" {
				continue
			}
			frame, err := hex.DecodeString(pkt.Raw)
			if err != nil {
				continue
			}
			p, err := ParsePacket(frame)
			if err != nil || !p.HasTransportCodes() {
				continue
			}
			scoped++
			if fr.Matches(p) {
				matched++
			}
		}
	}

	t.Logf("transport-scoped packets: %d, matched region #fr: %d", scoped, matched)
	if matched == 0 {
		t.Error("region #fr matched no live traffic — transport-code derivation broken")
	}
}
