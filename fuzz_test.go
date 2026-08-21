package meshcore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

// seedFromGolden feeds up to limit hex blobs extracted from the golden
// corpora to the fuzzer — real reference-produced inputs make far
// better starting points than the fuzzer's own guesses.
func seedFromGolden(f *testing.F, field func(*goldenRecord) string, limit int) {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "golden", "*.ndjson.gz"))
	if err != nil || len(files) == 0 {
		return
	}
	n := 0
	for _, path := range files {
		for line := range ndjsonLines(f, path) {
			var rec goldenRecord
			if json.Unmarshal(line, &rec) != nil {
				continue
			}
			if s := field(&rec); s != "" {
				if b, err := hex.DecodeString(s); err == nil {
					f.Add(b)
					if n++; n >= limit {
						return
					}
				}
			}
		}
	}
}

// seedFromMQTT feeds up to limit frames from the field captures.
func seedFromMQTT(f *testing.F, limit int) {
	f.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "mqtt", "*.ndjson.gz"))
	if err != nil {
		return
	}
	n := 0
	for _, path := range files {
		for line := range ndjsonLines(f, path) {
			var rec mqttRecord
			if json.Unmarshal(line, &rec) != nil {
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
			if frame, err := hex.DecodeString(pkt.Raw); err == nil {
				f.Add(frame)
				if n++; n >= limit {
					return
				}
			}
		}
	}
}

// FuzzParsePacket: whatever the input, the parser must not panic, and
// anything it accepts must re-encode byte-identically and hash without
// incident.
func FuzzParsePacket(f *testing.F) {
	seedFromMQTT(f, 100)
	seedFromGolden(f, func(r *goldenRecord) string { return r.Frame }, 200)

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParsePacket(data)
		if err != nil {
			return
		}
		out, err := p.MarshalBinary()
		if err != nil {
			t.Fatalf("accepted frame fails to re-encode: %v", err)
		}
		if !bytes.Equal(out, data) {
			t.Fatalf("round-trip drift:\n in  % x\n out % x", data, out)
		}
		_ = p.Hash()
	})
}

// FuzzParseAdvertData: no panic on any blob; anything accepted must
// re-encode without error into a blob that parses again.
func FuzzParseAdvertData(f *testing.F) {
	seedFromGolden(f, func(r *goldenRecord) string { return r.AppData }, 100)

	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := ParseAdvertData(data)
		if err != nil {
			return
		}
		b := a.EncodeAppData()
		if _, err := ParseAdvertData(b); err != nil {
			t.Fatalf("re-encoded blob does not parse: %v (in=% x, out=% x)", err, data, b)
		}
	})
}

// FuzzMACThenDecrypt: no panic for any key/blob pair, and anything the
// MAC accepts must re-seal to the exact input bytes — decrypted output
// is block-padded, so sealing it again is deterministic.
func FuzzMACThenDecrypt(f *testing.F) {
	seed, _ := EncryptThenMAC(testSecret, []byte("seed payload"))
	f.Add([]byte("key"), seed)
	f.Add([]byte{}, []byte{0, 0, 0})

	f.Fuzz(func(t *testing.T, key, data []byte) {
		secret := sha256.Sum256(key)
		plain, err := MACThenDecrypt(secret[:], data)
		if err != nil {
			return
		}
		resealed, err := EncryptThenMAC(secret[:], plain)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(resealed, data) {
			t.Fatalf("reseal drift:\n in  % x\n out % x", data, resealed)
		}
	})
}

// FuzzParseTextPlaintext: the text and group-text plaintext parsers must
// not panic on arbitrary bytes, whatever the flags or padding.
func FuzzParseTextPlaintext(f *testing.F) {
	f.Add(BuildTextPlaintext(time.Unix(1, 0), TxtTypePlain, "hi"))
	f.Add(BuildTextPlaintextAttempt(time.Unix(1, 0), TxtTypeCLIData, "cmd", 7))
	f.Add(BuildGroupText(time.Unix(1, 0), "alice", "hey"))
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseTextPlaintext(data)
		_, _ = ParseGroupText(data)
	})
}

// FuzzLPPDecode: the Cayenne LPP decoder must not panic on arbitrary
// bytes — truncated headers, unknown types, malformed polylines.
func FuzzLPPDecode(f *testing.F) {
	e := NewLPPEncoder()
	_ = e.Add(LPPReading{Channel: 1, Type: LPPVoltage, Value: 4.2})
	_ = e.Add(LPPReading{Channel: 1, Type: LPPGPS, Value: LPPGPSValue{Latitude: 48, Longitude: 2, Altitude: 30}})
	f.Add(e.Bytes())
	f.Add([]byte{0x01, 0xF0, 0x08})
	f.Add([]byte{})
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = LPPDecode(data)
	})
}
