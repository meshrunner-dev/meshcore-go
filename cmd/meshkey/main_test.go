package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"

	"meshrunner.dev/pkg/meshcore"
)

// fwTestPrv/fwTestPub: the known-good firmware keypair (Identity.cpp).
const (
	fwPrv = "7065e18fd9fabb70c1ed90dca19907de698c88b709ea146eafd93d9b830c7b60" +
		"c4681193c79bbc39945ba8064104bb618f8fd7a84a0af6f57033d6e8ddcd6471"
	fwPub = "1ec77175b0918ed206f9ae04ec136d6d5d4315bb26305427f645b492e9350c10"
	seed  = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"
)

func decode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestEncodeConversions(t *testing.T) {
	// A seed-born identity converts to every format.
	fromSeed, _, err := meshcore.ParsePrivateKey(decode(t, seed))
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"seed", "expanded", "seed-pub", "pubkey"} {
		b, err := encode(fromSeed, format)
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		want := map[string]int{"seed": 32, "expanded": 64, "seed-pub": 64, "pubkey": 32}[format]
		if len(b) != want {
			t.Fatalf("%s: %d bytes, want %d", format, len(b), want)
		}
	}
	// seed round-trips through the tool.
	if got := hex.EncodeToString(mustEncode(t, fromSeed, "seed")); got != seed {
		t.Fatalf("seed round-trip: %s", got)
	}
}

func TestExpandedIsOneWay(t *testing.T) {
	fromExpanded, format, err := meshcore.ParsePrivateKey(decode(t, fwPrv))
	if err != nil {
		t.Fatal(err)
	}
	if format != meshcore.KeyFormatExpanded {
		t.Fatalf("detected %v", format)
	}
	// Expanded and pubkey work; seed and seed-pub cannot be recovered.
	if got := hex.EncodeToString(mustEncode(t, fromExpanded, "pubkey")); got != fwPub {
		t.Fatalf("pubkey = %s", got)
	}
	if hex.EncodeToString(mustEncode(t, fromExpanded, "expanded")) != fwPrv {
		t.Fatal("expanded round-trip drifted")
	}
	for _, format := range []string{"seed", "seed-pub"} {
		if _, err := encode(fromExpanded, format); !errors.Is(err, errOneWay) {
			t.Fatalf("%s from expanded: err=%v, want errOneWay", format, err)
		}
	}
}

func TestEncodeUnknownFormat(t *testing.T) {
	id, _, _ := meshcore.ParsePrivateKey(decode(t, seed))
	if _, err := encode(id, "pem"); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestReadKey(t *testing.T) {
	if b, _ := readKey("deadbeef", nil); string(b) != "deadbeef" {
		t.Fatal("positional arg ignored")
	}
	// Stdin input ends at the first newline — Enter must hand control
	// back, EOF must not be required.
	b, err := readKey("", strings.NewReader("cafe0123\ngarbage that must not be read"))
	if err != nil || string(b) != "cafe0123" {
		t.Fatalf("line read: %q err=%v", b, err)
	}
	// A line at EOF without trailing newline still counts.
	if b, err := readKey("-", strings.NewReader("cafe")); err != nil || string(b) != "cafe" {
		t.Fatalf("EOF line: %q err=%v", b, err)
	}
	if _, err := readKey("", strings.NewReader("")); !errors.Is(err, errEmptyInput) {
		t.Fatalf("empty stdin: %v", err)
	}
}

func TestSeedPubIsStdlibLayout(t *testing.T) {
	id, _, _ := meshcore.ParsePrivateKey(decode(t, seed))
	sp := mustEncode(t, id, "seed-pub")
	if !bytes.Equal(sp[:32], decode(t, seed)) {
		t.Fatal("seed-pub first half is not the seed")
	}
	if hex.EncodeToString(sp[32:]) != hex.EncodeToString(mustEncode(t, id, "pubkey")) {
		t.Fatal("seed-pub second half is not the public key")
	}
}

func mustEncode(t *testing.T, id *meshcore.LocalIdentity, format string) []byte {
	t.Helper()
	b, err := encode(id, format)
	if err != nil {
		t.Fatalf("encode %s: %v", format, err)
	}
	return b
}

func TestInputAcceptsWhitespace(t *testing.T) {
	// The tool trims the hex input; a trailing newline must not break
	// detection (files often carry one).
	trimmed := strings.TrimSpace(seed + "\n")
	if _, _, err := meshcore.ParsePrivateKey(decode(t, trimmed)); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateNoPrefix(t *testing.T) {
	id, attempts, err := generate("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 0 {
		t.Errorf("no-prefix generation should not mine, got %d attempts", attempts)
	}
	if !id.FirmwareImportable() || id.Seed() == nil {
		t.Fatal("generated key not firmware-importable or missing seed")
	}
}

func TestGenerateWithPrefix(t *testing.T) {
	id, attempts, err := generate("a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if id.PubKey[0]>>4 != 0xA {
		t.Fatalf("mined pub starts %02x, want a…", id.PubKey[0])
	}
	if attempts == 0 {
		t.Error("mining reported zero candidates")
	}
}

func TestGenerateRejectsReservedPrefix(t *testing.T) {
	if _, _, err := generate("ff", 0); err == nil {
		t.Fatal("reserved prefix accepted")
	}
}

func TestGenerateTimeoutIsHonored(t *testing.T) {
	// A 12-nibble prefix is effectively unreachable in 50ms; the search
	// must give up with the context error, not hang.
	_, _, err := generate("abcdef123456", 50*time.Millisecond)
	if err == nil {
		t.Fatal("unreachable prefix returned a key")
	}
}

// The parser is built exactly as main builds it; dispatch and flag
// validation are kong's job, checked here against our declarations.
func TestParserDispatchAndValidation(t *testing.T) {
	quiet := []kong.Option{kong.Exit(func(int) {}), kong.Writers(io.Discard, io.Discard)}

	parse := func(args ...string) error {
		var c cli
		parser, err := newParser(&c, quiet...)
		if err != nil {
			t.Fatal(err)
		}
		_, err = parser.Parse(args)
		return err
	}

	if err := parse("frobnicate"); err == nil {
		t.Error("unknown command accepted")
	}
	if err := parse(); err == nil {
		t.Error("missing command accepted")
	}
	if err := parse("gen", "--format", "pem"); err == nil {
		t.Error("enum did not reject an unknown format")
	}
	if err := parse("convert", "--format", "seed", "deadbeef"); err != nil {
		t.Errorf("valid convert invocation rejected: %v", err)
	}
	if err := parse("gen", "-p", "ca7", "-t", "30s"); err != nil {
		t.Errorf("valid gen invocation rejected: %v", err)
	}
}
