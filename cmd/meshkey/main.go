// Command meshkey works with MeshCore node keys from the shell.
//
//	meshkey convert [--format f] [--output file] [key]
//	meshkey gen     [--format f] [--prefix hex] [--timeout d] [--output file]
//
// Private keys are handled in three serializations, detected on input
// and selectable on output:
//
//	seed      32-byte Ed25519 seed   (openHop identity_key, PyNaCl, libsodium seed)
//	expanded  64-byte orlp layout    (MeshCore firmware prv.key)
//	seed-pub  64-byte seed‖pubkey    (Go ed25519.PrivateKey, libsodium secret key)
//
// pubkey emits the 32-byte public key instead. Converting an expanded
// firmware key to a seed-bearing format fails: the expansion is one-way.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/alecthomas/kong"

	"meshrunner.dev/pkg/meshcore"
)

type cli struct {
	Convert convertCmd `cmd:"" help:"Convert a private key between serializations."`
	Gen     genCmd     `cmd:"" help:"Generate a new node key, optionally mining a public-key prefix."`
}

type convertCmd struct {
	Format string `default:"expanded"                      enum:"seed,expanded,seed-pub,pubkey"                  help:"Output format: ${enum}." short:"f"`
	Output string `help:"Write to FILE instead of stdout." placeholder:"FILE"                                    short:"o"`
	Key    string `arg:""                                  help:"Hex private key; read from stdin when omitted." optional:""`
}

func (c *convertCmd) Run() error {
	raw, err := readKey(c.Key, os.Stdin)
	if err != nil {
		return err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("input is not valid hex: %w", err)
	}

	id, format, err := meshcore.ParsePrivateKey(key)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "detected %s key, public key %x\n", format, id.PubKey[:])

	return emit(id, c.Format, c.Output)
}

type genCmd struct {
	Format  string        `default:"expanded"                                                  enum:"seed,expanded,seed-pub,pubkey" help:"Output format: ${enum}." short:"f"`
	Prefix  string        `help:"Desired public-key hex prefix (vanity search over all CPUs)." placeholder:"HEX"                    short:"p"`
	Timeout time.Duration `help:"Abort the vanity search after this long (0 = no limit)."      short:"t"`
	Output  string        `help:"Write to FILE instead of stdout."                             placeholder:"FILE"                   short:"o"`
}

func (g *genCmd) Run() error {
	id, attempts, err := generate(g.Prefix, g.Timeout)
	if err != nil {
		return err
	}
	if g.Prefix == "" {
		fmt.Fprintf(os.Stderr, "generated key, public key %x\n", id.PubKey[:])
	} else {
		fmt.Fprintf(os.Stderr, "generated key, public key %x (%d candidates tried)\n", id.PubKey[:], attempts)
	}

	return emit(id, g.Format, g.Output)
}

func main() {
	var c cli
	parser, err := newParser(&c)
	if err != nil {
		panic(err)
	}
	ctx, err := parser.Parse(os.Args[1:])
	parser.FatalIfErrorf(err)
	if err := ctx.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "meshkey:", err)
		os.Exit(1)
	}
}

// newParser builds the CLI parser; shared with the tests so dispatch
// and validation are exercised exactly as main sees them.
func newParser(c *cli, options ...kong.Option) (*kong.Kong, error) {
	return kong.New(c, append([]kong.Option{
		kong.Name("meshkey"),
		kong.Description("MeshCore node key tool: convert private keys between the " +
			"ecosystem's serializations (openHop seed, firmware expanded prv.key, " +
			"Go/libsodium seed‖pub) and generate new node keys, with optional " +
			"vanity public-key prefixes."),
		kong.UsageOnError(),
	}, options...)...)
}

// generate returns a new identity. With an empty prefix it draws one
// directly; otherwise it mines across all CPUs until the public key
// matches, bounded by timeout (0 = unbounded) and interruptible with
// Ctrl-C.
func generate(prefix string, timeout time.Duration) (*meshcore.LocalIdentity, uint64, error) {
	if prefix == "" {
		id, err := meshcore.NewLocalIdentity(rand.Reader)
		return id, 0, err
	}
	match, err := meshcore.PubKeyPrefixMatcher(prefix)
	if err != nil {
		return nil, 0, err
	}

	ctx := context.Background()
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	return meshcore.MineIdentity(ctx, match)
}

// emit encodes the identity and writes it as hex to a file or stdout.
func emit(id *meshcore.LocalIdentity, format, outFile string) error {
	encoded, err := encode(id, format)
	if err != nil {
		return err
	}
	line := hex.EncodeToString(encoded) + "\n"
	if outFile != "" {
		return os.WriteFile(outFile, []byte(line), 0o600)
	}
	_, err = io.WriteString(os.Stdout, line)
	return err
}

// readKey returns the key hex: the argument when given, otherwise the
// first line of stdin. Reading stops at the first newline, so an
// interactive user gets their answer (or their error) on Enter — no
// Ctrl-D needed; when stdin is a terminal, a short prompt says so.
func readKey(arg string, stdin io.Reader) ([]byte, error) {
	if arg != "" && arg != "-" {
		return []byte(arg), nil
	}
	if f, ok := stdin.(*os.File); ok {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			fmt.Fprintln(os.Stderr, "reading key from stdin — paste the hex key and press Enter")
		}
	}
	sc := bufio.NewScanner(stdin)
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return nil, err
		}
		return nil, errEmptyInput
	}
	return append([]byte(nil), sc.Bytes()...), nil
}

func encode(id *meshcore.LocalIdentity, format string) ([]byte, error) {
	switch format {
	case "expanded":
		return id.PrvKey(), nil
	case "pubkey":
		return append([]byte(nil), id.PubKey[:]...), nil
	case "seed":
		seed := id.Seed()
		if seed == nil {
			return nil, errOneWay
		}
		return seed, nil
	case "seed-pub":
		std, ok := id.StdPrivateKey()
		if !ok {
			return nil, errOneWay
		}
		return std, nil
	default:
		return nil, fmt.Errorf("%w: %q (want seed, expanded, seed-pub or pubkey)", errUnknownFormat, format)
	}
}

var (
	errOneWay        = errors.New("cannot recover a seed from an expanded firmware key: the expansion is one-way")
	errUnknownFormat = errors.New("unknown output format")
	errEmptyInput    = errors.New("no key on stdin")
)
