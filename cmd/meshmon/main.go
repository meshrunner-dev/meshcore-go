// Command meshmon subscribes to an MQTT broker where mesh observers
// publish captured traffic and pretty-prints each MeshCore packet.
//
//	meshmon wss://broker.example/mqtt
//	meshmon --format line --topic 'meshcore/PAR/#' tcp://localhost:1883
//
// It supports plain (tcp), TLS (ssl), WebSocket (ws) and secure
// WebSocket (wss) brokers — the last being the common observer setup.
// TLS certificates are verified by default; --insecure turns that off.
// Auth is optional: basic username/password, a ready-made JWT as the
// password, or a MeshCore Ed25519 JWT generated on the fly from an
// identity key (the scheme mesh observers authenticate with).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/kong"
	mqtt "github.com/eclipse/paho.mqtt.golang"

	"meshrunner.dev/pkg/meshcore"
)

type cli struct {
	Broker string `arg:"" help:"Broker URL: tcp://, ssl://, ws:// or wss://host[:port][/path]."`

	Topic  string `default:"meshcore/+/+/packets" help:"Subscription topic filter ('+' one level, '#' all trailing)." short:"t"`
	Format string `default:"dump"                 enum:"dump,line,summary"                                            help:"Packet print format: ${enum}." short:"f"`

	Retained   bool `help:"Show retained messages too (nodes' presence/status blobs, delivered on connect); ignored by default." short:"r"`
	FramesOnly bool `help:"Hide messages that carry no MeshCore frame (telemetry/status blobs)."                                 short:"F"`
	Dedup      bool `help:"Drop duplicate packets: a frame relayed by several nodes prints once (by dedup hash)."                short:"d"`

	Insecure bool   `help:"Skip TLS certificate verification."                         short:"k"`
	CA       string `help:"PEM CA bundle to trust for TLS (adds to the system roots)." placeholder:"FILE"`

	User     string `help:"MQTT username (basic auth)."                                            short:"u"`
	Password string `help:"MQTT password (basic auth)."                                            short:"P"`
	Token    string `help:"Use this JWT as the MQTT password (pair with --user for the username)."`

	JWTIdentity string        `help:"Generate a MeshCore Ed25519 JWT from this private key (any format)." name:"jwt-identity"                   placeholder:"HEX"`
	JWTAudience string        `help:"Audience claim for the generated JWT."                               name:"jwt-audience"`
	JWTTTL      time.Duration `default:"5m"                                                               help:"Lifetime of the generated JWT." name:"jwt-ttl"`
}

var errNoCerts = errors.New("no certificates found in the CA file")

func main() {
	var c cli
	parser, err := kong.New(&c,
		kong.Name("meshmon"),
		kong.Description("Subscribe to a mesh observer's MQTT broker and pretty-print each MeshCore packet."),
		kong.UsageOnError(),
	)
	if err != nil {
		panic(err)
	}
	if _, err := parser.Parse(os.Args[1:]); err != nil {
		parser.FatalIfErrorf(err)
	}
	if err := c.run(); err != nil {
		fmt.Fprintln(os.Stderr, "meshmon:", err)
		os.Exit(1)
	}
}

func (c *cli) run() error {
	opts := mqtt.NewClientOptions().AddBroker(c.Broker)
	opts.SetClientID(fmt.Sprintf("meshmon-%d", os.Getpid()))
	opts.SetCleanSession(true)
	opts.SetOrderMatters(false)

	tlsCfg, err := c.tlsConfig()
	if err != nil {
		return err
	}
	opts.SetTLSConfig(tlsCfg)

	if err := c.applyAuth(opts); err != nil {
		return err
	}

	var mu sync.Mutex
	dedup := newDeduper(8192)
	opts.SetDefaultPublishHandler(func(_ mqtt.Client, m mqtt.Message) {
		// Retained messages are the broker's last-known value for a
		// topic, delivered in a burst on connect — mostly node presence
		// blobs, not live traffic. Skip them unless asked.
		if m.Retained() && !c.Retained {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		c.handle(m.Topic(), m.Payload(), dedup)
	})
	opts.OnConnect = func(cl mqtt.Client) {
		if t := cl.Subscribe(c.Topic, 0, nil); t.Wait() && t.Error() != nil {
			fmt.Fprintln(os.Stderr, "meshmon: subscribe:", t.Error())
			return
		}
		fmt.Fprintf(os.Stderr, "connected to %s, subscribed to %q\n", c.Broker, c.Topic)
	}
	opts.OnConnectionLost = func(_ mqtt.Client, err error) {
		fmt.Fprintln(os.Stderr, "meshmon: connection lost:", err)
	}

	client := mqtt.NewClient(opts)
	if t := client.Connect(); t.Wait() && t.Error() != nil {
		return fmt.Errorf("connect: %w", t.Error())
	}
	defer client.Disconnect(250)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	<-ctx.Done()
	fmt.Fprintln(os.Stderr, "\nmeshmon: disconnecting")
	return nil
}

// tlsConfig builds the TLS config: verified by default, optionally with
// an extra CA bundle, or verification disabled with --insecure.
func (c *cli) tlsConfig() (*tls.Config, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.Insecure {
		cfg.InsecureSkipVerify = true
		return cfg, nil
	}
	if c.CA != "" {
		pem, err := os.ReadFile(c.CA)
		if err != nil {
			return nil, fmt.Errorf("read CA: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errNoCerts
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// applyAuth sets the MQTT credentials from the chosen mode.
func (c *cli) applyAuth(opts *mqtt.ClientOptions) error {
	switch {
	case c.JWTIdentity != "":
		key, err := hex.DecodeString(strings.TrimSpace(c.JWTIdentity))
		if err != nil {
			return fmt.Errorf("jwt-identity is not hex: %w", err)
		}
		id, _, err := meshcore.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("jwt-identity: %w", err)
		}
		user, token := meshcoreJWT(id, c.JWTAudience, c.JWTTTL, time.Now())
		opts.SetUsername(user)
		opts.SetPassword(token)
	case c.Token != "":
		opts.SetUsername(c.User)
		opts.SetPassword(c.Token)
	case c.User != "":
		opts.SetUsername(c.User)
		opts.SetPassword(c.Password)
	}
	return nil
}

// handle decodes one message and prints it in the chosen format,
// applying the --frames-only and --dedup filters. Payloads with no
// MeshCore frame get a short note unless hidden.
func (c *cli) handle(topic string, payload []byte, dedup *deduper) {
	frame, ok := extractFrame(payload)
	if !ok {
		if !c.FramesOnly {
			fmt.Printf("── %s\n   (no MeshCore frame)\n\n", topic)
		}
		return
	}
	p, err := meshcore.ParsePacket(frame)
	if err != nil {
		if !c.FramesOnly {
			fmt.Printf("── %s\n   unparseable frame (%v): %x\n\n", topic, err, frame)
		}
		return
	}
	if c.Dedup && dedup.seen(p.Hash()) {
		return
	}
	switch c.Format {
	case "line":
		fmt.Printf("%s  %s\n", topic, p)
	case "summary":
		fmt.Printf("%s  %s\n", topic, p.Summary())
	default:
		fmt.Printf("── %s\n%s\n\n", topic, p.Dump())
	}
}

// deduper remembers the most recent packet hashes so a frame relayed by
// several nodes is printed once. It keeps a bounded FIFO window: the
// oldest hash is evicted when the window is full.
type deduper struct {
	mu   sync.Mutex
	set  map[[meshcore.MaxHashSize]byte]struct{}
	ring [][meshcore.MaxHashSize]byte
	next int
}

func newDeduper(capacity int) *deduper {
	return &deduper{
		set:  make(map[[meshcore.MaxHashSize]byte]struct{}, capacity),
		ring: make([][meshcore.MaxHashSize]byte, capacity),
	}
}

// seen reports whether h was seen before; otherwise it records h
// (evicting the oldest entry if the window is full) and returns false.
func (d *deduper) seen(h [meshcore.MaxHashSize]byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.set[h]; ok {
		return true
	}
	if old := d.ring[d.next]; old != ([meshcore.MaxHashSize]byte{}) {
		delete(d.set, old)
	}
	d.ring[d.next] = h
	d.set[h] = struct{}{}
	d.next = (d.next + 1) % len(d.ring)
	return false
}

// extractFrame pulls the raw MeshCore frame out of an observer payload:
// either a JSON blob carrying a hex frame field (the common
// meshcoretomqtt / packet-capture form), or the raw binary frame as the
// message body.
func extractFrame(payload []byte) ([]byte, bool) {
	trimmed := trimSpace(payload)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		// A JSON observer payload: a frame field, or telemetry with none.
		return frameFromJSON(trimmed)
	}
	if len(payload) > 0 {
		return payload, true // raw binary frame as the message body
	}
	return nil, false
}

// frameFromJSON pulls a hex frame out of an observer's JSON payload.
func frameFromJSON(b []byte) ([]byte, bool) {
	var rec map[string]json.RawMessage
	if json.Unmarshal(b, &rec) != nil {
		return nil, false
	}
	for _, field := range []string{"raw", "raw_hex", "frame", "packet_hex", "hex"} {
		raw, ok := rec[field]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil || s == "" {
			continue
		}
		if frame, err := hex.DecodeString(s); err == nil && len(frame) > 0 {
			return frame, true
		}
	}
	return nil, false
}

func trimSpace(b []byte) []byte {
	i := 0
	for i < len(b) && (b[i] == ' ' || b[i] == '\t' || b[i] == '\n' || b[i] == '\r') {
		i++
	}
	return b[i:]
}
