package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"meshrunner.dev/pkg/meshcore"
)

// meshcoreJWT builds a MeshCore-style Ed25519 JWT and its paired MQTT
// username — the scheme mesh observers use to authenticate to their
// broker:
//
//   - header {"alg":"Ed25519","typ":"JWT"} and a payload with the
//     uppercase public key, audience and iat/exp, compact JSON;
//   - both base64url-encoded without padding and joined with '.';
//   - signed with the identity's Ed25519 key, the signature appended
//     as HEX (not base64url — a MeshCore quirk);
//   - the MQTT username is "v1_"+lowercase-public-key, the password is
//     the token.
func meshcoreJWT(id *meshcore.LocalIdentity, audience string, ttl time.Duration, now time.Time) (string, string) {
	pubHex := hex.EncodeToString(id.PubKey[:])

	type payload struct {
		PublicKey string `json:"publicKey"`
		Aud       string `json:"aud"`
		Iat       int64  `json:"iat"`
		Exp       int64  `json:"exp"`
		Email     string `json:"email"`
		Owner     string `json:"owner"`
	}
	// json.Marshal emits compact JSON (no spaces), matching the
	// reference's separators=(",",":").
	payloadJSON, err := json.Marshal(payload{
		PublicKey: strings.ToUpper(pubHex),
		Aud:       audience,
		Iat:       now.Unix(),
		Exp:       now.Add(ttl).Unix(),
	})
	if err != nil {
		panic("meshmon: JWT payload not marshalable: " + err.Error()) // unreachable
	}

	b64 := base64.RawURLEncoding.EncodeToString
	signingInput := b64([]byte(`{"alg":"Ed25519","typ":"JWT"}`)) + "." + b64(payloadJSON)
	sig := id.Sign([]byte(signingInput))

	return "v1_" + pubHex, signingInput + "." + hex.EncodeToString(sig)
}
