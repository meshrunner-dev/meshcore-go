// goldengen — emits protocol golden vectors as NDJSON on stdout, by
// driving the MeshCore reference sources directly (Packet, Identity,
// Utils, AdvertDataHelpers + the vendored orlp ed25519 and the
// rweather/Crypto primitives the firmware links).
//
// Verdicts are never assumed: every `valid` field records what the
// reference code actually returned, including for tampered inputs.
// Output is fully deterministic for a given seed (first argv, default 42).

#include <Packet.h>
#include <Identity.h>
#include <Utils.h>
#include <helpers/AdvertDataHelpers.h>

// Releases without UTF8Helpers truncate advert names bytewise; their
// builder output is not canonical for us, so only newer trees get the
// re-encode check (canon=true) on builder-produced app data.
#if __has_include(<helpers/UTF8Helpers.h>)
#define BUILDER_APPDATA_IS_CANONICAL true
#else
#define BUILDER_APPDATA_IS_CANONICAL false
#endif

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <random>
#include <vector>

using mesh::Packet;
using mesh::Identity;
using mesh::LocalIdentity;
using mesh::Utils;

static std::mt19937 g_rng;

static uint8_t rnd_byte() { return (uint8_t)(g_rng() & 0xFF); }
static void rnd_bytes(uint8_t* dest, size_t n) {
  for (size_t i = 0; i < n; i++) dest[i] = rnd_byte();
}

struct DetRNG : mesh::RNG {
  void random(uint8_t* dest, size_t sz) override { rnd_bytes(dest, sz); }
};

static void put_hex(const uint8_t* b, int n) {
  for (int i = 0; i < n; i++) printf("%02x", b[i]);
}
static void field_hex(const char* name, const uint8_t* b, int n) {
  printf(",\"%s\":\"", name); put_hex(b, n); printf("\"");
}
static void open_rec(const char* test) { printf("{\"test\":\"%s\"", test); }
static void close_rec() { printf("}\n"); }

// ---- packets ---------------------------------------------------------

static void emit_packet_records(const Packet& p) {
  uint8_t frame[MAX_TRANS_UNIT];
  uint8_t len = p.writeTo(frame);

  open_rec("packet_roundtrip");
  field_hex("frame", frame, len);
  close_rec();

  uint8_t hash[MAX_HASH_SIZE];
  p.calculatePacketHash(hash);
  open_rec("packet_hash");
  field_hex("frame", frame, len);
  field_hex("hash", hash, MAX_HASH_SIZE);
  close_rec();
}

// Feeds a raw frame to the reference parser and emits its verdict; for
// accepted frames also emits roundtrip + hash records.
static void emit_parse_verdict(const uint8_t* frame, int len) {
  uint8_t padded[512];  // readFrom may read past `len` before rejecting
  memset(padded, 0, sizeof(padded));
  memcpy(padded, frame, len);

  Packet p;
  bool ok = p.readFrom(padded, (uint8_t)len);

  open_rec("packet_parse");
  field_hex("frame", frame, len);
  printf(",\"valid\":%s", ok ? "true" : "false");
  close_rec();

  if (ok) emit_packet_records(p);
}

static void gen_packets_structural() {
  // Path descriptor variants: {hash size, hash count}. 63×1, 32×2 and
  // 21×3 are the per-size maxima under MAX_PATH_SIZE.
  static const int PATHV[][2] = {
    {1, 0}, {1, 1}, {1, 4}, {1, 63}, {2, 1}, {2, 32}, {3, 1}, {3, 21},
  };
  static const int PAYLEN[] = {1, 2, 5, 47, 120, MAX_PACKET_PAYLOAD};

  int n = 0;
  for (int route = 0; route <= 3; route++) {
    for (int type = 0; type <= 15; type++) {
      for (int ver = 0; ver <= 3; ver++, n++) {
        Packet p;
        p.header = (uint8_t)(route | (type << PH_TYPE_SHIFT) | (ver << PH_VER_SHIFT));
        const int* pv = PATHV[n % 8];
        p.path_len = (uint8_t)(((pv[0] - 1) << 6) | pv[1]);
        rnd_bytes(p.path, (size_t)(pv[0] * pv[1]));
        switch (n % 3) {
          case 0: p.transport_codes[0] = 0; p.transport_codes[1] = 0; break;
          case 1: p.transport_codes[0] = 0xFFFF; p.transport_codes[1] = 0xFFFF; break;
          default:
            p.transport_codes[0] = (uint16_t)g_rng();
            p.transport_codes[1] = (uint16_t)g_rng();
        }
        if (!p.hasTransportCodes()) p.transport_codes[0] = p.transport_codes[1] = 0;
        p.payload_len = (uint8_t)PAYLEN[n % 6];
        rnd_bytes(p.payload, p.payload_len);
        emit_packet_records(p);
      }
    }
  }

  // The TRACE hash preimage includes path_len: same payload under
  // different path descriptors must yield different hashes.
  Packet t;
  t.header = (uint8_t)(ROUTE_TYPE_FLOOD | (PAYLOAD_TYPE_TRACE << PH_TYPE_SHIFT));
  t.payload_len = 9;
  rnd_bytes(t.payload, t.payload_len);
  static const uint8_t TRACE_PL[] = {0, 2, (uint8_t)((1 << 6) | 3)};
  for (uint8_t pl : TRACE_PL) {
    t.path_len = pl;
    rnd_bytes(t.path, (size_t)((pl >> 6) + 1) * (pl & 63));
    emit_packet_records(t);
  }
}

static void gen_packets_negative() {
  uint8_t f[MAX_TRANS_UNIT];

  emit_parse_verdict(f, 0);                       // empty frame
  f[0] = 0x11; emit_parse_verdict(f, 1);          // header only
  f[0] = 0x11; f[1] = 0x00; emit_parse_verdict(f, 2);  // no payload
  f[0] = 0x10; f[1] = 0x00; f[2] = 0x00; emit_parse_verdict(f, 3);  // transport codes cut short

  f[0] = 0x11; f[1] = 0xC1; f[2] = 0xAB; f[3] = 0x01;
  emit_parse_verdict(f, 4);                       // reserved hash-size code (4 bytes)

  f[0] = 0x11; f[1] = (uint8_t)((1 << 6) | 33);   // 33×2 = 66 > MAX_PATH_SIZE
  rnd_bytes(f + 2, 70);
  emit_parse_verdict(f, 72);

  f[0] = 0x11; f[1] = 10;                         // 10 path hashes declared,
  rnd_bytes(f + 2, 6);                            // frame ends inside the path
  emit_parse_verdict(f, 8);

  f[0] = 0x11; f[1] = 0x00;                       // payload longer than MAX_PACKET_PAYLOAD
  rnd_bytes(f + 2, 253);
  emit_parse_verdict(f, 255);
}

static void gen_packets_fuzz(int count) {
  uint8_t f[MAX_TRANS_UNIT];
  for (int i = 0; i < count; i++) {
    int len = 1 + (int)(g_rng() % MAX_TRANS_UNIT);
    rnd_bytes(f, (size_t)len);
    emit_parse_verdict(f, len);
  }
}

// ---- identities & symmetric crypto -----------------------------------

// prv_key is private; the public buffer serializer hands it out.
static void get_prv(const LocalIdentity& li, uint8_t out[PRV_KEY_SIZE]) {
  uint8_t buf[PRV_KEY_SIZE + PUB_KEY_SIZE];
  const_cast<LocalIdentity&>(li).writeTo(buf, sizeof(buf));
  memcpy(out, buf, PRV_KEY_SIZE);
}

static void gen_crypto(const std::vector<LocalIdentity>& ids) {
  static const int MSGLEN[] = {0, 1, 15, 16, 17, 32, 33, 183, 300};
  uint8_t msg[300], sig[SIGNATURE_SIZE];

  // sign + verify (true, then tampered with the actual verdict recorded)
  for (size_t k = 0; k < 4; k++) {
    const LocalIdentity& li = ids[k];
    uint8_t prv[PRV_KEY_SIZE];
    get_prv(li, prv);
    for (int ml : MSGLEN) {
      rnd_bytes(msg, (size_t)ml);
      li.sign(sig, msg, ml);

      open_rec("sign");
      field_hex("prv", prv, PRV_KEY_SIZE);
      field_hex("message", msg, ml);
      field_hex("signature", sig, SIGNATURE_SIZE);
      close_rec();

      auto emit_verify = [&](const uint8_t* pub, const uint8_t* s, const uint8_t* m, int mlen) {
        Identity id;
        memcpy(id.pub_key, pub, PUB_KEY_SIZE);
        open_rec("verify");
        field_hex("pub", pub, PUB_KEY_SIZE);
        field_hex("message", m, mlen);
        field_hex("signature", s, SIGNATURE_SIZE);
        printf(",\"valid\":%s", id.verify(s, m, mlen) ? "true" : "false");
        close_rec();
      };
      emit_verify(li.pub_key, sig, msg, ml);
      if (ml % 3 == 0) {  // subsample the negatives
        uint8_t bad[SIGNATURE_SIZE];
        memcpy(bad, sig, SIGNATURE_SIZE);
        bad[(size_t)ml % SIGNATURE_SIZE] ^= 0x01;
        emit_verify(li.pub_key, bad, msg, ml);            // corrupted signature
        emit_verify(ids[(k + 1) % 4].pub_key, sig, msg, ml);  // wrong key
        if (ml > 0) {
          msg[0] ^= 0x80;
          emit_verify(li.pub_key, sig, msg, ml);          // corrupted message
          msg[0] ^= 0x80;
        }
      }
    }
  }

  // shared secrets, both directions of every pair
  for (size_t a = 0; a < 4; a++) {
    for (size_t b = 0; b < 4; b++) {
      if (a == b) continue;
      uint8_t secret[PUB_KEY_SIZE], prv_a[PRV_KEY_SIZE];
      ids[a].calcSharedSecret(secret, ids[b].pub_key);
      get_prv(ids[a], prv_a);
      open_rec("shared_secret");
      field_hex("prv_a", prv_a, PRV_KEY_SIZE);
      field_hex("pub_b", ids[b].pub_key, PUB_KEY_SIZE);
      field_hex("secret", secret, PUB_KEY_SIZE);
      close_rec();
    }
  }

  // encrypt-then-MAC, and MAC-then-decrypt with recorded verdicts
  static const int PLAINLEN[] = {1, 15, 16, 17, 32, 100, 168};
  for (int s = 0; s < 3; s++) {
    uint8_t secret[PUB_KEY_SIZE];
    rnd_bytes(secret, sizeof(secret));
    for (int pl : PLAINLEN) {
      uint8_t plain[168], sealed[2 + 176];
      rnd_bytes(plain, (size_t)pl);
      int sealed_len = Utils::encryptThenMAC(secret, sealed, plain, pl);

      open_rec("encrypt_then_mac");
      field_hex("secret", secret, PUB_KEY_SIZE);
      field_hex("plain", plain, pl);
      field_hex("out", sealed, sealed_len);
      close_rec();

      auto emit_mtd = [&](const uint8_t* key, const uint8_t* in, int in_len) {
        uint8_t out[192];
        int out_len = Utils::MACThenDecrypt(key, out, in, in_len);
        open_rec("mac_then_decrypt");
        field_hex("secret", key, PUB_KEY_SIZE);
        field_hex("in", in, in_len);
        printf(",\"valid\":%s", out_len > 0 ? "true" : "false");
        if (out_len > 0) field_hex("plain", out, out_len);
        close_rec();
      };
      emit_mtd(secret, sealed, sealed_len);
      if (pl % 2 == s % 2) {  // subsample the negatives
        uint8_t bad[2 + 176];
        memcpy(bad, sealed, (size_t)sealed_len);
        bad[0] ^= 0x01;                       // MAC bit
        emit_mtd(secret, bad, sealed_len);
        bad[0] ^= 0x01;
        bad[sealed_len - 1] ^= 0x10;          // ciphertext bit
        emit_mtd(secret, bad, sealed_len);
        emit_mtd(secret, sealed, 2);          // nothing after the MAC
        uint8_t wrong[PUB_KEY_SIZE];
        memcpy(wrong, secret, sizeof(wrong));
        wrong[17] ^= 0xFF;                    // MAC keyed beyond CIPHER_KEY_SIZE
        emit_mtd(wrong, sealed, sealed_len);
      }
    }
  }
}

// ---- path returns ----------------------------------------------------

// Emits a path_return record: the payload as Mesh::createPathReturn
// builds it, and the fields as the Mesh::onRecvPacket receiver extracts
// them (including block padding in extra). The verdict is measured by
// actually running the receiver steps.
static void emit_path_return(const uint8_t* secret, const uint8_t* payload, int payload_len) {
  open_rec("path_return");
  field_hex("secret", secret, PUB_KEY_SIZE);
  field_hex("payload", payload, payload_len);

  uint8_t data[MAX_PACKET_PAYLOAD];
  bool ok = payload_len > 2 + CIPHER_MAC_SIZE;
  int len = 0;
  if (ok) {
    len = Utils::MACThenDecrypt(secret, data, payload + 2, payload_len - 2);
    ok = len > 0;
  }
  int k = 0;
  uint8_t path_len = 0;
  if (ok) {
    path_len = data[k++];
#if MESHCORE_MINOR >= 17
    ok = Packet::isValidPathLen(path_len);  // guard added in firmware 1.17
#endif
  }
  if (ok) {
    uint8_t hash_size = (path_len >> 6) + 1;
    uint8_t hash_count = path_len & 63;
    const uint8_t* path = &data[k]; k += hash_size * hash_count;
    ok = k + 1 <= len;
    if (ok) {
      uint8_t extra_type = data[k++] & 0x0F;
      printf(",\"valid\":true,\"path_len\":%u,\"extra_type\":%u", path_len, extra_type);
      field_hex("path", path, hash_size * hash_count);
      field_hex("extra", &data[k], len - k);
      close_rec();
      return;
    }
  }
  printf(",\"valid\":false");
  close_rec();
}

static void gen_path_returns(const std::vector<LocalIdentity>& ids) {
  struct Variant { uint8_t path_len; int extra_len; };
  static const Variant V[] = {
    {0, 10},                    // empty path, with extra
    {3, 0},                     // 3×1-byte hashes, filler branch
    {3, 25},
    {(uint8_t)((1 << 6) | 2), 7},  // 2×2-byte hashes
    {40, 0},                    // long path, filler
  };

  int n = 0;
  for (const Variant& v : V) {
    uint8_t secret[PUB_KEY_SIZE];
    ids[n % ids.size()].calcSharedSecret(secret, ids[(n + 1) % ids.size()].pub_key);
    n++;

    uint8_t hash_size = (v.path_len >> 6) + 1;
    uint8_t hash_count = v.path_len & 63;
    uint8_t path[MAX_PATH_SIZE];
    rnd_bytes(path, (size_t)hash_size * hash_count);

    // Mirror Mesh::createPathReturn.
    uint8_t data[MAX_PACKET_PAYLOAD];
    int data_len = 0;
    data[data_len++] = v.path_len;
    memcpy(&data[data_len], path, hash_size * hash_count); data_len += hash_size * hash_count;
    if (v.extra_len > 0) {
      data[data_len++] = (uint8_t)(0x01 + (n % 3));
      rnd_bytes(&data[data_len], (size_t)v.extra_len); data_len += v.extra_len;
    } else {
      data[data_len++] = 0xFF;
      rnd_bytes(&data[data_len], 4); data_len += 4;
    }

    uint8_t payload[MAX_PACKET_PAYLOAD];
    int len = 0;
    payload[len++] = rnd_byte();  // dest hash
    payload[len++] = rnd_byte();  // src hash
    len += Utils::encryptThenMAC(secret, &payload[len], data, data_len);

    emit_path_return(secret, payload, len);

    // Tampered MAC must fail.
    uint8_t bad[MAX_PACKET_PAYLOAD];
    memcpy(bad, payload, (size_t)len);
    bad[2] ^= 0x01;
    emit_path_return(secret, bad, len);
  }

  // A well-sealed PATH whose inner descriptor is the reserved hash
  // size. The receiver rejects it only from firmware 1.17, which added
  // the Packet::isValidPathLen guard (Mesh.cpp); earlier receivers read
  // straight through it. Emit this adversarial vector only for versions
  // that actually reject — otherwise the corpus would certify a verdict
  // the older firmware it names does not produce.
#if MESHCORE_MINOR >= 17
  {
    uint8_t secret[PUB_KEY_SIZE];
    rnd_bytes(secret, sizeof(secret));
    uint8_t data[8] = {0xC1, 1, 2, 3, 4, 5, 6, 7};
    uint8_t payload[MAX_PACKET_PAYLOAD];
    int len = 2;
    payload[0] = 0x0A; payload[1] = 0x0B;
    len += Utils::encryptThenMAC(secret, &payload[len], data, sizeof(data));
    emit_path_return(secret, payload, len);
  }
#endif
}

// ---- group channels --------------------------------------------------

// Emits channel records pinning the PSK semantics: hash over the PSK's
// real length (16 or 32), crypto keyed by the zero-padded 32-byte
// array — as BaseChatMesh::addChannel + Mesh::createGroupDatagram do.
static void gen_channels() {
  static const int PSKLEN[] = {16, 16, 32};
  int n = 0;
  for (int psk_len : PSKLEN) {
    uint8_t psk[32];
    rnd_bytes(psk, (size_t)psk_len);

    uint8_t secret[PUB_KEY_SIZE];
    memset(secret, 0, sizeof(secret));
    memcpy(secret, psk, psk_len);

    uint8_t hash[PATH_HASH_SIZE];
    Utils::sha256(hash, PATH_HASH_SIZE, psk, psk_len);

    uint8_t plain[40];
    int plain_len = 11 + n++;
    rnd_bytes(plain, (size_t)plain_len);

    uint8_t sealed[2 + 48];
    int sealed_len = Utils::encryptThenMAC(secret, sealed, plain, plain_len);

    // The receiver sees the block-padded plaintext.
    uint8_t padded[48];
    int padded_len = Utils::MACThenDecrypt(secret, padded, sealed, sealed_len);

    open_rec("channel");
    field_hex("psk", psk, psk_len);
    field_hex("hash", hash, PATH_HASH_SIZE);
    field_hex("in", sealed, sealed_len);
    field_hex("plain", padded, padded_len);
    close_rec();
  }
}

// ---- adverts ---------------------------------------------------------

// Mirrors the advert acceptance check in Mesh::onRecvPacket.
static bool ref_advert_verify(const uint8_t* payload, int len) {
  if (len < PUB_KEY_SIZE + 4 + SIGNATURE_SIZE) return false;
  Identity id;
  memcpy(id.pub_key, payload, PUB_KEY_SIZE);
  uint8_t message[PUB_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE];
  int msg_len = 0;
  memcpy(&message[msg_len], payload, PUB_KEY_SIZE + 4); msg_len += PUB_KEY_SIZE + 4;
  int app_len = len - (PUB_KEY_SIZE + 4 + SIGNATURE_SIZE);
  if (app_len > MAX_ADVERT_DATA_SIZE) app_len = MAX_ADVERT_DATA_SIZE;  // Mesh.cpp:269
  memcpy(&message[msg_len], payload + PUB_KEY_SIZE + 4 + SIGNATURE_SIZE, app_len);
  msg_len += app_len;
  return id.verify(payload + PUB_KEY_SIZE + 4, message, msg_len);
}

static void emit_advert_verify(const uint8_t* payload, int len) {
  open_rec("advert_verify");
  field_hex("payload", payload, len);
  printf(",\"valid\":%s", ref_advert_verify(payload, len) ? "true" : "false");
  close_rec();
}

// Emits the app_data blob plus the reference parser's own reading of
// it. canon=true marks builder-produced (canonically encoded) blobs.
static void emit_advert_appdata(const uint8_t* app_data, int len, bool canon) {
  uint8_t padded[MAX_ADVERT_DATA_SIZE + 8];
  memset(padded, 0, sizeof(padded));  // parser may read past len before rejecting
  memcpy(padded, app_data, len);
  AdvertDataParser parser(padded, (uint8_t)len);

  open_rec("advert_appdata");
  field_hex("appdata", app_data, len);
  printf(",\"canon\":%s,\"valid\":%s", canon ? "true" : "false",
         parser.isValid() ? "true" : "false");
  if (parser.isValid()) {
    printf(",\"adv_type\":%u,\"has_loc\":%s,\"lat\":%d,\"lon\":%d,\"feat1\":%u,\"feat2\":%u",
           parser.getType(), parser.hasLatLon() ? "true" : "false",
           parser.getIntLat(), parser.getIntLon(),
           parser.getFeat1(), parser.getFeat2());
    field_hex("name_hex", (const uint8_t*)parser.getName(), (int)strlen(parser.getName()));
  }
  close_rec();
}

static void gen_adverts(const std::vector<LocalIdentity>& ids) {
  std::vector<AdvertDataBuilder> builders;
  builders.push_back(AdvertDataBuilder(ADV_TYPE_NONE));
  builders.push_back(AdvertDataBuilder(ADV_TYPE_CHAT, "Alice"));
  builders.push_back(AdvertDataBuilder(ADV_TYPE_REPEATER, "FR78_Trouspinette\xF0\x9F\x8D\xBE", 48.858370, 2.294481));
  builders.push_back(AdvertDataBuilder(ADV_TYPE_ROOM, "\xF0\x9F\x8D\xBE\xF0\x9F\x8D\xBE\xF0\x9F\x8D\xBE\xF0\x9F\x8D\xBE\xF0\x9F\x8D\xBE\xF0\x9F\x8D\xBE\xF0\x9F\x8D\xBE", 48.0, 2.0));  // truncation lands mid-emoji
  builders.push_back(AdvertDataBuilder(ADV_TYPE_SENSOR, "abcdefghijklmnopqrstuvwxyz01234"));  // 31 bytes, no loc
  builders.push_back(AdvertDataBuilder(ADV_TYPE_CHAT, "\xFF" "abc"));  // invalid UTF-8 head
  builders.push_back(AdvertDataBuilder(ADV_TYPE_ROOM, "caf\xC3\xA9 \xF0\x9F\x87\xAB\xF0\x9F\x87\xB7", -33.868820, 151.209290));
  {
    AdvertDataBuilder b(ADV_TYPE_REPEATER, "feat");
    b.setFeat1(0x1234);
    b.setFeat2(0xFFFF);
    builders.push_back(b);
  }

  static const uint32_t TS[] = {0, 1, 0x7FFFFFFFu, 0xFFFFFFFFu, 1765000000u};

  int n = 0;
  for (AdvertDataBuilder& b : builders) {
    uint8_t app_data[MAX_ADVERT_DATA_SIZE];
    uint8_t app_len = b.encodeTo(app_data);
    emit_advert_appdata(app_data, app_len, BUILDER_APPDATA_IS_CANONICAL);

    // Build the advert payload exactly as Mesh::createAdvert does.
    const LocalIdentity& li = ids[n % ids.size()];
    uint32_t ts = TS[n % 5];
    n++;

    uint8_t payload[MAX_PACKET_PAYLOAD];
    int len = 0;
    memcpy(&payload[len], li.pub_key, PUB_KEY_SIZE); len += PUB_KEY_SIZE;
    memcpy(&payload[len], &ts, 4); len += 4;
    uint8_t* signature = &payload[len]; len += SIGNATURE_SIZE;
    memcpy(&payload[len], app_data, app_len); len += app_len;
    {
      uint8_t message[PUB_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE];
      int msg_len = 0;
      memcpy(&message[msg_len], li.pub_key, PUB_KEY_SIZE); msg_len += PUB_KEY_SIZE;
      memcpy(&message[msg_len], &ts, 4); msg_len += 4;
      memcpy(&message[msg_len], app_data, app_len); msg_len += app_len;
      li.sign(signature, message, msg_len);
    }

    emit_advert_verify(payload, len);

    uint8_t bad[MAX_PACKET_PAYLOAD];
    static const int TAMPER[] = {0, PUB_KEY_SIZE + 1, PUB_KEY_SIZE + 4};
    for (int off : TAMPER) {  // pub_key, timestamp, signature
      memcpy(bad, payload, (size_t)len);
      bad[off] ^= 0x01;
      emit_advert_verify(bad, len);
    }
    if (app_len > 0) {  // app data
      memcpy(bad, payload, (size_t)len);
      bad[len - 1] ^= 0x01;
      emit_advert_verify(bad, len);
    }
    emit_advert_verify(payload, len - 1);              // truncated tail
    emit_advert_verify(payload, PUB_KEY_SIZE + 4 + SIGNATURE_SIZE - 1);  // below fixed size
  }

  // Oversized advert: 32 signed bytes, then padding no signer covered.
  // Mesh::onRecvPacket clamps to MAX_ADVERT_DATA_SIZE before verifying,
  // so the exact and the padded forms must BOTH verify true — a relay
  // appending bytes to a valid advert must not flip the verdict.
  {
    const LocalIdentity& li = ids[0];
    uint32_t ts = 1765000000u;
    uint8_t app_data[MAX_ADVERT_DATA_SIZE];
    app_data[0] = ADV_TYPE_CHAT | ADV_NAME_MASK;
    rnd_bytes(&app_data[1], MAX_ADVERT_DATA_SIZE - 1);

    uint8_t payload[MAX_PACKET_PAYLOAD];
    int len = 0;
    memcpy(&payload[len], li.pub_key, PUB_KEY_SIZE); len += PUB_KEY_SIZE;
    memcpy(&payload[len], &ts, 4); len += 4;
    uint8_t* signature = &payload[len]; len += SIGNATURE_SIZE;
    memcpy(&payload[len], app_data, MAX_ADVERT_DATA_SIZE); len += MAX_ADVERT_DATA_SIZE;
    {
      uint8_t message[PUB_KEY_SIZE + 4 + MAX_ADVERT_DATA_SIZE];
      int msg_len = 0;
      memcpy(&message[msg_len], li.pub_key, PUB_KEY_SIZE); msg_len += PUB_KEY_SIZE;
      memcpy(&message[msg_len], &ts, 4); msg_len += 4;
      memcpy(&message[msg_len], app_data, MAX_ADVERT_DATA_SIZE); msg_len += MAX_ADVERT_DATA_SIZE;
      li.sign(signature, message, msg_len);
    }
    emit_advert_verify(payload, len);     // exactly 32 bytes: valid

    rnd_bytes(&payload[len], 8);           // append 8 bytes of padding
    emit_advert_verify(payload, len + 8);  // clamped away: still valid
  }

  // Crafted app_data blobs straight to the parser (non-canonical).
  {
    uint8_t d[MAX_ADVERT_DATA_SIZE];
    d[0] = ADV_TYPE_CHAT | ADV_LATLON_MASK;            // loc flag, truncated loc
    d[1] = 0xAA; d[2] = 0xBB;
    emit_advert_appdata(d, 3, false);
    d[0] = ADV_TYPE_CHAT | ADV_NAME_MASK;              // name flag, no name bytes
    emit_advert_appdata(d, 1, false);
    d[0] = ADV_TYPE_SENSOR | ADV_FEAT1_MASK | ADV_FEAT2_MASK;  // features, cut inside feat2
    d[1] = 0x34; d[2] = 0x12; d[3] = 0xFF;
    emit_advert_appdata(d, 4, false);
    d[0] = ADV_TYPE_NONE;                              // flags byte alone
    emit_advert_appdata(d, 1, false);
    d[0] = ADV_TYPE_CHAT | ADV_NAME_MASK;              // name with an embedded NUL:
    d[1] = 'a'; d[2] = 'b'; d[3] = 0x00; d[4] = 'c';   // the C-string parser stops at the NUL
    d[5] = 'd';
    emit_advert_appdata(d, 6, false);
  }
}

// ----------------------------------------------------------------------

int main(int argc, char** argv) {
  unsigned seed = 42;
  if (argc > 1) seed = (unsigned)strtoul(argv[1], nullptr, 10);
  g_rng.seed(seed);

  DetRNG det;
  std::vector<LocalIdentity> ids;
  for (int i = 0; i < 4; i++) ids.push_back(LocalIdentity(&det));

  gen_packets_structural();
  gen_packets_negative();
  gen_packets_fuzz(400);
  gen_crypto(ids);
  gen_adverts(ids);
  gen_path_returns(ids);
  gen_channels();
  return 0;
}
