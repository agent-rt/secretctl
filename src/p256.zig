//! P-256 primitives for the out-of-band approval client.
//!
//! Every byte layout here has to match WebCrypto exactly, because the other
//! side of the wire is a phone and a Worker (see `docs/2fa-push-approval.md`
//! §5, and `nudge`'s pwa/nudge-core.js). The choices that are easy to get
//! wrong, and the reason each is what it is:
//!
//!   * signatures are raw r‖s big-endian, 64 bytes — never DER. WebCrypto
//!     produces and expects exactly this, and a DER signature would be
//!     rejected as a wrong key rather than a wrong encoding.
//!   * public keys are uncompressed SEC1, 0x04‖X‖Y, 65 bytes — the format
//!     `crypto.subtle.exportKey("raw", …)` emits.
//!   * an ECDH shared secret is the **X coordinate only**, 32 bytes. That is
//!     what WebCrypto's deriveBits(…, 256) returns; using the whole point
//!     would derive a different key and fail only at the AEAD tag, far from
//!     the cause. Measured against Node before writing this.
//!
//! Interop is not assumed: p256_test.zig checks against vectors produced by
//! WebCrypto rather than against this file's own output.

const std = @import("std");
const rand = @import("rand.zig");

pub const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
pub const Curve = std.crypto.ecc.P256;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
pub const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const pub_len = 65; // 0x04 ‖ X ‖ Y
pub const sig_len = 64; // r ‖ s
pub const shared_len = 32; // X only
pub const key_len = Aead.key_length; // 32
pub const nonce_len = Aead.nonce_length; // 12
pub const tag_len = Aead.tag_length; // 16

pub const Error = error{
    BadPublicKey,
    BadSignature,
    BadPrivateKey,
    SealTooShort,
    OpenFailed,
    IdentityElement,
};

// ---------- base64url ----------

/// base64url without padding, which is what every JSON field on this wire
/// uses. std's url_safe alphabet plus no-pad matches it exactly.
pub const b64u = std.base64.url_safe_no_pad;

pub fn b64uEncodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, b64u.Encoder.calcSize(bytes.len));
    _ = b64u.Encoder.encode(out, bytes);
    return out;
}

pub fn b64uDecodeAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const n = try b64u.Decoder.calcSizeForSlice(text);
    const out = try allocator.alloc(u8, n);
    errdefer allocator.free(out);
    try b64u.Decoder.decode(out, text);
    return out;
}

// ---------- signing ----------

pub const KeyPair = struct {
    inner: Ecdsa.KeyPair,

    /// Generated from `rand.zig` (arc4random_buf) rather than
    /// Ecdsa.KeyPair.generate, which in Zig 0.16 takes a std.Io this project
    /// has no other use for. Retries on the vanishingly rare out-of-range
    /// scalar rather than propagating an error nothing could act on.
    pub fn generate() KeyPair {
        var seed: [32]u8 = undefined;
        while (true) {
            rand.bytes(&seed);
            if (fromSeed(seed)) |kp| return kp else |_| continue;
        }
    }

    pub fn fromSeed(seed: [32]u8) !KeyPair {
        const sk = Ecdsa.SecretKey.fromBytes(seed) catch return Error.BadPrivateKey;
        return .{ .inner = Ecdsa.KeyPair.fromSecretKey(sk) catch return Error.BadPrivateKey };
    }

    pub fn secretBytes(self: KeyPair) [32]u8 {
        return self.inner.secret_key.toBytes();
    }

    pub fn publicBytes(self: KeyPair) [pub_len]u8 {
        return self.inner.public_key.toUncompressedSec1();
    }

    /// Sign a canonical string. Returns raw r‖s, never DER.
    pub fn sign(self: KeyPair, msg: []const u8) ![sig_len]u8 {
        const sig = try self.inner.sign(msg, null);
        return sig.toBytes();
    }
};

/// Verify a raw r‖s signature against an uncompressed SEC1 public key.
///
/// Length is checked before anything else so a DER-encoded signature — the
/// most likely client bug — is reported as a bad signature rather than
/// surfacing as a mysterious verification failure.
pub fn verify(pubkey: []const u8, msg: []const u8, sig: []const u8) Error!void {
    if (sig.len != sig_len) return Error.BadSignature;
    const pk = Ecdsa.PublicKey.fromSec1(pubkey) catch return Error.BadPublicKey;
    const s = Ecdsa.Signature.fromBytes(sig[0..sig_len].*);
    s.verify(msg, pk) catch return Error.BadSignature;
}

// ---------- base64url-taking wrappers ----------
//
// The raw-byte functions below are the primitives; these exist because every
// key on this wire arrives as base64url text, and passing that text straight
// into a function expecting bytes is silent until the curve rejects it. Naming
// the encoding at the call site is what stops that recurring — it already
// happened once, and the interop tests could not catch it because they were
// written against decoded bytes while the caller had encoded text.

/// Verify with a base64url-encoded public key and signature.
pub fn verifyB64(
    allocator: std.mem.Allocator,
    pubkey_b64: []const u8,
    msg: []const u8,
    sig_b64: []const u8,
) !void {
    const pk = b64uDecodeAlloc(allocator, pubkey_b64) catch return Error.BadPublicKey;
    defer allocator.free(pk);
    const sig = b64uDecodeAlloc(allocator, sig_b64) catch return Error.BadSignature;
    defer allocator.free(sig);
    return verify(pk, msg, sig);
}

/// Seal to a base64url-encoded recipient key. Caller owns the result.
pub fn sealB64(
    allocator: std.mem.Allocator,
    device_seal_pub_b64: []const u8,
    req_id: []const u8,
    app_id: []const u8,
    plaintext: []const u8,
) ![]u8 {
    const pk = b64uDecodeAlloc(allocator, device_seal_pub_b64) catch return Error.BadPublicKey;
    defer allocator.free(pk);
    return seal(allocator, pk, req_id, app_id, plaintext);
}

// ---------- ECDH ----------

/// X coordinate of the shared point, matching WebCrypto deriveBits(…, 256).
pub fn ecdh(their_pub: []const u8, our_secret: [32]u8) Error![shared_len]u8 {
    const point = Curve.fromSec1(their_pub) catch return Error.BadPublicKey;
    const shared = point.mul(our_secret, .big) catch return Error.IdentityElement;
    return shared.affineCoordinates().x.toBytes(.big);
}

// ---------- sealing ----------

/// Derive the AEAD key for a sealed envelope.
///
///   key = HKDF-SHA256(salt = raw req_id bytes, ikm = ECDH shared X,
///                     info = "nudge-seal-v1")
fn sealKey(shared: [shared_len]u8, req_id_raw: []const u8) [key_len]u8 {
    const prk = Hkdf.extract(req_id_raw, &shared);
    var out: [key_len]u8 = undefined;
    Hkdf.expand(&out, "nudge-seal-v1", prk);
    return out;
}

/// Associated data: `req_id "\n" app_id`.
///
/// The separator is load-bearing. Plain concatenation would make
/// ("ab","c") and ("a","bc") the same associated data, which is the exact
/// ambiguity AAD exists to remove.
fn writeAad(buf: []u8, req_id: []const u8, app_id: []const u8) ![]const u8 {
    return std.fmt.bufPrint(buf, "{s}\n{s}", .{ req_id, app_id });
}

/// Seal an envelope to a device's ECDH public key.
///
/// Layout: eph_pub(65) ‖ nonce(12) ‖ ciphertext ‖ tag(16). Caller owns the
/// result.
pub fn seal(
    allocator: std.mem.Allocator,
    device_seal_pub: []const u8,
    req_id: []const u8,
    app_id: []const u8,
    plaintext: []const u8,
) ![]u8 {
    // A fresh ephemeral key per request: reusing one would make two envelopes
    // to the same device share a key, and the nonce is the only other input.
    const eph = KeyPair.generate();
    const eph_secret = eph.secretBytes();
    const shared = try ecdh(device_seal_pub, eph_secret);

    var req_id_raw_buf: [64]u8 = undefined;
    const req_id_raw_len = try b64u.Decoder.calcSizeForSlice(req_id);
    if (req_id_raw_len > req_id_raw_buf.len) return Error.BadSignature;
    try b64u.Decoder.decode(req_id_raw_buf[0..req_id_raw_len], req_id);
    const key = sealKey(shared, req_id_raw_buf[0..req_id_raw_len]);

    var aad_buf: [512]u8 = undefined;
    const aad = try writeAad(&aad_buf, req_id, app_id);

    var nonce: [nonce_len]u8 = undefined;
    rand.bytes(&nonce);

    const out = try allocator.alloc(u8, pub_len + nonce_len + plaintext.len + tag_len);
    errdefer allocator.free(out);
    @memcpy(out[0..pub_len], &eph.publicBytes());
    @memcpy(out[pub_len..][0..nonce_len], &nonce);

    const ct = out[pub_len + nonce_len ..][0..plaintext.len];
    var tag: [tag_len]u8 = undefined;
    Aead.encrypt(ct, &tag, plaintext, aad, nonce, key);
    @memcpy(out[pub_len + nonce_len + plaintext.len ..][0..tag_len], &tag);
    return out;
}

/// Open a sealed envelope with our ECDH secret. Caller owns the result.
///
/// Present so the client can verify its own sealing round-trips; the device is
/// normally the only party that opens these.
pub fn open(
    allocator: std.mem.Allocator,
    our_secret: [32]u8,
    sealed: []const u8,
    req_id: []const u8,
    app_id: []const u8,
) ![]u8 {
    if (sealed.len < pub_len + nonce_len + tag_len) return Error.SealTooShort;
    const eph_pub = sealed[0..pub_len];
    const nonce: [nonce_len]u8 = sealed[pub_len..][0..nonce_len].*;
    const ct_len = sealed.len - pub_len - nonce_len - tag_len;
    const ct = sealed[pub_len + nonce_len ..][0..ct_len];
    const tag: [tag_len]u8 = sealed[pub_len + nonce_len + ct_len ..][0..tag_len].*;

    const shared = try ecdh(eph_pub, our_secret);

    var req_id_raw_buf: [64]u8 = undefined;
    const req_id_raw_len = try b64u.Decoder.calcSizeForSlice(req_id);
    if (req_id_raw_len > req_id_raw_buf.len) return Error.BadSignature;
    try b64u.Decoder.decode(req_id_raw_buf[0..req_id_raw_len], req_id);
    const key = sealKey(shared, req_id_raw_buf[0..req_id_raw_len]);

    var aad_buf: [512]u8 = undefined;
    const aad = try writeAad(&aad_buf, req_id, app_id);

    const out = try allocator.alloc(u8, ct_len);
    errdefer allocator.free(out);
    Aead.decrypt(out, ct, tag, aad, nonce, key) catch return Error.OpenFailed;
    return out;
}

// ---------- canonical strings ----------

/// What a client signs for every authenticated call.
///
/// `op` is included so a signature captured for one endpoint cannot be
/// replayed against another. Caller owns the result.
pub fn canonicalCall(
    allocator: std.mem.Allocator,
    op: []const u8,
    caller_id: []const u8,
    ts: i64,
    body_hash_b64u: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator, "nudge-{s}-v1\n{s}\n{d}\n{s}", .{
        op, caller_id, ts, body_hash_b64u,
    });
}

/// What a device signs, and what this client verifies. Deliberately
/// independent of HTTP framing: the client checks this string, not the
/// response shape, so a relay cannot change what a signature covers by
/// reshaping its own JSON. Caller owns the result.
pub fn canonicalVerdict(
    allocator: std.mem.Allocator,
    req_id: []const u8,
    verdict: []const u8,
    grace_s: u32,
    ts: i64,
) ![]u8 {
    return std.fmt.allocPrint(allocator, "nudge-verdict-v1\n{s}\n{s}\n{d}\n{d}", .{
        req_id, verdict, grace_s, ts,
    });
}

pub fn sha256b64u(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &h, .{});
    return b64uEncodeAlloc(allocator, &h);
}
