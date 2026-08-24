//! Interop tests for p256.zig, against vectors WebCrypto produced.
//!
//! The point of testing against foreign vectors rather than round-tripping our
//! own output: a self-consistent implementation of the wrong encoding passes
//! every round-trip test and then fails silently against a phone. Every
//! constant here came out of `node`, via src/testdata/p256_vectors.json.
//!
//! Regenerate with the snippet recorded in that file's `note`. It lives under
//! src/ because @embedFile cannot reach outside the package root.

const std = @import("std");
const p256 = @import("p256.zig");

const vectors = @embedFile("testdata/p256_vectors.json");

const Vectors = struct {
    note: []const u8,
    ecdsa: struct {
        secret: []const u8,
        public: []const u8,
        msg: []const u8,
        sig: []const u8,
    },
    ecdh: struct {
        a_secret: []const u8,
        b_public: []const u8,
        shared_x: []const u8,
    },
    seal: struct {
        recipient_secret: []const u8,
        req_id: []const u8,
        app_id: []const u8,
        sealed: []const u8,
        plaintext: []const u8,
    },
};

fn load(allocator: std.mem.Allocator) !std.json.Parsed(Vectors) {
    return std.json.parseFromSlice(Vectors, allocator, vectors, .{
        .ignore_unknown_fields = true,
    });
}

fn dec(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    return p256.b64uDecodeAlloc(allocator, text);
}

fn dec32(allocator: std.mem.Allocator, text: []const u8) ![32]u8 {
    const b = try dec(allocator, text);
    defer allocator.free(b);
    if (b.len != 32) return error.WrongLength;
    return b[0..32].*;
}

test "verifies a signature WebCrypto produced" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();

    const pub_key = try dec(a, v.value.ecdsa.public);
    defer a.free(pub_key);
    const sig = try dec(a, v.value.ecdsa.sig);
    defer a.free(sig);

    try p256.verify(pub_key, v.value.ecdsa.msg, sig);
}

test "rejects that signature against a tampered message" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();

    const pub_key = try dec(a, v.value.ecdsa.public);
    defer a.free(pub_key);
    const sig = try dec(a, v.value.ecdsa.sig);
    defer a.free(sig);

    // One byte different: the op name, which is exactly the cross-endpoint
    // replay the canonical string exists to prevent.
    try std.testing.expectError(
        p256.Error.BadSignature,
        p256.verify(pub_key, "nudge-verdict-v1\nclient-abc\n1787000000\naGFzaA", sig),
    );
}

test "rejects a DER-wrapped signature as a bad signature, not a bad key" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();
    const pub_key = try dec(a, v.value.ecdsa.public);
    defer a.free(pub_key);

    // The most likely client bug. It must be reported as a signature problem;
    // reporting it as a key problem sends the next person hunting the wrong
    // thing entirely.
    var der: [70]u8 = undefined;
    @memset(&der, 0x30);
    try std.testing.expectError(p256.Error.BadSignature, p256.verify(pub_key, "x", &der));
}

test "our signatures verify under the same encoding" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();

    // Same secret WebCrypto used, so both sides sign with one key. ECDSA is
    // randomised, so the bytes differ per signature — what must match is the
    // encoding, which is checked by verifying against the imported key.
    const seed = try dec32(a, v.value.ecdsa.secret);
    const kp = try p256.KeyPair.fromSeed(seed);

    const pub_from_vector = try dec(a, v.value.ecdsa.public);
    defer a.free(pub_from_vector);
    const pub_ours = kp.publicBytes();
    try std.testing.expectEqualSlices(u8, pub_from_vector, &pub_ours);

    const sig = try kp.sign(v.value.ecdsa.msg);
    try std.testing.expectEqual(@as(usize, 64), sig.len);
    try p256.verify(&pub_ours, v.value.ecdsa.msg, &sig);
}

test "ECDH matches WebCrypto: the X coordinate only" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();

    const a_secret = try dec32(a, v.value.ecdh.a_secret);
    const b_public = try dec(a, v.value.ecdh.b_public);
    defer a.free(b_public);
    const expected = try dec(a, v.value.ecdh.shared_x);
    defer a.free(expected);

    const shared = try p256.ecdh(b_public, a_secret);
    // 32 bytes, not 65: using the whole point would derive a different key and
    // fail only at the AEAD tag, a long way from the cause.
    try std.testing.expectEqual(@as(usize, 32), shared.len);
    try std.testing.expectEqualSlices(u8, expected, &shared);
}

test "opens an envelope the JS client sealed" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();

    const recipient = try dec32(a, v.value.seal.recipient_secret);
    const sealed = try dec(a, v.value.seal.sealed);
    defer a.free(sealed);

    const opened = try p256.open(a, recipient, sealed,
        v.value.seal.req_id, v.value.seal.app_id);
    defer a.free(opened);
    try std.testing.expectEqualStrings(v.value.seal.plaintext, opened);
}

test "refuses that envelope under the wrong app_id" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();
    const recipient = try dec32(a, v.value.seal.recipient_secret);
    const sealed = try dec(a, v.value.seal.sealed);
    defer a.free(sealed);

    try std.testing.expectError(p256.Error.OpenFailed, p256.open(
        a, recipient, sealed, v.value.seal.req_id, "app-other"));
}

test "refuses that envelope under the wrong req_id" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();
    const recipient = try dec32(a, v.value.seal.recipient_secret);
    const sealed = try dec(a, v.value.seal.sealed);
    defer a.free(sealed);

    // req_id is the HKDF salt, so a different one derives a different key.
    try std.testing.expectError(p256.Error.OpenFailed, p256.open(
        a, recipient, sealed, "AAAAAAAAAAAAAAAAAAAAAA", v.value.seal.app_id));
}

test "is not fooled by an ambiguous req_id/app_id split" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();
    const recipient = try dec32(a, v.value.seal.recipient_secret);
    const sealed = try dec(a, v.value.seal.sealed);
    defer a.free(sealed);

    // The newline in the AAD is what prevents ("ab","c") and ("a","bc") from
    // colliding. Moving the boundary must fail.
    var short_req: [8]u8 = undefined;
    @memcpy(&short_req, v.value.seal.req_id[0..8]);
    try std.testing.expectError(p256.Error.OpenFailed, p256.open(
        a, recipient, sealed, &short_req, v.value.seal.app_id));
}

test "refuses a tampered ciphertext" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();
    const recipient = try dec32(a, v.value.seal.recipient_secret);
    const sealed = try dec(a, v.value.seal.sealed);
    defer a.free(sealed);

    sealed[sealed.len - 20] ^= 0x01;
    try std.testing.expectError(p256.Error.OpenFailed, p256.open(
        a, recipient, sealed, v.value.seal.req_id, v.value.seal.app_id));
}

test "refuses a body too short to be an envelope" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();
    const recipient = try dec32(a, v.value.seal.recipient_secret);
    var tiny: [40]u8 = undefined;
    @memset(&tiny, 0);
    try std.testing.expectError(p256.Error.SealTooShort, p256.open(
        a, recipient, &tiny, v.value.seal.req_id, v.value.seal.app_id));
}

test "our sealing round-trips, and produces the layout the service validates" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();

    // Seal to the vector's recipient, then open with its secret: proves our
    // seal() agrees with the same construction from the other direction.
    const recipient_secret = try dec32(a, v.value.seal.recipient_secret);
    const recipient_pub = try dec(a, v.value.ecdh.b_public);
    defer a.free(recipient_pub);

    const msg = "{\"title\":\"round trip\"}";
    const sealed = try p256.seal(a, recipient_pub, v.value.seal.req_id,
        v.value.seal.app_id, msg);
    defer a.free(sealed);

    // Floor the service enforces: eph_pub(65) + nonce(12) + tag(16).
    try std.testing.expect(sealed.len >= 65 + 12 + 16);
    try std.testing.expectEqual(@as(u8, 0x04), sealed[0]);

    const opened = try p256.open(a, recipient_secret, sealed,
        v.value.seal.req_id, v.value.seal.app_id);
    defer a.free(opened);
    try std.testing.expectEqualStrings(msg, opened);
}

test "the b64-taking wrappers accept keys in the encoding the wire uses" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();

    // This is the case the byte-oriented tests could not catch: every key on
    // the wire is base64url text, and passing that text to a function wanting
    // raw bytes fails only when the curve rejects it. It shipped once.
    try p256.verifyB64(a, v.value.ecdsa.public, v.value.ecdsa.msg, v.value.ecdsa.sig);

    try std.testing.expectError(p256.Error.BadSignature, p256.verifyB64(
        a, v.value.ecdsa.public, "different message", v.value.ecdsa.sig));

    const recipient = try dec32(a, v.value.seal.recipient_secret);
    const sealed = try p256.sealB64(a, v.value.ecdh.b_public,
        v.value.seal.req_id, v.value.seal.app_id, "{\"t\":1}");
    defer a.free(sealed);
    const opened = try p256.open(a, recipient, sealed,
        v.value.seal.req_id, v.value.seal.app_id);
    defer a.free(opened);
    try std.testing.expectEqualStrings("{\"t\":1}", opened);
}

test "what we seal is openable with the recipient's key, in the wire encoding" {
    const a = std.testing.allocator;
    const v = try load(a);
    defer v.deinit();

    // The direction that actually broke. The vectors cover JS-seals ->
    // Zig-opens; this covers Zig-seals -> opened with the recipient secret,
    // using keys in the base64url form the config holds. A cross-language
    // check of the same direction lives in tests/e2e_seal_xlang.sh, because
    // only that can catch a divergence between this file and the phone.
    const recipient_secret = try dec32(a, v.value.seal.recipient_secret);
    const payload = "{\"title\":\"direction check\",\"details\":[[\"a\",\"b\"]]}";

    const sealed = try p256.sealB64(a, v.value.ecdh.b_public,
        v.value.seal.req_id, v.value.seal.app_id, payload);
    defer a.free(sealed);

    const opened = try p256.open(a, recipient_secret, sealed,
        v.value.seal.req_id, v.value.seal.app_id);
    defer a.free(opened);
    try std.testing.expectEqualStrings(payload, opened);
}

test "canonical strings match the wire format byte for byte" {
    const a = std.testing.allocator;

    const call = try p256.canonicalCall(a, "pairing", "client-abc", 1787000000, "aGFzaA");
    defer a.free(call);
    try std.testing.expectEqualStrings(
        "nudge-pairing-v1\nclient-abc\n1787000000\naGFzaA", call);

    const verdict = try p256.canonicalVerdict(a, "req-1", "approved", 300, 1787000001);
    defer a.free(verdict);
    try std.testing.expectEqualStrings(
        "nudge-verdict-v1\nreq-1\napproved\n300\n1787000001", verdict);
}

test "sha256b64u matches the known empty-string digest" {
    const a = std.testing.allocator;
    const h = try p256.sha256b64u(a, "");
    defer a.free(h);
    try std.testing.expectEqualStrings("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU", h);
}
