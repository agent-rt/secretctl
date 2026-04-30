//! Per-secret AEAD envelope. Two-layer encryption:
//!   inner: AES-256-GCM(DEK, value_nonce, AAD, plaintext)
//!   outer: AES-256-GCM(master_key, dek_nonce, AAD, DEK)
//! AAD = "secretctl/secret v1" || master_key_id || secret_id || mk_version
//! See TECH-DESIGN §5.

const std = @import("std");
const aes = @import("aes_gcm.zig");
const mem_util = @import("mem.zig");
const rand = @import("rand.zig");

pub const magic = "ENV1";
pub const version: u16 = 1;
pub const alg_id: u16 = 1;

pub const max_value_len: usize = 1 * 1024 * 1024; // 1 MiB

pub const Envelope = struct {
    mk_version: u32,
    dek_nonce: aes.Nonce,
    wrapped_dek_ct: [aes.key_len]u8,
    wrapped_dek_tag: aes.Tag,
    value_nonce: aes.Nonce,
    /// Owned heap allocation. Caller must free via `deinit`.
    value_ct: []u8,
    value_tag: aes.Tag,

    pub fn deinit(self: *Envelope, allocator: std.mem.Allocator) void {
        allocator.free(self.value_ct);
        self.value_ct = &.{};
    }
};

pub const Error = error{
    OutOfMemory,
    ValueTooLong,
    BadMagic,
    UnsupportedVersion,
    UnsupportedAlg,
    Truncated,
    AuthenticationFailed,
};

fn buildAad(
    allocator: std.mem.Allocator,
    master_key_id: *const [16]u8,
    secret_id: *const [16]u8,
    mk_version: u32,
) ![]u8 {
    const prefix = "secretctl/secret v1";
    var buf = try allocator.alloc(u8, prefix.len + 16 + 16 + 4);
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..16], master_key_id);
    @memcpy(buf[prefix.len + 16 ..][0..16], secret_id);
    std.mem.writeInt(u32, buf[prefix.len + 32 ..][0..4], mk_version, .little);
    return buf;
}

pub fn encrypt(
    allocator: std.mem.Allocator,
    master_key: *const [aes.key_len]u8,
    master_key_id: *const [16]u8,
    secret_id: *const [16]u8,
    mk_version: u32,
    plaintext: []const u8,
) Error!Envelope {
    if (plaintext.len > max_value_len) return Error.ValueTooLong;

    const aad = buildAad(allocator, master_key_id, secret_id, mk_version) catch return Error.OutOfMemory;
    defer allocator.free(aad);

    var dek: aes.Key = undefined;
    rand.bytes(&dek);
    defer mem_util.secureZero(u8, &dek);

    var dek_nonce: aes.Nonce = undefined;
    rand.bytes(&dek_nonce);
    var value_nonce: aes.Nonce = undefined;
    rand.bytes(&value_nonce);

    var wrapped_dek_ct: [aes.key_len]u8 = undefined;
    var wrapped_dek_tag: aes.Tag = undefined;
    aes.encrypt(master_key, &dek_nonce, aad, &dek, &wrapped_dek_ct, &wrapped_dek_tag);

    const value_ct = allocator.alloc(u8, plaintext.len) catch return Error.OutOfMemory;
    var value_tag: aes.Tag = undefined;
    aes.encrypt(&dek, &value_nonce, aad, plaintext, value_ct, &value_tag);

    return .{
        .mk_version = mk_version,
        .dek_nonce = dek_nonce,
        .wrapped_dek_ct = wrapped_dek_ct,
        .wrapped_dek_tag = wrapped_dek_tag,
        .value_nonce = value_nonce,
        .value_ct = value_ct,
        .value_tag = value_tag,
    };
}

/// Decrypt envelope. Returns a Plaintext that must be deinit'd by the caller.
pub fn decrypt(
    allocator: std.mem.Allocator,
    master_key: *const [aes.key_len]u8,
    master_key_id: *const [16]u8,
    secret_id: *const [16]u8,
    env: *const Envelope,
) Error!mem_util.Plaintext {
    const aad = buildAad(allocator, master_key_id, secret_id, env.mk_version) catch return Error.OutOfMemory;
    defer allocator.free(aad);

    var dek: aes.Key = undefined;
    aes.decrypt(master_key, &env.dek_nonce, aad, &env.wrapped_dek_ct, &env.wrapped_dek_tag, &dek) catch return Error.AuthenticationFailed;
    defer mem_util.secureZero(u8, &dek);

    var pt = mem_util.Plaintext.initLen(allocator, env.value_ct.len) catch return Error.OutOfMemory;
    aes.decrypt(&dek, &env.value_nonce, aad, env.value_ct, &env.value_tag, pt.bytes) catch {
        pt.deinit();
        return Error.AuthenticationFailed;
    };
    return pt;
}

/// Serialize envelope to a freshly allocated buffer.
pub fn serialize(allocator: std.mem.Allocator, env: *const Envelope) ![]u8 {
    const total = magic.len + 2 + 2 + 4 + 12 + 2 + aes.key_len + 16 + 12 + 4 + env.value_ct.len + 16;
    var buf = try allocator.alloc(u8, total);
    var w: usize = 0;
    @memcpy(buf[w .. w + magic.len], magic);
    w += magic.len;
    std.mem.writeInt(u16, buf[w..][0..2], version, .little);
    w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], alg_id, .little);
    w += 2;
    std.mem.writeInt(u32, buf[w..][0..4], env.mk_version, .little);
    w += 4;
    @memcpy(buf[w .. w + 12], &env.dek_nonce);
    w += 12;
    std.mem.writeInt(u16, buf[w..][0..2], aes.key_len, .little);
    w += 2;
    @memcpy(buf[w .. w + aes.key_len], &env.wrapped_dek_ct);
    w += aes.key_len;
    @memcpy(buf[w .. w + 16], &env.wrapped_dek_tag);
    w += 16;
    @memcpy(buf[w .. w + 12], &env.value_nonce);
    w += 12;
    std.mem.writeInt(u32, buf[w..][0..4], @intCast(env.value_ct.len), .little);
    w += 4;
    @memcpy(buf[w .. w + env.value_ct.len], env.value_ct);
    w += env.value_ct.len;
    @memcpy(buf[w .. w + 16], &env.value_tag);
    w += 16;
    std.debug.assert(w == total);
    return buf;
}

pub fn parse(allocator: std.mem.Allocator, blob: []const u8) Error!Envelope {
    const min_len = magic.len + 2 + 2 + 4 + 12 + 2 + aes.key_len + 16 + 12 + 4 + 16;
    if (blob.len < min_len) return Error.Truncated;
    var r: usize = 0;
    if (!std.mem.eql(u8, blob[0..magic.len], magic)) return Error.BadMagic;
    r += magic.len;
    const ver = std.mem.readInt(u16, blob[r..][0..2], .little);
    r += 2;
    if (ver != version) return Error.UnsupportedVersion;
    const alg = std.mem.readInt(u16, blob[r..][0..2], .little);
    r += 2;
    if (alg != alg_id) return Error.UnsupportedAlg;
    const mk_ver = std.mem.readInt(u32, blob[r..][0..4], .little);
    r += 4;
    var dek_nonce: aes.Nonce = undefined;
    @memcpy(&dek_nonce, blob[r .. r + 12]);
    r += 12;
    const wrapped_len = std.mem.readInt(u16, blob[r..][0..2], .little);
    r += 2;
    if (wrapped_len != aes.key_len) return Error.Truncated;
    var wrapped_ct: [aes.key_len]u8 = undefined;
    @memcpy(&wrapped_ct, blob[r .. r + aes.key_len]);
    r += aes.key_len;
    var wrapped_tag: aes.Tag = undefined;
    @memcpy(&wrapped_tag, blob[r .. r + 16]);
    r += 16;
    var value_nonce: aes.Nonce = undefined;
    @memcpy(&value_nonce, blob[r .. r + 12]);
    r += 12;
    const value_ct_len = std.mem.readInt(u32, blob[r..][0..4], .little);
    r += 4;
    if (value_ct_len > max_value_len) return Error.ValueTooLong;
    if (blob.len < r + value_ct_len + 16) return Error.Truncated;
    const value_ct = allocator.alloc(u8, value_ct_len) catch return Error.OutOfMemory;
    @memcpy(value_ct, blob[r .. r + value_ct_len]);
    r += value_ct_len;
    var value_tag: aes.Tag = undefined;
    @memcpy(&value_tag, blob[r .. r + 16]);
    r += 16;

    return .{
        .mk_version = mk_ver,
        .dek_nonce = dek_nonce,
        .wrapped_dek_ct = wrapped_ct,
        .wrapped_dek_tag = wrapped_tag,
        .value_nonce = value_nonce,
        .value_ct = value_ct,
        .value_tag = value_tag,
    };
}

const testing = std.testing;

test "encrypt -> decrypt round-trip" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);
    var sid: [16]u8 = undefined;
    rand.bytes(&sid);

    var env = try encrypt(a, &mk, &mk_id, &sid, 1, "the quick brown fox");
    defer env.deinit(a);
    var pt = try decrypt(a, &mk, &mk_id, &sid, &env);
    defer pt.deinit();
    try testing.expectEqualSlices(u8, "the quick brown fox", pt.bytes);
}

test "row-shuffle (different secret_id) is rejected" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);
    var sid_a: [16]u8 = undefined;
    var sid_b: [16]u8 = undefined;
    rand.bytes(&sid_a);
    rand.bytes(&sid_b);

    var env = try encrypt(a, &mk, &mk_id, &sid_a, 1, "payload");
    defer env.deinit(a);
    try testing.expectError(Error.AuthenticationFailed, decrypt(a, &mk, &mk_id, &sid_b, &env));
}

test "cross-vault (different mk_id) is rejected" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id_a: [16]u8 = undefined;
    var mk_id_b: [16]u8 = undefined;
    rand.bytes(&mk_id_a);
    rand.bytes(&mk_id_b);
    var sid: [16]u8 = undefined;
    rand.bytes(&sid);

    var env = try encrypt(a, &mk, &mk_id_a, &sid, 1, "x");
    defer env.deinit(a);
    try testing.expectError(Error.AuthenticationFailed, decrypt(a, &mk, &mk_id_b, &sid, &env));
}

test "tampered ciphertext is rejected" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);
    var sid: [16]u8 = undefined;
    rand.bytes(&sid);

    var env = try encrypt(a, &mk, &mk_id, &sid, 1, "secret data here");
    defer env.deinit(a);
    env.value_ct[0] ^= 0x01;
    try testing.expectError(Error.AuthenticationFailed, decrypt(a, &mk, &mk_id, &sid, &env));
}

test "serialize -> parse round-trip" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);
    var sid: [16]u8 = undefined;
    rand.bytes(&sid);

    var env = try encrypt(a, &mk, &mk_id, &sid, 7, "abcdef");
    defer env.deinit(a);
    const blob = try serialize(a, &env);
    defer a.free(blob);
    var env2 = try parse(a, blob);
    defer env2.deinit(a);
    try testing.expectEqual(env.mk_version, env2.mk_version);
    try testing.expectEqualSlices(u8, &env.dek_nonce, &env2.dek_nonce);
    try testing.expectEqualSlices(u8, env.value_ct, env2.value_ct);

    var pt = try decrypt(a, &mk, &mk_id, &sid, &env2);
    defer pt.deinit();
    try testing.expectEqualSlices(u8, "abcdef", pt.bytes);
}

test "rejects oversized value" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    var sid: [16]u8 = undefined;
    rand.bytes(&mk_id);
    rand.bytes(&sid);
    const oversized = try a.alloc(u8, max_value_len + 1);
    defer a.free(oversized);
    @memset(oversized, 0);
    try testing.expectError(Error.ValueTooLong, encrypt(a, &mk, &mk_id, &sid, 1, oversized));
}
