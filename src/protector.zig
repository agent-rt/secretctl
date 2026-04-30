//! Protector: the unified abstraction for unwrapping the master key.
//!
//! v1 implements two concrete kinds:
//!   type=1  passphrase     — Argon2id over a master password
//!   type=2  macos_keychain — wrapping_key stored in the macOS Keychain
//!
//! Future protectors (age identity, Touch ID, ...) plug in by adding new
//! type ids; the on-disk container always carries protector_len so older
//! readers can skip unknown types without breaking.
//!
//! This module owns the on-wire serialization for the *common* protector
//! header and the passphrase body. macOS Keychain bodies are serialized in
//! crypto/keychain.zig but use the same header.

const std = @import("std");
const aes = @import("aes_gcm.zig");
const argon2 = @import("argon2.zig");
const mem_util = @import("mem.zig");
const rand = @import("rand.zig");
const clock = @import("clock.zig");

pub const ProtectorType = enum(u16) {
    passphrase = 1,
    macos_keychain = 2,
    age_identity = 3,
    _,
};

pub const Protector = struct {
    id: [16]u8,
    type_id: u16,
    created_at: i64,
    /// Type-specific body bytes (passphrase body, keychain body, ...).
    /// Owned by this struct.
    body: []u8,

    pub fn deinit(self: *Protector, allocator: std.mem.Allocator) void {
        mem_util.secureZero(u8, self.body);
        allocator.free(self.body);
        self.body = &.{};
    }
};

pub const PassphraseBody = struct {
    kdf_id: u16, // = 1 (Argon2id)
    params: argon2.Params,
    salt: []const u8,
    nonce: aes.Nonce,
    /// Encrypted master_key.
    ciphertext: [aes.key_len]u8,
    tag: aes.Tag,
};

const passphrase_kdf_argon2id: u16 = 1;

/// Build the AAD that ties an unwrap operation to a particular vault and
/// protector. Caller owns the returned slice.
fn buildPassphraseAad(
    allocator: std.mem.Allocator,
    master_key_id: *const [16]u8,
    protector_id: *const [16]u8,
) ![]u8 {
    const prefix = "secretctl/master.key v1\x00passphrase";
    var buf = try allocator.alloc(u8, prefix.len + 16 + 16);
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..16], master_key_id);
    @memcpy(buf[prefix.len + 16 ..][0..16], protector_id);
    return buf;
}

/// Wrap a master_key with a passphrase, producing a Protector ready to
/// serialize into master.key.
pub fn wrapPassphrase(
    allocator: std.mem.Allocator,
    password: []const u8,
    master_key: *const [aes.key_len]u8,
    master_key_id: *const [16]u8,
    params: argon2.Params,
) !Protector {
    var protector_id: [16]u8 = undefined;
    rand.bytes(&protector_id);

    var salt: [16]u8 = undefined;
    rand.bytes(&salt);

    var nonce: aes.Nonce = undefined;
    rand.bytes(&nonce);

    var wrap_key: aes.Key = undefined;
    try argon2.deriveKey(allocator, password, &salt, params, &wrap_key);
    defer mem_util.secureZero(u8, &wrap_key);

    const aad = try buildPassphraseAad(allocator, master_key_id, &protector_id);
    defer allocator.free(aad);

    var ct: [aes.key_len]u8 = undefined;
    var tag: aes.Tag = undefined;
    aes.encrypt(&wrap_key, &nonce, aad, master_key, &ct, &tag);

    // Serialize body: kdf_id u16 | m u32 | t u32 | p u32 | version u32 | salt_len u16 | salt | nonce[12] | ct_len u16(=32) | ct[32] | tag[16]
    const salt_len_u16: u16 = @intCast(salt.len);
    const body_len = 2 + 4 + 4 + 4 + 4 + 2 + salt.len + 12 + 2 + ct.len + 16;
    var body = try allocator.alloc(u8, body_len);
    var w: usize = 0;
    std.mem.writeInt(u16, body[w..][0..2], passphrase_kdf_argon2id, .little);
    w += 2;
    std.mem.writeInt(u32, body[w..][0..4], params.m_kib, .little);
    w += 4;
    std.mem.writeInt(u32, body[w..][0..4], params.t, .little);
    w += 4;
    std.mem.writeInt(u32, body[w..][0..4], @as(u32, params.p), .little);
    w += 4;
    std.mem.writeInt(u32, body[w..][0..4], params.version, .little);
    w += 4;
    std.mem.writeInt(u16, body[w..][0..2], salt_len_u16, .little);
    w += 2;
    @memcpy(body[w .. w + salt.len], &salt);
    w += salt.len;
    @memcpy(body[w .. w + 12], &nonce);
    w += 12;
    std.mem.writeInt(u16, body[w..][0..2], @as(u16, @intCast(ct.len)), .little);
    w += 2;
    @memcpy(body[w .. w + ct.len], &ct);
    w += ct.len;
    @memcpy(body[w .. w + 16], &tag);
    w += 16;
    std.debug.assert(w == body_len);

    return .{
        .id = protector_id,
        .type_id = @intFromEnum(ProtectorType.passphrase),
        .created_at = clock.unixSeconds(),
        .body = body,
    };
}

pub const UnwrapError = error{
    UnsupportedKdf,
    MalformedBody,
    AuthenticationFailed,
    OutOfMemory,
    Unexpected,
};

/// Unwrap a passphrase protector to recover the master_key.
/// Caller is responsible for secureZero-ing `out_master_key` after use.
pub fn unwrapPassphrase(
    allocator: std.mem.Allocator,
    body: []const u8,
    password: []const u8,
    master_key_id: *const [16]u8,
    protector_id: *const [16]u8,
    out_master_key: *[aes.key_len]u8,
) UnwrapError!void {
    if (body.len < 2 + 4 + 4 + 4 + 4 + 2) return UnwrapError.MalformedBody;
    var r: usize = 0;
    const kdf_id = std.mem.readInt(u16, body[r..][0..2], .little);
    r += 2;
    if (kdf_id != passphrase_kdf_argon2id) return UnwrapError.UnsupportedKdf;
    const m_kib = std.mem.readInt(u32, body[r..][0..4], .little);
    r += 4;
    const t_cost = std.mem.readInt(u32, body[r..][0..4], .little);
    r += 4;
    const p_lanes = std.mem.readInt(u32, body[r..][0..4], .little);
    r += 4;
    const version = std.mem.readInt(u32, body[r..][0..4], .little);
    r += 4;
    if (body.len < r + 2) return UnwrapError.MalformedBody;
    const salt_len = std.mem.readInt(u16, body[r..][0..2], .little);
    r += 2;
    if (body.len < r + salt_len + 12 + 2) return UnwrapError.MalformedBody;
    const salt = body[r .. r + salt_len];
    r += salt_len;
    var nonce: aes.Nonce = undefined;
    @memcpy(&nonce, body[r .. r + 12]);
    r += 12;
    const ct_len = std.mem.readInt(u16, body[r..][0..2], .little);
    r += 2;
    if (ct_len != aes.key_len) return UnwrapError.MalformedBody;
    if (body.len < r + ct_len + 16) return UnwrapError.MalformedBody;
    var ct: [aes.key_len]u8 = undefined;
    @memcpy(&ct, body[r .. r + ct_len]);
    r += ct_len;
    var tag: aes.Tag = undefined;
    @memcpy(&tag, body[r .. r + 16]);
    r += 16;

    const params: argon2.Params = .{
        .m_kib = m_kib,
        .t = t_cost,
        .p = @intCast(p_lanes),
        .version = version,
    };

    var wrap_key: aes.Key = undefined;
    argon2.deriveKey(allocator, password, salt, params, &wrap_key) catch |e| switch (e) {
        error.OutOfMemory => return UnwrapError.OutOfMemory,
        else => return UnwrapError.Unexpected,
    };
    defer mem_util.secureZero(u8, &wrap_key);

    const aad = buildPassphraseAad(allocator, master_key_id, protector_id) catch return UnwrapError.OutOfMemory;
    defer allocator.free(aad);

    aes.decrypt(&wrap_key, &nonce, aad, &ct, &tag, out_master_key) catch return UnwrapError.AuthenticationFailed;
}

const testing = std.testing;

test "wrap then unwrap passphrase" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    @memset(&mk, 0xAB);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    const params: argon2.Params = .{ .m_kib = 8, .t = 1, .p = 1 };
    var p = try wrapPassphrase(a, "correct horse battery staple", &mk, &mk_id, params);
    defer p.deinit(a);

    var recovered: [aes.key_len]u8 = undefined;
    try unwrapPassphrase(a, p.body, "correct horse battery staple", &mk_id, &p.id, &recovered);
    try testing.expectEqualSlices(u8, &mk, &recovered);
}

test "wrong password fails" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    @memset(&mk, 0xAB);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    const params: argon2.Params = .{ .m_kib = 8, .t = 1, .p = 1 };
    var p = try wrapPassphrase(a, "right", &mk, &mk_id, params);
    defer p.deinit(a);

    var recovered: [aes.key_len]u8 = undefined;
    try testing.expectError(UnwrapError.AuthenticationFailed, unwrapPassphrase(a, p.body, "wrong", &mk_id, &p.id, &recovered));
}

test "cross-vault AAD mismatch fails" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    @memset(&mk, 0xAB);
    var mk_id_a: [16]u8 = undefined;
    var mk_id_b: [16]u8 = undefined;
    rand.bytes(&mk_id_a);
    rand.bytes(&mk_id_b);

    const params: argon2.Params = .{ .m_kib = 8, .t = 1, .p = 1 };
    var p = try wrapPassphrase(a, "pw", &mk, &mk_id_a, params);
    defer p.deinit(a);

    var recovered: [aes.key_len]u8 = undefined;
    try testing.expectError(UnwrapError.AuthenticationFailed, unwrapPassphrase(a, p.body, "pw", &mk_id_b, &p.id, &recovered));
}

test "malformed body rejected" {
    const a = testing.allocator;
    var mk_id: [16]u8 = undefined;
    var pid: [16]u8 = undefined;
    @memset(&mk_id, 0);
    @memset(&pid, 0);
    var recovered: [aes.key_len]u8 = undefined;
    try testing.expectError(UnwrapError.MalformedBody, unwrapPassphrase(a, "tooshort", "pw", &mk_id, &pid, &recovered));
}
