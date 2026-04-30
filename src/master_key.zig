//! master.key file format. Self-contained key container with magic, version,
//! protector list, and an HMAC over the file body keyed by HKDF(master_key).
//! Layout (TECH-DESIGN §2.2):
//!
//!   0   8   magic              "SCTL\x00KEY"
//!   8   2   format_version     u16=1
//!  10  16   master_key_id      [16]u8
//!  26   4   master_key_version u32
//!  30   4   protector_count    u32
//!  34  ..   protectors[]
//!  ..  32   file_hmac          HMAC-SHA256
//!
//! Each protector entry starts with the common header (TECH-DESIGN §3.1):
//!   4    protector_len   u32
//!  16    protector_id
//!   2    protector_type  u16
//!   8    created_at      i64
//!   4    body_len        u32
//!  body_len bytes        type-specific body

const std = @import("std");
const aes = @import("aes_gcm.zig");
const protector_mod = @import("protector.zig");
const keychain_mod = @import("keychain.zig");
const mem_util = @import("mem.zig");
const rand = @import("rand.zig");
const clock = @import("clock.zig");

const magic = "SCTL\x00KEY";
const format_version: u16 = 1;

pub const Error = error{
    OutOfMemory,
    BadMagic,
    UnsupportedVersion,
    Truncated,
    NoProtectorMatched,
    NoUsableProtector,
    AuthenticationFailed,
    HmacMismatch,
    Unexpected,
};

pub const MasterFile = struct {
    master_key_id: [16]u8,
    master_key_version: u32,
    protectors: []protector_mod.Protector,

    pub fn deinit(self: *MasterFile, allocator: std.mem.Allocator) void {
        for (self.protectors) |*p| p.deinit(allocator);
        allocator.free(self.protectors);
        self.protectors = &.{};
    }
};

fn hkdfExtract(salt: []const u8, ikm: []const u8) [32]u8 {
    return std.crypto.auth.hmac.sha2.HmacSha256.create(salt, ikm);
}

fn deriveHmacKey(master_key: *const [aes.key_len]u8, master_key_id: *const [16]u8) [32]u8 {
    var info_buf: [64]u8 = undefined;
    const info = "secretctl/master.key/hmac";
    @memcpy(info_buf[0..info.len], info);
    @memcpy(info_buf[info.len..][0..16], master_key_id);
    const info_len = info.len + 16;

    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const prk = Hkdf.extract("", master_key);
    var okm: [32]u8 = undefined;
    Hkdf.expand(&okm, info_buf[0..info_len], prk);
    return okm;
}

fn computeFileHmac(body_without_hmac: []const u8, hmac_key: *const [32]u8) [32]u8 {
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    var out: [32]u8 = undefined;
    HmacSha256.create(&out, body_without_hmac, hmac_key);
    return out;
}

/// Serialize a MasterFile into a freshly allocated buffer (caller owns).
/// `master_key` is needed to compute the file HMAC.
pub fn serialize(
    allocator: std.mem.Allocator,
    file: *const MasterFile,
    master_key: *const [aes.key_len]u8,
) ![]u8 {
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(allocator);

    try list.appendSlice(allocator, magic);
    try writeU16(&list, allocator, format_version);
    try list.appendSlice(allocator, &file.master_key_id);
    try writeU32(&list, allocator, file.master_key_version);
    try writeU32(&list, allocator, @intCast(file.protectors.len));

    for (file.protectors) |p| {
        // protector_len excludes the protector_len field itself.
        const protector_len = 16 + 2 + 8 + 4 + p.body.len;
        try writeU32(&list, allocator, @intCast(protector_len));
        try list.appendSlice(allocator, &p.id);
        try writeU16(&list, allocator, p.type_id);
        try writeI64(&list, allocator, p.created_at);
        try writeU32(&list, allocator, @intCast(p.body.len));
        try list.appendSlice(allocator, p.body);
    }

    const hmac_key = deriveHmacKey(master_key, &file.master_key_id);
    const file_hmac = computeFileHmac(list.items, &hmac_key);
    try list.appendSlice(allocator, &file_hmac);

    return list.toOwnedSlice(allocator);
}

/// Parse a master.key blob and unwrap using either a passphrase or the
/// macOS Keychain. `password` may be null when only Keychain protectors
/// should be tried.
pub fn parseAndUnlock(
    allocator: std.mem.Allocator,
    blob: []const u8,
    password: ?[]const u8,
    out_master_key: *[aes.key_len]u8,
) Error!MasterFile {
    if (blob.len < magic.len + 2 + 16 + 4 + 4 + 32) return Error.Truncated;
    if (!std.mem.eql(u8, blob[0..magic.len], magic)) return Error.BadMagic;

    var r: usize = magic.len;
    const ver = std.mem.readInt(u16, blob[r..][0..2], .little);
    r += 2;
    if (ver != format_version) return Error.UnsupportedVersion;

    var mk_id: [16]u8 = undefined;
    @memcpy(&mk_id, blob[r .. r + 16]);
    r += 16;
    const mk_ver = std.mem.readInt(u32, blob[r..][0..4], .little);
    r += 4;
    const protector_count = std.mem.readInt(u32, blob[r..][0..4], .little);
    r += 4;

    const hmac_start = blob.len - 32;
    if (r > hmac_start) return Error.Truncated;

    var protectors_list: std.ArrayList(protector_mod.Protector) = .empty;
    errdefer {
        for (protectors_list.items) |*pp| pp.deinit(allocator);
        protectors_list.deinit(allocator);
    }

    var unlocked = false;
    var first_err: ?Error = null;

    var i: u32 = 0;
    while (i < protector_count) : (i += 1) {
        if (r + 4 > hmac_start) return Error.Truncated;
        const plen = std.mem.readInt(u32, blob[r..][0..4], .little);
        r += 4;
        if (r + plen > hmac_start) return Error.Truncated;
        const entry_end = r + plen;

        if (plen < 16 + 2 + 8 + 4) return Error.Truncated;
        var pid: [16]u8 = undefined;
        @memcpy(&pid, blob[r .. r + 16]);
        r += 16;
        const ptype = std.mem.readInt(u16, blob[r..][0..2], .little);
        r += 2;
        const created_at = std.mem.readInt(i64, blob[r..][0..8], .little);
        r += 8;
        const body_len = std.mem.readInt(u32, blob[r..][0..4], .little);
        r += 4;
        if (r + body_len > entry_end) return Error.Truncated;
        const body_src = blob[r .. r + body_len];
        r = entry_end;

        const body_copy = try allocator.dupe(u8, body_src);
        try protectors_list.append(allocator, .{
            .id = pid,
            .type_id = ptype,
            .created_at = created_at,
            .body = body_copy,
        });

        if (unlocked) continue;

        switch (ptype) {
            @intFromEnum(protector_mod.ProtectorType.passphrase) => {
                if (password) |pw| {
                    var probe: [aes.key_len]u8 = undefined;
                    if (protector_mod.unwrapPassphrase(allocator, body_src, pw, &mk_id, &pid, &probe)) |_| {
                        @memcpy(out_master_key, &probe);
                        mem_util.secureZero(u8, &probe);
                        unlocked = true;
                    } else |err| switch (err) {
                        protector_mod.UnwrapError.AuthenticationFailed => {
                            if (first_err == null) first_err = Error.AuthenticationFailed;
                        },
                        else => {
                            if (first_err == null) first_err = Error.Unexpected;
                        },
                    }
                }
            },
            @intFromEnum(protector_mod.ProtectorType.macos_keychain) => {
                var probe: [aes.key_len]u8 = undefined;
                if (keychain_mod.unwrap(allocator, body_src, &mk_id, &pid, &probe)) |_| {
                    @memcpy(out_master_key, &probe);
                    mem_util.secureZero(u8, &probe);
                    unlocked = true;
                } else |_| {
                    if (first_err == null) first_err = Error.AuthenticationFailed;
                }
            },
            else => {
                // Unknown protector — skip silently for forward compat.
            },
        }
    }

    if (!unlocked) {
        // errdefer will clean up protectors_list.
        return first_err orelse Error.NoUsableProtector;
    }

    // Verify file HMAC.
    if (r != hmac_start) return Error.Truncated;
    const expected_hmac = blob[hmac_start..];
    const hmac_key = deriveHmacKey(out_master_key, &mk_id);
    const actual_hmac = computeFileHmac(blob[0..hmac_start], &hmac_key);
    if (!std.crypto.timing_safe.eql([32]u8, actual_hmac, expected_hmac[0..32].*)) {
        // HMAC mismatch — warn via error, but caller may decide to continue
        // operating on this protector (per TECH-DESIGN §2.3). We surface a
        // distinct error so caller can detect tampering.
        return Error.HmacMismatch;
    }

    const ps = try protectors_list.toOwnedSlice(allocator);
    return .{
        .master_key_id = mk_id,
        .master_key_version = mk_ver,
        .protectors = ps,
    };
}

fn writeU16(list: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, v, .little);
    try list.appendSlice(allocator, &buf);
}
fn writeU32(list: *std.ArrayList(u8), allocator: std.mem.Allocator, v: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, v, .little);
    try list.appendSlice(allocator, &buf);
}
fn writeI64(list: *std.ArrayList(u8), allocator: std.mem.Allocator, v: i64) !void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(i64, &buf, v, .little);
    try list.appendSlice(allocator, &buf);
}

const argon2 = @import("argon2.zig");
const testing = std.testing;

test "serialize -> parseAndUnlock round-trip with passphrase" {
    const a = testing.allocator;

    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    const params: argon2.Params = .{ .m_kib = 8, .t = 1, .p = 1 };
    var p = try protector_mod.wrapPassphrase(a, "the-password", &mk, &mk_id, params);
    defer p.deinit(a);

    var protectors: [1]protector_mod.Protector = .{p};
    const file: MasterFile = .{
        .master_key_id = mk_id,
        .master_key_version = 1,
        .protectors = &protectors,
    };
    const blob = try serialize(a, &file, &mk);
    defer a.free(blob);

    var recovered: [aes.key_len]u8 = undefined;
    var parsed = try parseAndUnlock(a, blob, "the-password", &recovered);
    defer parsed.deinit(a);
    try testing.expectEqualSlices(u8, &mk, &recovered);
    try testing.expectEqual(@as(u32, 1), parsed.master_key_version);
}

test "wrong password rejected" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    const params: argon2.Params = .{ .m_kib = 8, .t = 1, .p = 1 };
    var p = try protector_mod.wrapPassphrase(a, "right", &mk, &mk_id, params);
    defer p.deinit(a);

    var protectors: [1]protector_mod.Protector = .{p};
    const file: MasterFile = .{
        .master_key_id = mk_id,
        .master_key_version = 1,
        .protectors = &protectors,
    };
    const blob = try serialize(a, &file, &mk);
    defer a.free(blob);

    var recovered: [aes.key_len]u8 = undefined;
    try testing.expectError(Error.AuthenticationFailed, parseAndUnlock(a, blob, "wrong", &recovered));
}

test "tampered HMAC detected" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    const params: argon2.Params = .{ .m_kib = 8, .t = 1, .p = 1 };
    var p = try protector_mod.wrapPassphrase(a, "pw", &mk, &mk_id, params);
    defer p.deinit(a);

    var protectors: [1]protector_mod.Protector = .{p};
    const file: MasterFile = .{
        .master_key_id = mk_id,
        .master_key_version = 1,
        .protectors = &protectors,
    };
    const blob = try serialize(a, &file, &mk);
    defer a.free(blob);

    // Flip a byte in the HMAC trailer.
    blob[blob.len - 1] ^= 0x01;

    var recovered: [aes.key_len]u8 = undefined;
    try testing.expectError(Error.HmacMismatch, parseAndUnlock(a, blob, "pw", &recovered));
}
