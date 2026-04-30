//! Single-file encrypted vault.
//!
//! File layout (TECH-DESIGN §4.1):
//!   0   8   magic "SCTLVLT1"
//!   8   2   format_version u16=1
//!  10  16   master_key_id [16]u8
//!  26   4   master_key_version u32
//!  30  12   body_nonce [12]u8
//!  42   8   body_ct_len u64
//!  50  ..   body_ct
//!  ..  16   body_tag
//!
//! Body (after outer AEAD decrypt) is encoded with codec.zig:
//!   VaultBody { schema_version u32, updated_at i64, secrets: []SecretRecord }
//!   SecretRecord { id fix16, name string, tags array<string>, envelope, created_at i64, updated_at i64 }
//!
//! Outer AAD: "secretctl/vault v1" || master_key_id || mk_version

const std = @import("std");
const aes = @import("aes_gcm.zig");
const envelope_mod = @import("envelope.zig");
const mem_util = @import("mem.zig");
const rand = @import("rand.zig");
const clock = @import("clock.zig");
const codec = @import("codec.zig");
const fsx = @import("fsx.zig");

pub const magic = "SCTLVLT1";
pub const format_version: u16 = 1;
pub const schema_version: u32 = 1;
pub const max_file_size: usize = 1 * 1024 * 1024;

pub const Error = error{
    OutOfMemory,
    BadMagic,
    UnsupportedVersion,
    Truncated,
    AuthenticationFailed,
    DuplicateName,
    NotFound,
    PathTooLong,
    OpenFailed,
    ReadFailed,
    WriteFailed,
    FsyncFailed,
    RenameFailed,
    InvalidUtf8,
};

pub const SecretRecord = struct {
    id: [16]u8,
    name: []const u8,
    tags: [][]const u8,
    envelope: envelope_mod.Envelope,
    created_at: i64,
    updated_at: i64,

    fn deinit(self: *SecretRecord, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        for (self.tags) |t| allocator.free(t);
        allocator.free(self.tags);
        self.envelope.deinit(allocator);
    }
};

pub const VaultBody = struct {
    schema_version: u32,
    updated_at: i64,
    secrets: std.ArrayList(SecretRecord),

    pub fn empty() VaultBody {
        return .{
            .schema_version = schema_version,
            .updated_at = clock.unixSeconds(),
            .secrets = .empty,
        };
    }

    pub fn deinit(self: *VaultBody, allocator: std.mem.Allocator) void {
        for (self.secrets.items) |*s| s.deinit(allocator);
        self.secrets.deinit(allocator);
    }

    pub fn findIndex(self: *const VaultBody, name: []const u8) ?usize {
        for (self.secrets.items, 0..) |s, i| {
            if (std.ascii.eqlIgnoreCase(s.name, name)) return i;
        }
        return null;
    }

    /// Add a new secret. The plaintext is encrypted into a per-secret envelope
    /// bound to a freshly generated secret_id so that AAD is internally consistent.
    pub fn addSecret(
        self: *VaultBody,
        allocator: std.mem.Allocator,
        master_key: *const [aes.key_len]u8,
        master_key_id: *const [16]u8,
        master_key_version: u32,
        name: []const u8,
        tags: []const []const u8,
        plaintext: []const u8,
    ) Error!void {
        if (self.findIndex(name) != null) return Error.DuplicateName;
        var id: [16]u8 = undefined;
        rand.bytes(&id);

        var env = envelope_mod.encrypt(allocator, master_key, master_key_id, &id, master_key_version, plaintext) catch |e| return switch (e) {
            error.OutOfMemory => Error.OutOfMemory,
            error.ValueTooLong => Error.WriteFailed,
            else => Error.WriteFailed,
        };
        errdefer env.deinit(allocator);

        const name_copy = allocator.dupe(u8, name) catch return Error.OutOfMemory;
        errdefer allocator.free(name_copy);

        const tags_copy = allocator.alloc([]const u8, tags.len) catch return Error.OutOfMemory;
        errdefer {
            for (tags_copy[0..]) |t| if (t.len != 0) allocator.free(t);
            allocator.free(tags_copy);
        }
        var done: usize = 0;
        for (tags) |t| {
            tags_copy[done] = allocator.dupe(u8, t) catch return Error.OutOfMemory;
            done += 1;
        }

        const now = clock.unixSeconds();
        const rec: SecretRecord = .{
            .id = id,
            .name = name_copy,
            .tags = tags_copy,
            .envelope = env,
            .created_at = now,
            .updated_at = now,
        };
        try self.secrets.append(allocator, rec);
        self.updated_at = now;
    }

    /// Decrypt a secret value by name. Caller deinit's the returned Plaintext.
    pub fn revealSecret(
        self: *const VaultBody,
        allocator: std.mem.Allocator,
        master_key: *const [aes.key_len]u8,
        master_key_id: *const [16]u8,
        name: []const u8,
    ) Error!mem_util.Plaintext {
        const idx = self.findIndex(name) orelse return Error.NotFound;
        const rec = self.secrets.items[idx];
        return envelope_mod.decrypt(allocator, master_key, master_key_id, &rec.id, &rec.envelope) catch |e| switch (e) {
            error.OutOfMemory => Error.OutOfMemory,
            error.AuthenticationFailed => Error.AuthenticationFailed,
            else => Error.AuthenticationFailed,
        };
    }

    pub fn removeByName(self: *VaultBody, allocator: std.mem.Allocator, name: []const u8) Error!void {
        const idx = self.findIndex(name) orelse return Error.NotFound;
        var rec = self.secrets.orderedRemove(idx);
        rec.deinit(allocator);
        self.updated_at = clock.unixSeconds();
    }
};

fn buildOuterAad(
    allocator: std.mem.Allocator,
    master_key_id: *const [16]u8,
    mk_version: u32,
) ![]u8 {
    const prefix = "secretctl/vault v1";
    var buf = try allocator.alloc(u8, prefix.len + 16 + 4);
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..16], master_key_id);
    std.mem.writeInt(u32, buf[prefix.len + 16 ..][0..4], mk_version, .little);
    return buf;
}

fn encodeBody(allocator: std.mem.Allocator, body: *const VaultBody) ![]u8 {
    var enc: codec.Encoder = .init(allocator);
    defer enc.deinit(allocator);
    try enc.writeU32(allocator, body.schema_version);
    try enc.writeI64(allocator, body.updated_at);
    try enc.writeArrayHeader(allocator, @intCast(body.secrets.items.len));
    for (body.secrets.items) |s| {
        try enc.writeFix16(allocator, &s.id);
        try enc.writeString(allocator, s.name);
        try enc.writeArrayHeader(allocator, @intCast(s.tags.len));
        for (s.tags) |t| try enc.writeString(allocator, t);
        // envelope inlined: mk_version u32, dek_nonce fix12, wrapped_dek_ct fix32,
        // wrapped_dek_tag fix16, value_nonce fix12, value_ct bytes, value_tag fix16
        try enc.writeU32(allocator, s.envelope.mk_version);
        try enc.writeFix12(allocator, &s.envelope.dek_nonce);
        try enc.writeFix32(allocator, &s.envelope.wrapped_dek_ct);
        try enc.writeFix16(allocator, &s.envelope.wrapped_dek_tag);
        try enc.writeFix12(allocator, &s.envelope.value_nonce);
        try enc.writeBytes(allocator, s.envelope.value_ct);
        try enc.writeFix16(allocator, &s.envelope.value_tag);
        try enc.writeI64(allocator, s.created_at);
        try enc.writeI64(allocator, s.updated_at);
    }
    return enc.toOwnedSlice(allocator);
}

fn decodeBody(allocator: std.mem.Allocator, body_bytes: []const u8) Error!VaultBody {
    var dec: codec.Decoder = .init(body_bytes);
    const sv = dec.readU32() catch return Error.Truncated;
    const updated = dec.readI64() catch return Error.Truncated;
    const count = dec.readArrayHeader() catch return Error.Truncated;

    var body: VaultBody = .{
        .schema_version = sv,
        .updated_at = updated,
        .secrets = .empty,
    };
    errdefer body.deinit(allocator);

    var i: u32 = 0;
    while (i < count) : (i += 1) {
        var rec: SecretRecord = undefined;
        // Build the record incrementally so partial failures are cleanable.
        rec.tags = &.{};
        rec.name = &.{};
        rec.envelope = undefined;

        dec.readFix16(&rec.id) catch return Error.Truncated;
        const name_view = dec.readString() catch return Error.Truncated;
        rec.name = allocator.dupe(u8, name_view) catch return Error.OutOfMemory;
        errdefer allocator.free(rec.name);

        const tag_count = dec.readArrayHeader() catch return Error.Truncated;
        const tags_buf = allocator.alloc([]const u8, tag_count) catch return Error.OutOfMemory;
        errdefer {
            for (tags_buf) |t| if (t.len != 0) allocator.free(t);
            allocator.free(tags_buf);
        }
        var t_idx: u32 = 0;
        while (t_idx < tag_count) : (t_idx += 1) {
            const tv = dec.readString() catch return Error.Truncated;
            tags_buf[t_idx] = allocator.dupe(u8, tv) catch return Error.OutOfMemory;
        }
        rec.tags = tags_buf;

        const mkv = dec.readU32() catch return Error.Truncated;
        var dek_nonce: [12]u8 = undefined;
        dec.readFix12(&dek_nonce) catch return Error.Truncated;
        var wrapped_ct: [32]u8 = undefined;
        dec.readFix32(&wrapped_ct) catch return Error.Truncated;
        var wrapped_tag: [16]u8 = undefined;
        dec.readFix16(&wrapped_tag) catch return Error.Truncated;
        var value_nonce: [12]u8 = undefined;
        dec.readFix12(&value_nonce) catch return Error.Truncated;
        const ct_view = dec.readBytesValue() catch return Error.Truncated;
        const ct_owned = allocator.dupe(u8, ct_view) catch return Error.OutOfMemory;
        errdefer allocator.free(ct_owned);
        var value_tag: [16]u8 = undefined;
        dec.readFix16(&value_tag) catch return Error.Truncated;

        rec.envelope = .{
            .mk_version = mkv,
            .dek_nonce = dek_nonce,
            .wrapped_dek_ct = wrapped_ct,
            .wrapped_dek_tag = wrapped_tag,
            .value_nonce = value_nonce,
            .value_ct = ct_owned,
            .value_tag = value_tag,
        };
        rec.created_at = dec.readI64() catch return Error.Truncated;
        rec.updated_at = dec.readI64() catch return Error.Truncated;

        body.secrets.append(allocator, rec) catch return Error.OutOfMemory;
    }
    return body;
}

pub fn serializeAndEncrypt(
    allocator: std.mem.Allocator,
    body: *const VaultBody,
    master_key: *const [aes.key_len]u8,
    master_key_id: *const [16]u8,
    master_key_version: u32,
) Error![]u8 {
    const body_bytes = encodeBody(allocator, body) catch return Error.OutOfMemory;
    defer {
        mem_util.secureZero(u8, body_bytes);
        allocator.free(body_bytes);
    }

    const aad = buildOuterAad(allocator, master_key_id, master_key_version) catch return Error.OutOfMemory;
    defer allocator.free(aad);

    var body_nonce: aes.Nonce = undefined;
    rand.bytes(&body_nonce);

    const total = magic.len + 2 + 16 + 4 + 12 + 8 + body_bytes.len + 16;
    var blob = allocator.alloc(u8, total) catch return Error.OutOfMemory;
    var w: usize = 0;
    @memcpy(blob[w .. w + magic.len], magic);
    w += magic.len;
    std.mem.writeInt(u16, blob[w..][0..2], format_version, .little);
    w += 2;
    @memcpy(blob[w .. w + 16], master_key_id);
    w += 16;
    std.mem.writeInt(u32, blob[w..][0..4], master_key_version, .little);
    w += 4;
    @memcpy(blob[w .. w + 12], &body_nonce);
    w += 12;
    std.mem.writeInt(u64, blob[w..][0..8], @intCast(body_bytes.len), .little);
    w += 8;

    const ct_dst = blob[w .. w + body_bytes.len];
    var tag: aes.Tag = undefined;
    aes.encrypt(master_key, &body_nonce, aad, body_bytes, ct_dst, &tag);
    w += body_bytes.len;
    @memcpy(blob[w .. w + 16], &tag);
    w += 16;
    std.debug.assert(w == total);
    return blob;
}

pub const ParseResult = struct {
    body: VaultBody,
    master_key_id: [16]u8,
    master_key_version: u32,
};

pub fn parseAndDecrypt(
    allocator: std.mem.Allocator,
    blob: []const u8,
    master_key: *const [aes.key_len]u8,
    expected_mk_id: ?*const [16]u8,
) Error!ParseResult {
    if (blob.len < magic.len + 2 + 16 + 4 + 12 + 8 + 16) return Error.Truncated;
    if (!std.mem.eql(u8, blob[0..magic.len], magic)) return Error.BadMagic;
    var r: usize = magic.len;
    const ver = std.mem.readInt(u16, blob[r..][0..2], .little);
    r += 2;
    if (ver != format_version) return Error.UnsupportedVersion;
    var mk_id: [16]u8 = undefined;
    @memcpy(&mk_id, blob[r .. r + 16]);
    r += 16;
    if (expected_mk_id) |emk| {
        if (!std.mem.eql(u8, &mk_id, emk)) return Error.AuthenticationFailed;
    }
    const mk_ver = std.mem.readInt(u32, blob[r..][0..4], .little);
    r += 4;
    var nonce: aes.Nonce = undefined;
    @memcpy(&nonce, blob[r .. r + 12]);
    r += 12;
    const ct_len = std.mem.readInt(u64, blob[r..][0..8], .little);
    r += 8;
    if (ct_len > max_file_size) return Error.Truncated;
    if (blob.len < r + ct_len + 16) return Error.Truncated;
    const ct = blob[r .. r + ct_len];
    r += @intCast(ct_len);
    var tag: aes.Tag = undefined;
    @memcpy(&tag, blob[r .. r + 16]);

    const aad = buildOuterAad(allocator, &mk_id, mk_ver) catch return Error.OutOfMemory;
    defer allocator.free(aad);

    const pt = allocator.alloc(u8, ct.len) catch return Error.OutOfMemory;
    defer {
        mem_util.secureZero(u8, pt);
        allocator.free(pt);
    }
    aes.decrypt(master_key, &nonce, aad, ct, &tag, pt) catch return Error.AuthenticationFailed;

    const body = try decodeBody(allocator, pt);
    return .{ .body = body, .master_key_id = mk_id, .master_key_version = mk_ver };
}

pub fn loadFromFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    master_key: *const [aes.key_len]u8,
    expected_mk_id: ?*const [16]u8,
) Error!ParseResult {
    const blob = fsx.readAllAlloc(allocator, path, max_file_size) catch |e| return switch (e) {
        error.OutOfMemory => Error.OutOfMemory,
        error.OpenFailed => Error.OpenFailed,
        error.ReadFailed => Error.ReadFailed,
        else => Error.OpenFailed,
    };
    defer allocator.free(blob);
    return parseAndDecrypt(allocator, blob, master_key, expected_mk_id);
}

pub fn saveToFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    body: *const VaultBody,
    master_key: *const [aes.key_len]u8,
    master_key_id: *const [16]u8,
    master_key_version: u32,
) Error!void {
    const blob = try serializeAndEncrypt(allocator, body, master_key, master_key_id, master_key_version);
    defer allocator.free(blob);
    fsx.writeAllAtomic(path, blob, 0o600) catch |e| return switch (e) {
        error.OutOfMemory => Error.OutOfMemory,
        error.OpenFailed => Error.OpenFailed,
        error.WriteFailed => Error.WriteFailed,
        error.FsyncFailed => Error.FsyncFailed,
        error.RenameFailed => Error.RenameFailed,
        else => Error.WriteFailed,
    };
}

const testing = std.testing;

extern "c" fn getpid() c_int;

fn tmpPath(buf: *[256]u8, name: []const u8) ![]u8 {
    return std.fmt.bufPrint(buf, "/tmp/secretctl-test-vault-{d}-{s}", .{ getpid(), name });
}

test "empty vault round-trip" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    var body = VaultBody.empty();
    defer body.deinit(a);

    const blob = try serializeAndEncrypt(a, &body, &mk, &mk_id, 1);
    defer a.free(blob);

    var parsed = try parseAndDecrypt(a, blob, &mk, &mk_id);
    defer parsed.body.deinit(a);
    try testing.expectEqual(@as(usize, 0), parsed.body.secrets.items.len);
    try testing.expectEqual(@as(u32, 1), parsed.master_key_version);
}

test "addSecret + serialize + parse + read back" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    var body = VaultBody.empty();
    defer body.deinit(a);

    const tags = [_][]const u8{ "npm", "ci" };
    try body.addSecret(a, &mk, &mk_id, 1, "NPM_TOKEN", &tags, "npm-secret-value");

    const blob = try serializeAndEncrypt(a, &body, &mk, &mk_id, 1);
    defer a.free(blob);

    var parsed = try parseAndDecrypt(a, blob, &mk, &mk_id);
    defer parsed.body.deinit(a);
    try testing.expectEqual(@as(usize, 1), parsed.body.secrets.items.len);
    const rec = parsed.body.secrets.items[0];
    try testing.expectEqualStrings("NPM_TOKEN", rec.name);
    try testing.expectEqual(@as(usize, 2), rec.tags.len);
    try testing.expectEqualStrings("npm", rec.tags[0]);

    var pt = try parsed.body.revealSecret(a, &mk, &mk_id, "NPM_TOKEN");
    defer pt.deinit();
    try testing.expectEqualSlices(u8, "npm-secret-value", pt.bytes);
}

test "wrong master_key_id rejected" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id_a: [16]u8 = undefined;
    var mk_id_b: [16]u8 = undefined;
    rand.bytes(&mk_id_a);
    rand.bytes(&mk_id_b);

    var body = VaultBody.empty();
    defer body.deinit(a);
    const blob = try serializeAndEncrypt(a, &body, &mk, &mk_id_a, 1);
    defer a.free(blob);

    try testing.expectError(Error.AuthenticationFailed, parseAndDecrypt(a, blob, &mk, &mk_id_b));
}

test "save and load via filesystem" {
    const a = testing.allocator;
    var pbuf: [256]u8 = undefined;
    const path = try tmpPath(&pbuf, "save");
    defer fsx.unlinkIfExists(path);

    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    var body = VaultBody.empty();
    defer body.deinit(a);

    const tags = [_][]const u8{};
    try body.addSecret(a, &mk, &mk_id, 1, "GITHUB_TOKEN", &tags, "value");

    try saveToFile(a, path, &body, &mk, &mk_id, 1);

    var parsed = try loadFromFile(a, path, &mk, &mk_id);
    defer parsed.body.deinit(a);
    try testing.expectEqual(@as(usize, 1), parsed.body.secrets.items.len);
    try testing.expectEqualStrings("GITHUB_TOKEN", parsed.body.secrets.items[0].name);
}

test "duplicate name rejected (case-insensitive)" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    var body = VaultBody.empty();
    defer body.deinit(a);

    const tags = [_][]const u8{};
    try body.addSecret(a, &mk, &mk_id, 1, "MY_KEY", &tags, "v1");
    try testing.expectError(Error.DuplicateName, body.addSecret(a, &mk, &mk_id, 1, "my_key", &tags, "v2"));
}

test "removeByName works" {
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    var body = VaultBody.empty();
    defer body.deinit(a);

    const tags = [_][]const u8{};
    try body.addSecret(a, &mk, &mk_id, 1, "K", &tags, "v");
    try testing.expectEqual(@as(usize, 1), body.secrets.items.len);
    try body.removeByName(a, "k");
    try testing.expectEqual(@as(usize, 0), body.secrets.items.len);
    try testing.expectError(Error.NotFound, body.removeByName(a, "K"));
}
