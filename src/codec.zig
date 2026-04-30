//! Minimal self-describing binary codec used to encode VaultBody and the
//! per-secret envelope. Tag-prefixed primitives, little-endian length fields,
//! UTF-8 strings, no third-party dependencies.
//!
//! Layout for each value:
//!   0x01 u32  : 4 bytes LE
//!   0x02 u64  : 8 bytes LE
//!   0x03 i64  : 8 bytes LE
//!   0x04 bytes: u32 LE length || bytes
//!   0x05 str  : u32 LE length || UTF-8 bytes
//!   0x06 array: u32 LE count || items   (item type implied by the schema, no inner tag)
//!   0x08 fix16: 16 bytes
//!   0x09 fix12: 12 bytes
//!   0x0A fix32: 32 bytes
//!
//! The format_version field of any container that wraps codec output controls
//! schema evolution. Decode rejects truncated input and length-overflow.

const std = @import("std");

pub const Tag = enum(u8) {
    u32 = 0x01,
    u64 = 0x02,
    i64 = 0x03,
    bytes = 0x04,
    string = 0x05,
    array = 0x06,
    fix16 = 0x08,
    fix12 = 0x09,
    fix32 = 0x0A,
};

pub const EncodeError = error{OutOfMemory};
pub const DecodeError = error{ Truncated, TagMismatch, InvalidLength };

pub const Encoder = struct {
    buf: std.ArrayList(u8),

    pub fn init(_: std.mem.Allocator) Encoder {
        return .{ .buf = .empty };
    }

    pub fn deinit(self: *Encoder, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
    }

    pub fn toOwnedSlice(self: *Encoder, allocator: std.mem.Allocator) ![]u8 {
        return self.buf.toOwnedSlice(allocator);
    }

    fn appendByte(self: *Encoder, allocator: std.mem.Allocator, b: u8) EncodeError!void {
        try self.buf.append(allocator, b);
    }

    fn appendBytes(self: *Encoder, allocator: std.mem.Allocator, bs: []const u8) EncodeError!void {
        try self.buf.appendSlice(allocator, bs);
    }

    fn appendU32(self: *Encoder, allocator: std.mem.Allocator, v: u32) EncodeError!void {
        var le: [4]u8 = undefined;
        std.mem.writeInt(u32, &le, v, .little);
        try self.appendBytes(allocator, &le);
    }

    fn appendU64(self: *Encoder, allocator: std.mem.Allocator, v: u64) EncodeError!void {
        var le: [8]u8 = undefined;
        std.mem.writeInt(u64, &le, v, .little);
        try self.appendBytes(allocator, &le);
    }

    pub fn writeU32(self: *Encoder, allocator: std.mem.Allocator, v: u32) EncodeError!void {
        try self.appendByte(allocator, @intFromEnum(Tag.u32));
        try self.appendU32(allocator, v);
    }

    pub fn writeU64(self: *Encoder, allocator: std.mem.Allocator, v: u64) EncodeError!void {
        try self.appendByte(allocator, @intFromEnum(Tag.u64));
        try self.appendU64(allocator, v);
    }

    pub fn writeI64(self: *Encoder, allocator: std.mem.Allocator, v: i64) EncodeError!void {
        try self.appendByte(allocator, @intFromEnum(Tag.i64));
        var le: [8]u8 = undefined;
        std.mem.writeInt(i64, &le, v, .little);
        try self.appendBytes(allocator, &le);
    }

    pub fn writeBytes(self: *Encoder, allocator: std.mem.Allocator, bs: []const u8) EncodeError!void {
        try self.appendByte(allocator, @intFromEnum(Tag.bytes));
        try self.appendU32(allocator, @intCast(bs.len));
        try self.appendBytes(allocator, bs);
    }

    pub fn writeString(self: *Encoder, allocator: std.mem.Allocator, s: []const u8) EncodeError!void {
        try self.appendByte(allocator, @intFromEnum(Tag.string));
        try self.appendU32(allocator, @intCast(s.len));
        try self.appendBytes(allocator, s);
    }

    pub fn writeArrayHeader(self: *Encoder, allocator: std.mem.Allocator, count: u32) EncodeError!void {
        try self.appendByte(allocator, @intFromEnum(Tag.array));
        try self.appendU32(allocator, count);
    }

    pub fn writeFix16(self: *Encoder, allocator: std.mem.Allocator, v: *const [16]u8) EncodeError!void {
        try self.appendByte(allocator, @intFromEnum(Tag.fix16));
        try self.appendBytes(allocator, v);
    }

    pub fn writeFix12(self: *Encoder, allocator: std.mem.Allocator, v: *const [12]u8) EncodeError!void {
        try self.appendByte(allocator, @intFromEnum(Tag.fix12));
        try self.appendBytes(allocator, v);
    }

    pub fn writeFix32(self: *Encoder, allocator: std.mem.Allocator, v: *const [32]u8) EncodeError!void {
        try self.appendByte(allocator, @intFromEnum(Tag.fix32));
        try self.appendBytes(allocator, v);
    }
};

pub const Decoder = struct {
    src: []const u8,
    pos: usize = 0,

    pub fn init(src: []const u8) Decoder {
        return .{ .src = src };
    }

    pub fn remaining(self: *const Decoder) usize {
        return self.src.len - self.pos;
    }

    pub fn isExhausted(self: *const Decoder) bool {
        return self.pos == self.src.len;
    }

    fn readByte(self: *Decoder) DecodeError!u8 {
        if (self.pos >= self.src.len) return DecodeError.Truncated;
        const b = self.src[self.pos];
        self.pos += 1;
        return b;
    }

    fn readBytes(self: *Decoder, n: usize) DecodeError![]const u8 {
        if (self.pos + n > self.src.len) return DecodeError.Truncated;
        const slice = self.src[self.pos .. self.pos + n];
        self.pos += n;
        return slice;
    }

    fn readU32Raw(self: *Decoder) DecodeError!u32 {
        const bs = try self.readBytes(4);
        return std.mem.readInt(u32, bs[0..4], .little);
    }

    fn readU64Raw(self: *Decoder) DecodeError!u64 {
        const bs = try self.readBytes(8);
        return std.mem.readInt(u64, bs[0..8], .little);
    }

    fn expectTag(self: *Decoder, want: Tag) DecodeError!void {
        const b = try self.readByte();
        if (b != @intFromEnum(want)) return DecodeError.TagMismatch;
    }

    pub fn readU32(self: *Decoder) DecodeError!u32 {
        try self.expectTag(.u32);
        return self.readU32Raw();
    }

    pub fn readU64(self: *Decoder) DecodeError!u64 {
        try self.expectTag(.u64);
        return self.readU64Raw();
    }

    pub fn readI64(self: *Decoder) DecodeError!i64 {
        try self.expectTag(.i64);
        const bs = try self.readBytes(8);
        return std.mem.readInt(i64, bs[0..8], .little);
    }

    /// Returns a slice into the decoder's input. Caller must copy if the
    /// decoder buffer might be freed before use.
    pub fn readBytesValue(self: *Decoder) DecodeError![]const u8 {
        try self.expectTag(.bytes);
        const n = try self.readU32Raw();
        return self.readBytes(n);
    }

    pub fn readString(self: *Decoder) DecodeError![]const u8 {
        try self.expectTag(.string);
        const n = try self.readU32Raw();
        return self.readBytes(n);
    }

    pub fn readArrayHeader(self: *Decoder) DecodeError!u32 {
        try self.expectTag(.array);
        return self.readU32Raw();
    }

    pub fn readFix16(self: *Decoder, out: *[16]u8) DecodeError!void {
        try self.expectTag(.fix16);
        const bs = try self.readBytes(16);
        @memcpy(out, bs);
    }

    pub fn readFix12(self: *Decoder, out: *[12]u8) DecodeError!void {
        try self.expectTag(.fix12);
        const bs = try self.readBytes(12);
        @memcpy(out, bs);
    }

    pub fn readFix32(self: *Decoder, out: *[32]u8) DecodeError!void {
        try self.expectTag(.fix32);
        const bs = try self.readBytes(32);
        @memcpy(out, bs);
    }
};

const testing = std.testing;

test "round-trip primitives" {
    const a = testing.allocator;
    var enc: Encoder = .init(a);
    defer enc.deinit(a);
    try enc.writeU32(a, 0xdeadbeef);
    try enc.writeU64(a, 0x0102030405060708);
    try enc.writeI64(a, -42);
    try enc.writeBytes(a, "hello");
    try enc.writeString(a, "string-utf8-😀");
    var fix16: [16]u8 = undefined;
    @memset(&fix16, 0xAB);
    try enc.writeFix16(a, &fix16);
    var fix12: [12]u8 = undefined;
    @memset(&fix12, 0xCD);
    try enc.writeFix12(a, &fix12);
    var fix32: [32]u8 = undefined;
    @memset(&fix32, 0xEF);
    try enc.writeFix32(a, &fix32);

    var dec: Decoder = .init(enc.buf.items);
    try testing.expectEqual(@as(u32, 0xdeadbeef), try dec.readU32());
    try testing.expectEqual(@as(u64, 0x0102030405060708), try dec.readU64());
    try testing.expectEqual(@as(i64, -42), try dec.readI64());
    try testing.expectEqualSlices(u8, "hello", try dec.readBytesValue());
    try testing.expectEqualSlices(u8, "string-utf8-😀", try dec.readString());
    var f16buf: [16]u8 = undefined;
    try dec.readFix16(&f16buf);
    try testing.expectEqualSlices(u8, &fix16, &f16buf);
    var f12buf: [12]u8 = undefined;
    try dec.readFix12(&f12buf);
    try testing.expectEqualSlices(u8, &fix12, &f12buf);
    var f32buf: [32]u8 = undefined;
    try dec.readFix32(&f32buf);
    try testing.expectEqualSlices(u8, &fix32, &f32buf);
    try testing.expect(dec.isExhausted());
}

test "array header" {
    const a = testing.allocator;
    var enc: Encoder = .init(a);
    defer enc.deinit(a);
    try enc.writeArrayHeader(a, 3);
    try enc.writeString(a, "a");
    try enc.writeString(a, "bb");
    try enc.writeString(a, "ccc");

    var dec: Decoder = .init(enc.buf.items);
    try testing.expectEqual(@as(u32, 3), try dec.readArrayHeader());
    try testing.expectEqualSlices(u8, "a", try dec.readString());
    try testing.expectEqualSlices(u8, "bb", try dec.readString());
    try testing.expectEqualSlices(u8, "ccc", try dec.readString());
}

test "tag mismatch is rejected" {
    const a = testing.allocator;
    var enc: Encoder = .init(a);
    defer enc.deinit(a);
    try enc.writeU32(a, 1);

    var dec: Decoder = .init(enc.buf.items);
    try testing.expectError(DecodeError.TagMismatch, dec.readU64());
}

test "truncated input is rejected" {
    const partial: [3]u8 = .{ 0x01, 0xff, 0xff };
    var dec: Decoder = .init(&partial);
    try testing.expectError(DecodeError.Truncated, dec.readU32());
}

test "empty array" {
    const a = testing.allocator;
    var enc: Encoder = .init(a);
    defer enc.deinit(a);
    try enc.writeArrayHeader(a, 0);
    var dec: Decoder = .init(enc.buf.items);
    try testing.expectEqual(@as(u32, 0), try dec.readArrayHeader());
}
