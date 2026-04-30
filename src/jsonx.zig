//! JSON helpers built on std.json. Encoding side accumulates into an
//! ArrayList(u8); decoding side wraps std.json.parseFromSlice with a
//! lifetime-managed Parsed value. Adds a base64 helper used by
//! `run_with_secrets` for binary stdout/stderr.

const std = @import("std");

// ------- Encoder -------

pub const Encoder = struct {
    buf: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *Encoder, allocator: std.mem.Allocator) void {
        self.buf.deinit(allocator);
    }

    pub fn toOwnedSlice(self: *Encoder, allocator: std.mem.Allocator) ![]u8 {
        return self.buf.toOwnedSlice(allocator);
    }

    pub fn writeByte(self: *Encoder, allocator: std.mem.Allocator, b: u8) !void {
        try self.buf.append(allocator, b);
    }

    pub fn writeRaw(self: *Encoder, allocator: std.mem.Allocator, s: []const u8) !void {
        try self.buf.appendSlice(allocator, s);
    }

    /// Write a JSON string with proper escaping.
    pub fn writeString(self: *Encoder, allocator: std.mem.Allocator, s: []const u8) !void {
        try self.buf.append(allocator, '"');
        for (s) |c| {
            switch (c) {
                '"' => try self.buf.appendSlice(allocator, "\\\""),
                '\\' => try self.buf.appendSlice(allocator, "\\\\"),
                '\n' => try self.buf.appendSlice(allocator, "\\n"),
                '\r' => try self.buf.appendSlice(allocator, "\\r"),
                '\t' => try self.buf.appendSlice(allocator, "\\t"),
                else => {
                    if (c < 0x20) {
                        var tmp: [6]u8 = undefined;
                        const escaped = std.fmt.bufPrint(&tmp, "\\u{x:0>4}", .{c}) catch unreachable;
                        try self.buf.appendSlice(allocator, escaped);
                    } else {
                        try self.buf.append(allocator, c);
                    }
                },
            }
        }
        try self.buf.append(allocator, '"');
    }

    pub fn writeNumber(self: *Encoder, allocator: std.mem.Allocator, n: i64) !void {
        try self.buf.print(allocator, "{d}", .{n});
    }

    pub fn writeBool(self: *Encoder, allocator: std.mem.Allocator, b: bool) !void {
        try self.buf.appendSlice(allocator, if (b) "true" else "false");
    }

    pub fn writeNull(self: *Encoder, allocator: std.mem.Allocator) !void {
        try self.buf.appendSlice(allocator, "null");
    }
};

/// Write a `"key":` field separator into an encoder. Caller writes the value next.
pub fn writeKey(enc: *Encoder, allocator: std.mem.Allocator, key: []const u8, first: *bool) !void {
    if (!first.*) try enc.writeByte(allocator, ',');
    first.* = false;
    try enc.writeString(allocator, key);
    try enc.writeByte(allocator, ':');
}

// ------- Decoder -------

pub const Parsed = struct {
    inner: std.json.Parsed(std.json.Value),

    pub fn deinit(self: *Parsed) void {
        self.inner.deinit();
    }

    pub fn root(self: *const Parsed) std.json.Value {
        return self.inner.value;
    }
};

pub fn parse(allocator: std.mem.Allocator, src: []const u8) !Parsed {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, src, .{});
    return .{ .inner = parsed };
}

pub fn objectGet(v: std.json.Value, key: []const u8) ?std.json.Value {
    if (v != .object) return null;
    return v.object.get(key);
}

pub fn asString(v: std.json.Value) ?[]const u8 {
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

pub fn asInt(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |n| n,
        else => null,
    };
}

pub fn asBool(v: std.json.Value) ?bool {
    return switch (v) {
        .bool => |b| b,
        else => null,
    };
}

pub fn asArray(v: std.json.Value) ?std.json.Array {
    return switch (v) {
        .array => |a| a,
        else => null,
    };
}

// ------- base64 -------

const b64 = std.base64.standard;

pub fn base64Encode(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    const len = b64.Encoder.calcSize(src.len);
    const out = try allocator.alloc(u8, len);
    _ = b64.Encoder.encode(out, src);
    return out;
}

// ------- tests -------

const testing = std.testing;

test "encode primitives" {
    const a = testing.allocator;
    var enc: Encoder = .{};
    defer enc.deinit(a);
    try enc.writeByte(a, '[');
    try enc.writeNumber(a, 42);
    try enc.writeByte(a, ',');
    try enc.writeBool(a, true);
    try enc.writeByte(a, ',');
    try enc.writeString(a, "hello\nworld");
    try enc.writeByte(a, ']');
    try testing.expectEqualSlices(u8, "[42,true,\"hello\\nworld\"]", enc.buf.items);
}

test "encode object with writeKey" {
    const a = testing.allocator;
    var enc: Encoder = .{};
    defer enc.deinit(a);
    try enc.writeByte(a, '{');
    var first = true;
    try writeKey(&enc, a, "name", &first);
    try enc.writeString(a, "x");
    try writeKey(&enc, a, "n", &first);
    try enc.writeNumber(a, 7);
    try enc.writeByte(a, '}');
    try testing.expectEqualSlices(u8, "{\"name\":\"x\",\"n\":7}", enc.buf.items);
}

test "string escapes" {
    const a = testing.allocator;
    var enc: Encoder = .{};
    defer enc.deinit(a);
    try enc.writeString(a, "tab\there\"quote\\back\x01");
    try testing.expectEqualSlices(u8, "\"tab\\there\\\"quote\\\\back\\u0001\"", enc.buf.items);
}

test "decode object" {
    const a = testing.allocator;
    var p = try parse(a, "{\"name\":\"abc\",\"n\":42,\"ok\":true}");
    defer p.deinit();
    const root = p.root();
    try testing.expectEqualSlices(u8, "abc", asString(objectGet(root, "name").?).?);
    try testing.expectEqual(@as(i64, 42), asInt(objectGet(root, "n").?).?);
    try testing.expect(asBool(objectGet(root, "ok").?).?);
}

test "decode rejects garbage" {
    const a = testing.allocator;
    try testing.expectError(error.SyntaxError, parse(a, "{not json"));
}

test "base64Encode" {
    const a = testing.allocator;
    const out = try base64Encode(a, "hello");
    defer a.free(out);
    try testing.expectEqualSlices(u8, "aGVsbG8=", out);
}
