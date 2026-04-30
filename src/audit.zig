//! Append-only JSONL audit log. Each event is one line of JSON object with
//! at minimum: ts (ISO8601 UTC), op, transport ("cli"|"mcp"). Optional
//! per-event fields are typed (string / int / bool / string_array).
//!
//! Hard rules:
//!   * never write secret values
//!   * never write full argv (basename only)
//!   * write failures degrade to a stderr warning, never block the caller

const std = @import("std");
const fsx = @import("fsx.zig");
const jsonx = @import("jsonx.zig");

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern "c" fn time(t: ?*i64) i64;
extern "c" fn gmtime_r(t: *const i64, tm: *Tm) ?*Tm;
extern "c" fn snprintf(buf: [*]u8, sz: usize, fmt: [*:0]const u8, ...) c_int;

const Tm = extern struct {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: c_long,
    tm_zone: ?[*:0]const u8,
};

extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const O_WRONLY: c_int = 0x0001;
const O_CREAT: c_int = 0x0200;
const O_APPEND: c_int = 0x0008;

pub const Transport = enum {
    cli,
    mcp,

    pub fn str(self: Transport) []const u8 {
        return switch (self) {
            .cli => "cli",
            .mcp => "mcp",
        };
    }
};

pub const FieldValue = union(enum) {
    string: []const u8,
    int: i64,
    bool_value: bool,
    string_array: []const []const u8,
};

pub const Field = struct {
    key: []const u8,
    value: FieldValue,
};

pub fn s(key: []const u8, value: []const u8) Field {
    return .{ .key = key, .value = .{ .string = value } };
}
pub fn n(key: []const u8, value: i64) Field {
    return .{ .key = key, .value = .{ .int = value } };
}
pub fn b(key: []const u8, value: bool) Field {
    return .{ .key = key, .value = .{ .bool_value = value } };
}
pub fn arr(key: []const u8, value: []const []const u8) Field {
    return .{ .key = key, .value = .{ .string_array = value } };
}

fn defaultLogPath(buf: *[1024]u8) []const u8 {
    const home = if (getenv("HOME")) |h| std.mem.span(h) else "/tmp";
    const subdir = "/Library/Logs";
    const name = "/secretctl.log";
    if (home.len + subdir.len + name.len + 1 >= buf.len) {
        return "/tmp/secretctl.log";
    }
    var w: usize = 0;
    @memcpy(buf[w..][0..home.len], home);
    w += home.len;
    @memcpy(buf[w..][0..subdir.len], subdir);
    w += subdir.len;
    @memcpy(buf[w..][0..name.len], name);
    w += name.len;
    return buf[0..w];
}

fn ensureDir(log_path: []const u8) void {
    const dir = std.fs.path.dirname(log_path) orelse return;
    fsx.mkdirP(dir, 0o700) catch {};
}

fn isoTimestamp(buf: *[32]u8) []const u8 {
    const t = time(null);
    var tm: Tm = undefined;
    if (gmtime_r(&t, &tm) == null) return buf[0..0];
    const len = snprintf(@ptrCast(buf), buf.len, "%04d-%02d-%02dT%02d:%02d:%02dZ", @as(c_int, tm.tm_year + 1900), @as(c_int, tm.tm_mon + 1), tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (len <= 0) return buf[0..0];
    return buf[0..@intCast(len)];
}

/// Write a single audit event as a JSONL line. Failures are warned to
/// stderr but never propagated.
pub fn log(op: []const u8, transport: Transport, fields: []const Field) void {
    var path_buf: [1024]u8 = undefined;
    const path = defaultLogPath(&path_buf);
    logTo(path, op, transport, fields);
}

pub fn logTo(path: []const u8, op: []const u8, transport: Transport, fields: []const Field) void {
    const allocator = std.heap.page_allocator;
    var enc: jsonx.Encoder = .{};
    defer enc.deinit(allocator);

    var ts_buf: [32]u8 = undefined;
    const ts = isoTimestamp(&ts_buf);

    enc.writeByte(allocator, '{') catch return;
    var first = true;
    jsonx.writeKey(&enc, allocator, "ts", &first) catch return;
    enc.writeString(allocator, ts) catch return;
    jsonx.writeKey(&enc, allocator, "op", &first) catch return;
    enc.writeString(allocator, op) catch return;
    jsonx.writeKey(&enc, allocator, "transport", &first) catch return;
    enc.writeString(allocator, transport.str()) catch return;

    for (fields) |f| {
        jsonx.writeKey(&enc, allocator, f.key, &first) catch return;
        switch (f.value) {
            .string => |v| enc.writeString(allocator, v) catch return,
            .int => |v| enc.writeNumber(allocator, v) catch return,
            .bool_value => |v| enc.writeBool(allocator, v) catch return,
            .string_array => |arr_| {
                enc.writeByte(allocator, '[') catch return;
                for (arr_, 0..) |item, idx| {
                    if (idx > 0) enc.writeByte(allocator, ',') catch return;
                    enc.writeString(allocator, item) catch return;
                }
                enc.writeByte(allocator, ']') catch return;
            },
        }
    }
    enc.writeByte(allocator, '}') catch return;
    enc.writeByte(allocator, '\n') catch return;

    ensureDir(path);

    var cpath_buf: [1024]u8 = undefined;
    if (path.len >= cpath_buf.len) return;
    @memcpy(cpath_buf[0..path.len], path);
    cpath_buf[path.len] = 0;
    const cpath: [*:0]const u8 = @ptrCast(&cpath_buf[0]);

    const fd = open(cpath, O_WRONLY | O_CREAT | O_APPEND, @as(c_uint, 0o600));
    if (fd < 0) {
        const msg = "secretctl: audit log write failed (open)\n";
        _ = write(2, msg.ptr, msg.len);
        return;
    }
    defer _ = close(fd);

    var off: usize = 0;
    while (off < enc.buf.items.len) {
        const written = write(fd, enc.buf.items[off..].ptr, enc.buf.items.len - off);
        if (written <= 0) return;
        off += @intCast(written);
    }
}

const testing = std.testing;

extern "c" fn getpid() c_int;

test "log writes JSONL" {
    const a = testing.allocator;
    var pbuf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&pbuf, "/tmp/secretctl-test-audit-{d}.log", .{getpid()});
    defer fsx.unlinkIfExists(path);

    const tags = [_][]const u8{ "npm", "github" };
    logTo(path, "exec", .cli, &.{
        s("cmd", "npm"),
        arr("tags", &tags),
        n("exit", 0),
    });
    logTo(path, "mcp.run_with_secrets", .mcp, &.{
        s("cmd", "yarn"),
        b("truncated", false),
    });

    const data = try fsx.readAllAlloc(a, path, 4096);
    defer a.free(data);

    // Each line should be valid JSON.
    var iter = std.mem.splitScalar(u8, std.mem.trim(u8, data, "\n"), '\n');
    var count: u32 = 0;
    while (iter.next()) |line| {
        if (line.len == 0) continue;
        var p = try jsonx.parse(a, line);
        defer p.deinit();
        const root = p.root();
        try testing.expectEqual(std.json.Value.object, std.meta.activeTag(root));
        count += 1;
    }
    try testing.expectEqual(@as(u32, 2), count);

    // Spot-check field values.
    try testing.expect(std.mem.indexOf(u8, data, "\"transport\":\"cli\"") != null);
    try testing.expect(std.mem.indexOf(u8, data, "\"transport\":\"mcp\"") != null);
    try testing.expect(std.mem.indexOf(u8, data, "\"tags\":[\"npm\",\"github\"]") != null);
    try testing.expect(std.mem.indexOf(u8, data, "\"exit\":0") != null);
    try testing.expect(std.mem.indexOf(u8, data, "\"truncated\":false") != null);
}
