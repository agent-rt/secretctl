//! Append-only plaintext audit log. Phase 1 keeps this dumb on purpose:
//! one line per event, ISO 8601 timestamp, key=value pairs separated by
//! spaces. Values containing whitespace are double-quoted.
//!
//! Hard rules (TECH-DESIGN §17):
//!   * never write secret values
//!   * never write full argv (basename only)
//!   * write failures degrade to a stderr warning, never block the caller

const std = @import("std");
const fsx = @import("fsx.zig");

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

pub const Field = struct {
    key: []const u8,
    value: []const u8,
};

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

extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const O_WRONLY: c_int = 0x0001;
const O_CREAT: c_int = 0x0200;
const O_APPEND: c_int = 0x0008;

fn isoTimestamp(buf: *[32]u8) []const u8 {
    const t = time(null);
    var tm: Tm = undefined;
    if (gmtime_r(&t, &tm) == null) return buf[0..0];
    const n = snprintf(@ptrCast(buf), buf.len, "%04d-%02d-%02dT%02d:%02d:%02dZ", @as(c_int, tm.tm_year + 1900), @as(c_int, tm.tm_mon + 1), tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (n <= 0) return buf[0..0];
    return buf[0..@intCast(n)];
}

fn needsQuoting(s: []const u8) bool {
    if (s.len == 0) return true;
    for (s) |c| {
        if (c == ' ' or c == '\t' or c == '"' or c == '=' or c < 0x20) return true;
    }
    return false;
}

fn appendQuoted(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try out.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => try out.append(allocator, c),
        }
    }
    try out.append(allocator, '"');
}

/// Write a single audit event. Failures are warned to stderr but never
/// propagated.
pub fn log(op: []const u8, fields: []const Field) void {
    var path_buf: [1024]u8 = undefined;
    const path = defaultLogPath(&path_buf);
    logTo(path, op, fields);
}

pub fn logTo(path: []const u8, op: []const u8, fields: []const Field) void {
    const allocator = std.heap.page_allocator;
    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(allocator);

    var ts_buf: [32]u8 = undefined;
    const ts = isoTimestamp(&ts_buf);
    line.appendSlice(allocator, ts) catch return;
    line.append(allocator, ' ') catch return;
    line.appendSlice(allocator, op) catch return;

    for (fields) |f| {
        line.append(allocator, ' ') catch return;
        line.appendSlice(allocator, f.key) catch return;
        line.append(allocator, '=') catch return;
        if (needsQuoting(f.value)) {
            appendQuoted(&line, allocator, f.value) catch return;
        } else {
            line.appendSlice(allocator, f.value) catch return;
        }
    }
    line.append(allocator, '\n') catch return;

    ensureDir(path);

    // O_APPEND ensures atomic line writes among concurrent processes.
    var path_buf: [1024]u8 = undefined;
    if (path.len >= path_buf.len) return;
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;
    const cpath: [*:0]const u8 = @ptrCast(&path_buf[0]);

    const fd = open(cpath, O_WRONLY | O_CREAT | O_APPEND, @as(c_uint, 0o600));
    if (fd < 0) {
        const msg = "secretctl: audit log write failed (open)\n";
        _ = write(2, msg.ptr, msg.len);
        return;
    }
    defer _ = close(fd);

    var off: usize = 0;
    while (off < line.items.len) {
        const n = write(fd, line.items[off..].ptr, line.items.len - off);
        if (n < 0) return;
        if (n == 0) return;
        off += @intCast(n);
    }
}

const testing = std.testing;

extern "c" fn getpid() c_int;

test "log writes to a temp file" {
    const a = testing.allocator;
    var pbuf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&pbuf, "/tmp/secretctl-test-audit-{d}.log", .{getpid()});
    defer fsx.unlinkIfExists(path);

    logTo(path, "exec", &.{
        .{ .key = "cmd", .value = "npm" },
        .{ .key = "tags", .value = "npm,github" },
        .{ .key = "exit", .value = "0" },
    });
    logTo(path, "exec", &.{
        .{ .key = "cmd", .value = "with space" },
    });

    const data = try fsx.readAllAlloc(a, path, 4096);
    defer a.free(data);
    try testing.expect(std.mem.indexOf(u8, data, "exec cmd=npm") != null);
    try testing.expect(std.mem.indexOf(u8, data, "exit=0") != null);
    try testing.expect(std.mem.indexOf(u8, data, "cmd=\"with space\"") != null);
}
