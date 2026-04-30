//! Tiny filesystem helpers via libc. macOS-only by project scope.
//! Avoids the std.Io.Dir abstraction since we don't need an Io instance
//! threaded through every CLI entry point.

const std = @import("std");

pub const O_RDONLY: c_int = 0x0000;
pub const O_WRONLY: c_int = 0x0001;
pub const O_RDWR: c_int = 0x0002;
pub const O_CREAT: c_int = 0x0200;
pub const O_EXCL: c_int = 0x0800;
pub const O_TRUNC: c_int = 0x0400;
pub const O_APPEND: c_int = 0x0008;

pub const mode_t = u16;

extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn fsync(fd: c_int) c_int;
extern "c" fn rename(oldpath: [*:0]const u8, newpath: [*:0]const u8) c_int;
extern "c" fn unlink(path: [*:0]const u8) c_int;
extern "c" fn lseek(fd: c_int, offset: i64, whence: c_int) i64;
extern "c" fn mkdir(path: [*:0]const u8, mode: mode_t) c_int;
extern "c" fn stat64(path: [*:0]const u8, statbuf: *anyopaque) c_int;
extern "c" fn fstat64(fd: c_int, statbuf: *anyopaque) c_int;
extern "c" fn fchmod(fd: c_int, mode: mode_t) c_int;
extern "c" fn chmod(path: [*:0]const u8, mode: mode_t) c_int;
extern "c" fn __error() *c_int;

const SEEK_END: c_int = 2;

pub const Error = error{
    OpenFailed,
    ReadFailed,
    WriteFailed,
    FsyncFailed,
    RenameFailed,
    UnlinkFailed,
    MkdirFailed,
    OutOfMemory,
    AlreadyExists,
    NotFound,
    Truncated,
    PathTooLong,
};

const max_path: usize = 1023;

fn toCStr(buf: *[max_path + 1]u8, path: []const u8) Error![*:0]u8 {
    if (path.len > max_path) return Error.PathTooLong;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return @ptrCast(&buf[0]);
}

pub fn fileExists(path: []const u8) bool {
    var pbuf: [max_path + 1]u8 = undefined;
    const cpath = toCStr(&pbuf, path) catch return false;
    var st: [256]u8 align(8) = undefined;
    return stat64(cpath, @ptrCast(&st)) == 0;
}

pub fn mkdirP(path: []const u8, mode: mode_t) Error!void {
    var pbuf: [max_path + 1]u8 = undefined;
    const cpath = try toCStr(&pbuf, path);
    if (mkdir(cpath, mode) != 0) {
        // Already exists is OK.
        const errno = __error().*;
        const EEXIST: c_int = 17;
        if (errno == EEXIST) return;
        return Error.MkdirFailed;
    }
}

/// `mkdir -p` equivalent. Creates `path` and any missing parents using `mode`
/// for newly-created directories. Existing directories are left untouched.
pub fn mkdirAll(path: []const u8, mode: mode_t) Error!void {
    if (path.len == 0) return;
    if (fileExists(path)) return;
    if (std.fs.path.dirname(path)) |parent| {
        if (parent.len > 0 and !fileExists(parent)) try mkdirAll(parent, mode);
    }
    try mkdirP(path, mode);
}

pub fn readAllAlloc(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) Error![]u8 {
    var pbuf: [max_path + 1]u8 = undefined;
    const cpath = try toCStr(&pbuf, path);
    const fd = open(cpath, O_RDONLY);
    if (fd < 0) return Error.OpenFailed;
    defer _ = close(fd);

    const total = lseek(fd, 0, SEEK_END);
    if (total < 0) return Error.ReadFailed;
    if (@as(usize, @intCast(total)) > max_bytes) return Error.OutOfMemory;
    _ = lseek(fd, 0, 0);

    const buf = allocator.alloc(u8, @intCast(total)) catch return Error.OutOfMemory;
    var off: usize = 0;
    while (off < buf.len) {
        const n = read(fd, buf[off..].ptr, buf.len - off);
        if (n < 0) {
            allocator.free(buf);
            return Error.ReadFailed;
        }
        if (n == 0) break;
        off += @intCast(n);
    }
    if (off != buf.len) {
        allocator.free(buf);
        return Error.Truncated;
    }
    return buf;
}

/// Atomic write: tmp + fsync + rename. Mode is applied to the new file.
pub fn writeAllAtomic(path: []const u8, data: []const u8, mode: mode_t) Error!void {
    var pbuf: [max_path + 1]u8 = undefined;
    var tbuf: [max_path + 1]u8 = undefined;
    const cpath = try toCStr(&pbuf, path);
    var tmp_buf: [max_path + 8]u8 = undefined;
    if (path.len + 5 > max_path) return Error.PathTooLong;
    @memcpy(tmp_buf[0..path.len], path);
    @memcpy(tmp_buf[path.len..][0..4], ".tmp");
    const tmp_path = tmp_buf[0 .. path.len + 4];
    const ctmp = try toCStr(&tbuf, tmp_path);

    // Best effort: remove stale tmp.
    _ = unlink(ctmp);

    const fd = open(ctmp, O_WRONLY | O_CREAT | O_EXCL | O_TRUNC, @as(c_uint, mode));
    if (fd < 0) return Error.OpenFailed;
    var ok = false;
    defer {
        _ = close(fd);
        if (!ok) _ = unlink(ctmp);
    }

    if (fchmod(fd, mode) != 0) return Error.WriteFailed;

    var off: usize = 0;
    while (off < data.len) {
        const n = write(fd, data[off..].ptr, data.len - off);
        if (n < 0) return Error.WriteFailed;
        if (n == 0) return Error.WriteFailed;
        off += @intCast(n);
    }
    if (fsync(fd) != 0) return Error.FsyncFailed;
    if (rename(ctmp, cpath) != 0) return Error.RenameFailed;
    ok = true;
}

pub fn unlinkIfExists(path: []const u8) void {
    var pbuf: [max_path + 1]u8 = undefined;
    const cpath = toCStr(&pbuf, path) catch return;
    _ = unlink(cpath);
}

const testing = std.testing;

extern "c" fn getpid() c_int;

test "writeAllAtomic + readAllAlloc round-trip" {
    const a = testing.allocator;
    var pbuf: [256]u8 = undefined;
    const path = try std.fmt.bufPrint(&pbuf, "/tmp/secretctl-test-fsx-{d}", .{getpid()});
    defer unlinkIfExists(path);

    try writeAllAtomic(path, "hello world", 0o600);
    const data = try readAllAlloc(a, path, 1024);
    defer a.free(data);
    try testing.expectEqualSlices(u8, "hello world", data);
}
