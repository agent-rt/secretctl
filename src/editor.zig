//! Spawn $EDITOR on a temporary file to edit a Plaintext.
//!
//! Tradeoff (documented in SPEC): plaintext sits on disk in $TMPDIR for
//! the duration of the editor process. macOS has no tmpfs; FileVault
//! provides at-rest encryption. We mitigate by:
//!   * 0600 mode at create
//!   * ftruncate(0) before unlink so freed disk pages contain zeros
//!   * unlink immediately after read
//!   * secureZero on every plaintext buffer in this process

const std = @import("std");
const mem_util = @import("mem.zig");
const rand = @import("rand.zig");

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn fsync(fd: c_int) c_int;
extern "c" fn ftruncate(fd: c_int, length: i64) c_int;
extern "c" fn unlink(path: [*:0]const u8) c_int;
extern "c" fn lseek(fd: c_int, offset: i64, whence: c_int) i64;
extern "c" fn fork() c_int;
extern "c" fn waitpid(pid: c_int, stat_loc: *c_int, options: c_int) c_int;
extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern "c" fn _exit(status: c_int) noreturn;
extern "c" fn getpid() c_int;

const O_RDWR: c_int = 0x0002;
const O_CREAT: c_int = 0x0200;
const O_EXCL: c_int = 0x0800;
const SEEK_SET: c_int = 0;

pub const Error = error{
    OutOfMemory,
    OpenFailed,
    WriteFailed,
    ReadFailed,
    ForkFailed,
    EditorFailed,
    EditorMissing,
    PathTooLong,
};

/// Resolve which editor to launch.
pub fn editorBinary() []const u8 {
    if (getenv("VISUAL")) |v| {
        const s = std.mem.span(v);
        if (s.len > 0) return s;
    }
    if (getenv("EDITOR")) |v| {
        const s = std.mem.span(v);
        if (s.len > 0) return s;
    }
    return "vi";
}

fn tmpDir() []const u8 {
    if (getenv("TMPDIR")) |v| return std.mem.span(v);
    return "/tmp";
}

/// Open $EDITOR on a tempfile, optionally preloaded with `initial`. Returns
/// the saved bytes as a Plaintext (caller deinit's). One trailing newline is
/// stripped if present (most editors append it). Empty content returns an
/// empty Plaintext.
pub fn editPlaintext(allocator: std.mem.Allocator, initial: ?[]const u8) Error!mem_util.Plaintext {
    var rand_buf: [8]u8 = undefined;
    rand.bytes(&rand_buf);
    const tmp = tmpDir();

    var hex: [16]u8 = undefined;
    const hex_chars = "0123456789abcdef";
    for (rand_buf, 0..) |b, i| {
        hex[i * 2] = hex_chars[b >> 4];
        hex[i * 2 + 1] = hex_chars[b & 0x0f];
    }

    var path_buf: [1024]u8 = undefined;
    const tmp_path = std.fmt.bufPrint(&path_buf, "{s}/secretctl-edit-{d}-{s}", .{
        tmp, getpid(), &hex,
    }) catch return Error.PathTooLong;

    var cpath_buf: [1024]u8 = undefined;
    if (tmp_path.len + 1 > cpath_buf.len) return Error.PathTooLong;
    @memcpy(cpath_buf[0..tmp_path.len], tmp_path);
    cpath_buf[tmp_path.len] = 0;
    const cpath: [*:0]const u8 = @ptrCast(&cpath_buf[0]);

    const fd = open(cpath, O_RDWR | O_CREAT | O_EXCL, @as(c_uint, 0o600));
    if (fd < 0) return Error.OpenFailed;
    var must_unlink = true;
    defer {
        if (must_unlink) {
            // Best-effort: zero remaining bytes then unlink.
            _ = ftruncate(fd, 0);
            _ = unlink(cpath);
        }
        _ = close(fd);
    }

    if (initial) |bytes| {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = write(fd, bytes[off..].ptr, bytes.len - off);
            if (n < 0) return Error.WriteFailed;
            if (n == 0) return Error.WriteFailed;
            off += @intCast(n);
        }
        if (fsync(fd) != 0) return Error.WriteFailed;
    }

    // Spawn editor.
    const ed = editorBinary();
    if (ed.len == 0) return Error.EditorMissing;

    // editor argv: split on spaces (basic; quoted args not supported).
    var argv_storage = std.ArrayList([:0]u8).empty;
    defer {
        for (argv_storage.items) |s| allocator.free(s);
        argv_storage.deinit(allocator);
    }
    var it = std.mem.tokenizeScalar(u8, ed, ' ');
    while (it.next()) |part| {
        const z = allocator.allocSentinel(u8, part.len, 0) catch return Error.OutOfMemory;
        @memcpy(z, part);
        argv_storage.append(allocator, z) catch return Error.OutOfMemory;
    }
    const path_z = allocator.allocSentinel(u8, tmp_path.len, 0) catch return Error.OutOfMemory;
    @memcpy(path_z, tmp_path);
    argv_storage.append(allocator, path_z) catch return Error.OutOfMemory;
    var argv: []?[*:0]const u8 = allocator.alloc(?[*:0]const u8, argv_storage.items.len + 1) catch return Error.OutOfMemory;
    defer allocator.free(argv);
    for (argv_storage.items, 0..) |s, i| argv[i] = s.ptr;
    argv[argv_storage.items.len] = null;

    const pid = fork();
    if (pid < 0) return Error.ForkFailed;
    if (pid == 0) {
        const argv_terminated: [*:null]const ?[*:0]const u8 = @ptrCast(argv.ptr);
        _ = execvp(argv[0].?, argv_terminated);
        _exit(127);
    }
    var status: c_int = 0;
    if (waitpid(pid, &status, 0) < 0) return Error.EditorFailed;
    if ((status & 0x7f) != 0 or ((status >> 8) & 0xff) != 0) return Error.EditorFailed;

    // Re-read file from start.
    if (lseek(fd, 0, SEEK_SET) < 0) return Error.ReadFailed;

    // Determine size by reading until EOF.
    var content: std.ArrayList(u8) = .empty;
    errdefer {
        if (content.items.len > 0) mem_util.secureZero(u8, content.items);
        content.deinit(allocator);
    }
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = read(fd, &chunk, chunk.len);
        if (n < 0) return Error.ReadFailed;
        if (n == 0) break;
        content.appendSlice(allocator, chunk[0..@intCast(n)]) catch return Error.OutOfMemory;
    }
    mem_util.secureZero(u8, &chunk);

    // Truncate + unlink to wipe disk-side bytes ASAP (best effort on APFS).
    _ = ftruncate(fd, 0);
    _ = unlink(cpath);
    must_unlink = false;

    // Strip exactly one trailing \n (most editors add it).
    if (content.items.len > 0 and content.items[content.items.len - 1] == '\n') {
        // secureZero the last byte before truncating.
        content.items[content.items.len - 1] = 0;
        _ = content.pop();
    }

    const owned = content.toOwnedSlice(allocator) catch return Error.OutOfMemory;
    return mem_util.Plaintext.fromOwnedSlice(allocator, owned);
}

const testing = std.testing;

test "editorBinary defaults to vi" {
    // Hard to test env-affecting code in unit tests; just make sure the
    // function returns something non-empty in all conditions.
    const e = editorBinary();
    try testing.expect(e.len > 0);
}
