//! Minimal terminal helpers. We deliberately avoid a full TUI library for
//! Phase 1 — password & value entry only need non-echoing line read, list
//! output is plain stdout. This keeps the binary small and the cognitive
//! load low.
//!
//! All routines are macOS-specific (termios layout, isatty(3)).

const std = @import("std");
const mem_util = @import("mem.zig");

const STDIN: c_int = 0;
const STDOUT: c_int = 1;
const STDERR: c_int = 2;

extern "c" fn isatty(fd: c_int) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

fn batchMode() bool {
    return getenv("SECRETCTL_BATCH") != null;
}

const tcflag_t = u64;
const cc_t = u8;
const speed_t = u64;
const NCCS: usize = 20;

const termios = extern struct {
    c_iflag: tcflag_t,
    c_oflag: tcflag_t,
    c_cflag: tcflag_t,
    c_lflag: tcflag_t,
    c_cc: [NCCS]cc_t,
    c_ispeed: speed_t,
    c_ospeed: speed_t,
};

const ECHO: tcflag_t = 0x00000008;
const ICANON: tcflag_t = 0x00000100;
const ISIG: tcflag_t = 0x00000080;
const TCSANOW: c_int = 0;
const TCSAFLUSH: c_int = 2;

extern "c" fn tcgetattr(fd: c_int, t: *termios) c_int;
extern "c" fn tcsetattr(fd: c_int, optional_actions: c_int, t: *const termios) c_int;

pub fn isStdinTty() bool {
    return isatty(STDIN) != 0;
}

pub fn isStdoutTty() bool {
    return isatty(STDOUT) != 0;
}

pub fn writeStdout(bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = write(STDOUT, bytes[off..].ptr, bytes.len - off);
        if (n <= 0) return;
        off += @intCast(n);
    }
}

pub fn writeStderr(bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = write(STDERR, bytes[off..].ptr, bytes.len - off);
        if (n <= 0) return;
        off += @intCast(n);
    }
}

pub const ReadError = error{
    ReadFailed,
    NoTty,
    OutOfMemory,
    Cancelled,
    LineTooLong,
};

/// Read a line from stdin (terminated by newline or EOF). Newline excluded.
/// Returns owned slice. Caller frees.
pub fn readLine(allocator: std.mem.Allocator, max_len: usize) ReadError![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var c: [1]u8 = undefined;
    while (true) {
        const n = read(STDIN, &c, 1);
        if (n < 0) return ReadError.ReadFailed;
        if (n == 0) break; // EOF
        if (c[0] == '\n') break;
        if (c[0] == 4) return ReadError.Cancelled; // Ctrl-D
        if (c[0] == 0x7f or c[0] == 0x08) {
            if (buf.items.len > 0) _ = buf.pop();
            continue;
        }
        if (buf.items.len >= max_len) return ReadError.LineTooLong;
        buf.append(allocator, c[0]) catch return ReadError.OutOfMemory;
    }
    return buf.toOwnedSlice(allocator);
}

/// Read a password. stdin must be a tty. Echo is suppressed and the buffer
/// is returned as a Plaintext that securely zeros on deinit. Newline ends
/// the input; backspace deletes the previous byte; Ctrl-C/Ctrl-D cancel.
pub fn readPassword(allocator: std.mem.Allocator, prompt: []const u8) ReadError!mem_util.Plaintext {
    if (batchMode()) {
        const line = try readLine(allocator, 4096);
        return mem_util.Plaintext.fromOwnedSlice(allocator, line);
    }
    if (!isStdinTty()) return ReadError.NoTty;
    if (prompt.len > 0) writeStdout(prompt);

    var orig: termios = undefined;
    if (tcgetattr(STDIN, &orig) != 0) return ReadError.ReadFailed;
    var raw = orig;
    raw.c_lflag &= ~(ECHO);
    if (tcsetattr(STDIN, TCSAFLUSH, &raw) != 0) return ReadError.ReadFailed;
    defer _ = tcsetattr(STDIN, TCSAFLUSH, &orig);

    var buf: std.ArrayList(u8) = .empty;
    errdefer {
        // Securely clear before any path that propagates the error.
        if (buf.items.len > 0) mem_util.secureZero(u8, buf.items);
        buf.deinit(allocator);
    }
    var c: [1]u8 = undefined;
    while (true) {
        const n = read(STDIN, &c, 1);
        if (n < 0) return ReadError.ReadFailed;
        if (n == 0) break;
        if (c[0] == '\n' or c[0] == '\r') break;
        if (c[0] == 4) return ReadError.Cancelled;
        if (c[0] == 0x03) return ReadError.Cancelled;
        if (c[0] == 0x7f or c[0] == 0x08) {
            if (buf.items.len > 0) {
                buf.items[buf.items.len - 1] = 0;
                _ = buf.pop();
            }
            continue;
        }
        if (buf.items.len >= 4096) return ReadError.LineTooLong;
        buf.append(allocator, c[0]) catch return ReadError.OutOfMemory;
    }
    writeStdout("\n");
    const owned = buf.toOwnedSlice(allocator) catch return ReadError.OutOfMemory;
    return mem_util.Plaintext.fromOwnedSlice(allocator, owned);
}

/// Prompt for a password twice; require equal inputs and minimum length.
pub fn readNewPassword(
    allocator: std.mem.Allocator,
    min_len: usize,
) ReadError!mem_util.Plaintext {
    if (batchMode()) {
        const line = try readLine(allocator, 4096);
        return mem_util.Plaintext.fromOwnedSlice(allocator, line);
    }
    while (true) {
        var p1 = try readPassword(allocator, "Master password: ");
        if (p1.len() < min_len) {
            writeStderr("password too short, try again\n");
            p1.deinit();
            continue;
        }
        var p2 = try readPassword(allocator, "Confirm password: ");
        if (!std.mem.eql(u8, p1.bytes, p2.bytes)) {
            writeStderr("passwords do not match, try again\n");
            p1.deinit();
            p2.deinit();
            continue;
        }
        p2.deinit();
        return p1;
    }
}

/// Yes/no prompt; returns true on yes, false on no, default applies on empty.
pub fn confirm(prompt: []const u8, default_yes: bool) ReadError!bool {
    const a = std.heap.page_allocator;
    writeStdout(prompt);
    if (default_yes) writeStdout(" [Y/n] ") else writeStdout(" [y/N] ");
    const line = readLine(a, 16) catch |e| switch (e) {
        ReadError.LineTooLong => return false,
        else => return e,
    };
    defer a.free(line);
    if (line.len == 0) return default_yes;
    return line[0] == 'y' or line[0] == 'Y';
}
