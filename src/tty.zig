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

/// Set when fd 0 is a protocol transport rather than user input — currently
/// the MCP server's JSON-RPC stream. Every routine that reads fd 0 checks it
/// (there are exactly two: readLine and readSecret), so no code path can
/// consume protocol bytes as a password or a secret value.
///
/// This has to be explicit state rather than an isatty() test. `SECRETCTL_BATCH`
/// deliberately reads fd 0 when it is *not* a tty, which is exactly the shape
/// of an MCP pipe, so the two are indistinguishable by inspection.
var stdin_reserved: bool = false;

/// Declare fd 0 off-limits for interactive and batch input. Called once at MCP
/// startup; never cleared.
pub fn reserveStdin() void {
    stdin_reserved = true;
}

pub fn stdinReserved() bool {
    return stdin_reserved;
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
    /// fd 0 carries a protocol stream, not user input. See reserveStdin.
    StdinReserved,
    /// A passphrase is needed but no passphrase channel is configured and no
    /// terminal is available. See passphraseFd.
    PassphraseChannelRequired,
};

/// Read a line from stdin (terminated by newline or EOF). Newline excluded.
/// Returns owned slice. Caller frees.
pub fn readLine(allocator: std.mem.Allocator, max_len: usize) ReadError![]u8 {
    if (stdin_reserved) return ReadError.StdinReserved;
    return readLineFrom(allocator, STDIN, max_len, true);
}

/// Read one newline-terminated line from `fd`. With `editing` the byte stream
/// is interpreted the way a terminal would (backspace erases, Ctrl-D
/// cancels); without it, bytes are taken literally, which is what a data
/// channel needs — a passphrase may legitimately contain 0x7f.
fn readLineFrom(
    allocator: std.mem.Allocator,
    fd: c_int,
    max_len: usize,
    editing: bool,
) ReadError![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var c: [1]u8 = undefined;
    while (true) {
        const n = read(fd, &c, 1);
        if (n < 0) return ReadError.ReadFailed;
        if (n == 0) break; // EOF
        if (c[0] == '\n') break;
        if (editing) {
            if (c[0] == 4) return ReadError.Cancelled; // Ctrl-D
            if (c[0] == 0x7f or c[0] == 0x08) {
                if (buf.items.len > 0) _ = buf.pop();
                continue;
            }
        }
        if (buf.items.len >= max_len) return ReadError.LineTooLong;
        buf.append(allocator, c[0]) catch return ReadError.OutOfMemory;
    }
    return buf.toOwnedSlice(allocator);
}

/// Dedicated passphrase channel: $SECRETCTL_PASSPHRASE_FD=N reads the master
/// passphrase from fd N.
///
/// Why this exists. Batch mode used to take the passphrase from fd 0 as the
/// first line, followed by the secret value — but whether that first line is
/// consumed at all depends on unlock state, because a keychain protector or a
/// warm agent cache satisfies the unlock without any passphrase. When that
/// happens the value slot silently reads the *passphrase* line, so the master
/// passphrase gets stored as a secret and then written out in plaintext by
/// `render`/`materialize`. Confirmed on v0.6.2 via both triggers.
///
/// `SECRETCTL_BATCH_KEYCHAIN` was an attempt to hold the line count stable by
/// disabling the keychain; the agent cache (v0.6.0) then broke it again. Two
/// logical inputs on one unframed channel cannot be made deterministic by
/// disabling whatever might consume one of them, so they get separate
/// channels instead: passphrase on this fd, secret data on fd 0.
fn passphraseFd() ?c_int {
    const v = getenv("SECRETCTL_PASSPHRASE_FD") orelse return null;
    const s = std.mem.span(v);
    if (s.len == 0) return null;
    const n = std.fmt.parseInt(c_int, s, 10) catch return null;
    if (n < 0) return null;
    return n;
}

/// Read a password. stdin must be a tty. Echo is suppressed entirely (no
/// length is leaked on screen) and the buffer is returned as a Plaintext that
/// securely zeros on deinit. Newline ends the input; backspace deletes the
/// previous byte; Ctrl-C/Ctrl-D cancel.
pub fn readPassword(allocator: std.mem.Allocator, prompt: []const u8) ReadError!mem_util.Plaintext {
    if (passphraseFd()) |fd| {
        const line = try readLineFrom(allocator, fd, 4096, false);
        return mem_util.Plaintext.fromOwnedSlice(allocator, line);
    }
    // Deliberately not fd 0: see passphraseFd. Failing here is the point —
    // the alternative is silently consuming a line of secret data.
    if (batchMode()) return ReadError.PassphraseChannelRequired;
    return readSecret(allocator, prompt, false);
}

/// Like readPassword, but echoes a '*' per character so the user gets visual
/// confirmation that input (e.g. a pasted value) was received. Used for the
/// secret-value prompt where feedback matters more than hiding length.
pub fn readMasked(allocator: std.mem.Allocator, prompt: []const u8) ReadError!mem_util.Plaintext {
    return readSecret(allocator, prompt, true);
}

fn readSecret(allocator: std.mem.Allocator, prompt: []const u8, mask: bool) ReadError!mem_util.Plaintext {
    // Before batchMode: batch mode reads fd 0 precisely when it is not a tty,
    // so without this check `SECRETCTL_BATCH=1 secretctl mcp` would consume a
    // JSON-RPC frame as the secret.
    if (stdin_reserved) return ReadError.StdinReserved;
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
                // Erase one mask glyph: back up, overwrite with space, back up.
                if (mask) writeStdout("\x08 \x08");
            }
            continue;
        }
        if (buf.items.len >= 4096) return ReadError.LineTooLong;
        buf.append(allocator, c[0]) catch return ReadError.OutOfMemory;
        if (mask) writeStdout("*");
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
    if (passphraseFd()) |fd| {
        const line = try readLineFrom(allocator, fd, 4096, false);
        return mem_util.Plaintext.fromOwnedSlice(allocator, line);
    }
    if (batchMode()) return ReadError.PassphraseChannelRequired;
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
