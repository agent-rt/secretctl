//! Cross-process master-key cache, ssh-agent style.
//!
//! Each `secretctl` command is a separate process, so macOS biometric reuse
//! (which is scoped to a single LAContext / process) cannot suppress repeated
//! Touch ID prompts across commands. This module runs a small long-lived
//! daemon that holds decrypted master keys in RAM only, keyed by
//! `master_key_id`, each with a sliding TTL. The first command unlocks
//! normally (Touch ID / password) and pushes the key to the agent; subsequent
//! commands fetch it from the agent and skip the prompt.
//!
//! Security model:
//!   * Keys live only in the agent's process memory; never written to disk.
//!   * The socket lives in $TMPDIR (a per-user 0700 dir on macOS) and is
//!     additionally chmod'd 0600; connections from other uids are rejected
//!     via getpeereid().
//!   * Entries are secureZero'd on eviction, on STOP, and on idle exit.
//!   * Opt-in: only active when $SECRETCTL_AGENT is set to a non-empty,
//!     non-"0" value. Default behavior (Touch ID every command) is unchanged.

const std = @import("std");
const mem_util = @import("mem.zig");
const aes = @import("aes_gcm.zig");
const clock = @import("clock.zig");

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;
extern "c" fn getuid() u32;
extern "c" fn getpeereid(fd: c_int, euid: *u32, egid: *u32) c_int;
extern "c" fn socket(domain: c_int, type: c_int, protocol: c_int) c_int;
extern "c" fn bind(fd: c_int, addr: *const anyopaque, addrlen: u32) c_int;
extern "c" fn listen(fd: c_int, backlog: c_int) c_int;
extern "c" fn accept(fd: c_int, addr: ?*anyopaque, addrlen: ?*u32) c_int;
extern "c" fn connect(fd: c_int, addr: *const anyopaque, addrlen: u32) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;
extern "c" fn unlink(path: [*:0]const u8) c_int;
extern "c" fn chmod(path: [*:0]const u8, mode: c_uint) c_int;
extern "c" fn poll(fds: *pollfd, nfds: u32, timeout: c_int) c_int;
extern "c" fn fork() c_int;
extern "c" fn setsid() c_int;
extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;
extern "c" fn usleep(usec: u32) c_int;
extern "c" fn _exit(status: c_int) noreturn;

// Darwin socket constants.
const AF_UNIX: c_int = 1;
const SOCK_STREAM: c_int = 1;
const POLLIN: i16 = 0x0001;
const O_RDWR: c_int = 0x0002;

// Darwin sockaddr_un carries a leading length byte (unlike Linux).
const sockaddr_un = extern struct {
    sun_len: u8,
    sun_family: u8,
    sun_path: [104]u8,
};

const pollfd = extern struct {
    fd: c_int,
    events: i16,
    revents: i16,
};

// Wire protocol (fixed-size frames; one request per connection).
const OP_GET: u8 = 1; // [16 id]            -> [1 hit][32 key?]
const OP_PUT: u8 = 2; // [16 id][32 key][4 ttl_le] -> [1 ok]
const OP_DROP: u8 = 3; // [16 id]           -> [1 ok]
const OP_STOP: u8 = 4; // []                -> [1 ok], then exit
const OP_STATUS: u8 = 5; // []              -> [4 count_le]

const id_len = 16;
const key_len = aes.key_len; // 32

const default_ttl: i64 = 300;
const max_entries = 16;

/// True if the agent feature is opted in via $SECRETCTL_AGENT.
pub fn enabled() bool {
    const v = getenv("SECRETCTL_AGENT") orelse return false;
    const s = std.mem.span(v);
    if (s.len == 0) return false;
    if (std.mem.eql(u8, s, "0")) return false;
    return true;
}

/// Sliding TTL in seconds, from $SECRETCTL_AGENT_TTL (default 300, clamped
/// to 1..3600).
pub fn ttlSeconds() i64 {
    const v = getenv("SECRETCTL_AGENT_TTL") orelse return default_ttl;
    const s = std.mem.span(v);
    const n = std.fmt.parseInt(i64, s, 10) catch return default_ttl;
    if (n < 1) return 1;
    if (n > 3600) return 3600;
    return n;
}

/// Fill `buf` with the per-user socket path, returns the slice. The path is
/// scoped by uid so distinct users don't collide on a shared $TMPDIR.
pub fn socketPath(buf: []u8) error{PathTooLong}![]const u8 {
    const tmp: []const u8 = if (getenv("TMPDIR")) |t| blk: {
        const s = std.mem.span(t);
        // Strip a single trailing slash for a clean join.
        break :blk if (s.len > 0 and s[s.len - 1] == '/') s[0 .. s.len - 1] else s;
    } else "/tmp";
    return std.fmt.bufPrint(buf, "{s}/secretctl-agent-{d}.sock", .{ tmp, getuid() }) catch
        error.PathTooLong;
}

fn toCPath(path: []const u8, cbuf: []u8) ?[*:0]const u8 {
    if (path.len + 1 > cbuf.len) return null;
    @memcpy(cbuf[0..path.len], path);
    cbuf[path.len] = 0;
    return @ptrCast(&cbuf[0]);
}

fn fillAddr(addr: *sockaddr_un, cpath: [*:0]const u8, path_len: usize) bool {
    if (path_len + 1 > addr.sun_path.len) return false;
    addr.* = std.mem.zeroes(sockaddr_un);
    addr.sun_len = @intCast(@sizeOf(sockaddr_un));
    addr.sun_family = AF_UNIX;
    @memcpy(addr.sun_path[0..path_len], cpath[0..path_len]);
    return true;
}

fn readExact(fd: c_int, buf: []u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const n = read(fd, buf[off..].ptr, buf.len - off);
        if (n <= 0) return false;
        off += @intCast(n);
    }
    return true;
}

fn writeExact(fd: c_int, buf: []const u8) bool {
    var off: usize = 0;
    while (off < buf.len) {
        const n = write(fd, buf[off..].ptr, buf.len - off);
        if (n <= 0) return false;
        off += @intCast(n);
    }
    return true;
}

/// Connect to a running agent. Returns the connected fd, or -1 if none.
fn dialFd() c_int {
    var pbuf: [128]u8 = undefined;
    const path = socketPath(&pbuf) catch return -1;
    var cbuf: [128]u8 = undefined;
    const cpath = toCPath(path, &cbuf) orelse return -1;

    var addr: sockaddr_un = undefined;
    if (!fillAddr(&addr, cpath, path.len)) return -1;

    const fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, &addr, @sizeOf(sockaddr_un)) != 0) {
        _ = close(fd);
        return -1;
    }
    return fd;
}

// ---------------- client API ----------------

/// Ask the agent for a cached master key. Returns true (key written to
/// `out_key`) on hit. Best-effort: any error / no agent → false.
pub fn cacheGet(id: *const [id_len]u8, out_key: *[key_len]u8) bool {
    const fd = dialFd();
    if (fd < 0) return false;
    defer _ = close(fd);

    var req: [1 + id_len]u8 = undefined;
    req[0] = OP_GET;
    @memcpy(req[1..], id);
    if (!writeExact(fd, &req)) return false;

    var status: [1]u8 = undefined;
    if (!readExact(fd, &status)) return false;
    if (status[0] != 1) return false;
    return readExact(fd, out_key[0..]);
}

/// Push a master key into the agent's cache. Best-effort; ignores failure.
pub fn cachePut(id: *const [id_len]u8, key: *const [key_len]u8, ttl: i64) void {
    const fd = dialFd();
    if (fd < 0) return;
    defer _ = close(fd);

    var req: [1 + id_len + key_len + 4]u8 = undefined;
    req[0] = OP_PUT;
    @memcpy(req[1 .. 1 + id_len], id);
    @memcpy(req[1 + id_len .. 1 + id_len + key_len], key);
    const ttl_u: u32 = if (ttl < 0) 0 else @intCast(@min(ttl, std.math.maxInt(u32)));
    std.mem.writeInt(u32, req[1 + id_len + key_len ..][0..4], ttl_u, .little);
    if (!writeExact(fd, &req)) return;
    var ack: [1]u8 = undefined;
    _ = readExact(fd, &ack);
}

/// Tell a running agent to forget everything and exit. Returns true if an
/// agent acknowledged.
pub fn stopRunning() bool {
    const fd = dialFd();
    if (fd < 0) return false;
    defer _ = close(fd);
    const req = [_]u8{OP_STOP};
    if (!writeExact(fd, &req)) return false;
    var ack: [1]u8 = undefined;
    return readExact(fd, &ack);
}

/// Query how many keys a running agent currently holds. Returns null if no
/// agent is reachable.
pub fn statusCount() ?u32 {
    const fd = dialFd();
    if (fd < 0) return null;
    defer _ = close(fd);
    const req = [_]u8{OP_STATUS};
    if (!writeExact(fd, &req)) return null;
    var resp: [4]u8 = undefined;
    if (!readExact(fd, &resp)) return null;
    return std.mem.readInt(u32, &resp, .little);
}

/// If no agent is reachable, fork one into the background and wait briefly for
/// its socket to come up. Best-effort and idempotent; safe to call before
/// every unlock when the feature is enabled.
pub fn ensureRunning() void {
    const probe = dialFd();
    if (probe >= 0) {
        _ = close(probe);
        return;
    }

    const pid = fork();
    if (pid < 0) return;
    if (pid == 0) {
        // Child: detach from the controlling terminal and stdio, then serve.
        _ = setsid();
        const devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            _ = dup2(devnull, 0);
            _ = dup2(devnull, 1);
            _ = dup2(devnull, 2);
            if (devnull > 2) _ = close(devnull);
        }
        serve(false) catch {};
        _exit(0);
    }

    // Parent: poll for the socket to accept connections (~up to 500ms).
    var tries: u32 = 0;
    while (tries < 50) : (tries += 1) {
        const fd = dialFd();
        if (fd >= 0) {
            _ = close(fd);
            return;
        }
        _ = usleep(10_000);
    }
}

// ---------------- server ----------------

const Entry = struct {
    used: bool = false,
    id: [id_len]u8 = undefined,
    key: [key_len]u8 = undefined,
    ttl: i64 = 0,
    expiry: i64 = 0,
};

const Store = struct {
    entries: [max_entries]Entry = [_]Entry{.{}} ** max_entries,

    fn evictExpired(self: *Store, now: i64) void {
        for (&self.entries) |*e| {
            if (e.used and now >= e.expiry) self.clearEntry(e);
        }
    }

    fn clearEntry(self: *Store, e: *Entry) void {
        _ = self;
        mem_util.secureZero(u8, &e.key);
        e.used = false;
    }

    fn count(self: *const Store) u32 {
        var n: u32 = 0;
        for (self.entries) |e| {
            if (e.used) n += 1;
        }
        return n;
    }

    /// Look up by id; on hit, slide the expiry forward and return the key.
    fn get(self: *Store, id: *const [id_len]u8, now: i64) ?*[key_len]u8 {
        for (&self.entries) |*e| {
            if (e.used and std.mem.eql(u8, &e.id, id)) {
                e.expiry = now + e.ttl;
                return &e.key;
            }
        }
        return null;
    }

    fn put(self: *Store, id: *const [id_len]u8, key: *const [key_len]u8, ttl: i64, now: i64) void {
        const eff_ttl = if (ttl <= 0) default_ttl else ttl;
        // Replace existing entry for this id if present.
        var slot: ?*Entry = null;
        for (&self.entries) |*e| {
            if (e.used and std.mem.eql(u8, &e.id, id)) {
                slot = e;
                break;
            }
        }
        if (slot == null) {
            for (&self.entries) |*e| {
                if (!e.used) {
                    slot = e;
                    break;
                }
            }
        }
        // No free slot: overwrite the soonest-to-expire entry.
        if (slot == null) {
            var victim: *Entry = &self.entries[0];
            for (&self.entries) |*e| {
                if (e.expiry < victim.expiry) victim = e;
            }
            self.clearEntry(victim);
            slot = victim;
        }
        const e = slot.?;
        @memcpy(&e.id, id);
        @memcpy(&e.key, key);
        e.ttl = eff_ttl;
        e.expiry = now + eff_ttl;
        e.used = true;
    }

    fn clearAll(self: *Store) void {
        for (&self.entries) |*e| {
            if (e.used) self.clearEntry(e);
        }
    }
};

pub const ServeError = error{
    AlreadyRunning,
    SocketFailed,
    BindFailed,
    PathTooLong,
};

/// Run the agent loop. Binds the per-user socket, serves requests until a STOP
/// arrives or the cache sits empty for one TTL window, then cleans up. When
/// `foreground` is true, prints the socket path on startup.
pub fn serve(foreground: bool) ServeError!void {
    var pbuf: [128]u8 = undefined;
    const path = socketPath(&pbuf) catch return error.PathTooLong;
    var cbuf: [128]u8 = undefined;
    const cpath = toCPath(path, &cbuf) orelse return error.PathTooLong;

    // If a live agent already owns the socket, don't take over.
    const existing = dialFd();
    if (existing >= 0) {
        _ = close(existing);
        return error.AlreadyRunning;
    }
    // Remove a stale socket left by a crashed agent before binding.
    _ = unlink(cpath);

    const lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) return error.SocketFailed;
    defer _ = close(lfd);

    var addr: sockaddr_un = undefined;
    if (!fillAddr(&addr, cpath, path.len)) return error.PathTooLong;
    if (bind(lfd, &addr, @sizeOf(sockaddr_un)) != 0) return error.BindFailed;
    _ = chmod(cpath, 0o600);
    if (listen(lfd, 8) != 0) return error.BindFailed;

    defer _ = unlink(cpath);

    if (foreground) {
        var msg: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&msg, "secretctl agent listening on {s}\n", .{path}) catch path;
        _ = write(1, line.ptr, line.len);
    }

    var store = Store{};
    defer store.clearAll();

    const ttl_ms: c_int = @intCast(@min(ttlSeconds() * 1000, @as(i64, std.math.maxInt(c_int))));
    const my_uid = getuid();

    while (true) {
        store.evictExpired(clock.unixSeconds());

        var pfd = pollfd{ .fd = lfd, .events = POLLIN, .revents = 0 };
        const pr = poll(&pfd, 1, ttl_ms);
        if (pr == 0) {
            // Idle for a full TTL window. Exit if nothing left to protect.
            store.evictExpired(clock.unixSeconds());
            if (store.count() == 0) break;
            continue;
        }
        if (pr < 0) continue; // EINTR etc.

        const conn = accept(lfd, null, null);
        if (conn < 0) continue;
        const stop = handleConn(&store, conn, my_uid);
        _ = close(conn);
        if (stop) break;
    }
}

/// Handle one connection. Returns true if the agent should stop.
fn handleConn(store: *Store, conn: c_int, my_uid: u32) bool {
    // Reject peers from other uids.
    var peer_uid: u32 = undefined;
    var peer_gid: u32 = undefined;
    if (getpeereid(conn, &peer_uid, &peer_gid) != 0 or peer_uid != my_uid) return false;

    var op: [1]u8 = undefined;
    if (!readExact(conn, &op)) return false;
    const now = clock.unixSeconds();

    switch (op[0]) {
        OP_GET => {
            var id: [id_len]u8 = undefined;
            if (!readExact(conn, &id)) return false;
            if (store.get(&id, now)) |key| {
                var resp: [1 + key_len]u8 = undefined;
                resp[0] = 1;
                @memcpy(resp[1..], key);
                _ = writeExact(conn, &resp);
                mem_util.secureZero(u8, &resp);
            } else {
                _ = writeExact(conn, &[_]u8{0});
            }
            return false;
        },
        OP_PUT => {
            var payload: [id_len + key_len + 4]u8 = undefined;
            if (!readExact(conn, &payload)) return false;
            const id: *const [id_len]u8 = payload[0..id_len];
            const key: *const [key_len]u8 = payload[id_len .. id_len + key_len];
            const ttl = std.mem.readInt(u32, payload[id_len + key_len ..][0..4], .little);
            store.put(id, key, @intCast(ttl), now);
            mem_util.secureZero(u8, &payload);
            _ = writeExact(conn, &[_]u8{1});
            return false;
        },
        OP_DROP => {
            var id: [id_len]u8 = undefined;
            if (!readExact(conn, &id)) return false;
            for (&store.entries) |*e| {
                if (e.used and std.mem.eql(u8, &e.id, &id)) store.clearEntry(e);
            }
            _ = writeExact(conn, &[_]u8{1});
            return false;
        },
        OP_STATUS => {
            var resp: [4]u8 = undefined;
            std.mem.writeInt(u32, &resp, store.count(), .little);
            _ = writeExact(conn, &resp);
            return false;
        },
        OP_STOP => {
            _ = writeExact(conn, &[_]u8{1});
            return true;
        },
        else => return false,
    }
}

const testing = std.testing;

test "store put/get/evict with sliding ttl" {
    var s = Store{};
    var id = [_]u8{0xab} ** id_len;
    var key = [_]u8{0xcd} ** key_len;

    s.put(&id, &key, 100, 1000);
    try testing.expectEqual(@as(u32, 1), s.count());

    // Hit slides expiry forward from the access time.
    const got = s.get(&id, 1050).?;
    try testing.expectEqualSlices(u8, &key, got);
    try testing.expectEqual(@as(i64, 1150), s.entries[0].expiry);

    // Not yet expired.
    s.evictExpired(1100);
    try testing.expectEqual(@as(u32, 1), s.count());

    // Past the slid expiry → evicted and zeroed.
    s.evictExpired(1200);
    try testing.expectEqual(@as(u32, 0), s.count());
    try testing.expect(s.get(&id, 1200) == null);
}

test "store replaces same id and evicts soonest when full" {
    var s = Store{};
    // Fill all slots with increasing expiry.
    var i: u8 = 0;
    while (i < max_entries) : (i += 1) {
        var id = [_]u8{i} ** id_len;
        var key = [_]u8{i} ** key_len;
        s.put(&id, &key, @as(i64, i) + 1, 1000);
    }
    try testing.expectEqual(@as(u32, max_entries), s.count());

    // New id evicts the soonest-to-expire (id 0, ttl 1 → expiry 1001).
    var nid = [_]u8{0xff} ** id_len;
    var nkey = [_]u8{0xff} ** key_len;
    s.put(&nid, &nkey, 999, 1000);
    try testing.expectEqual(@as(u32, max_entries), s.count());
    var zero = [_]u8{0} ** id_len;
    try testing.expect(s.get(&zero, 1000) == null); // id 0 gone
    try testing.expect(s.get(&nid, 1000) != null); // new present
}

test "ttlSeconds clamps and defaults" {
    // No env in test → default.
    try testing.expectEqual(@as(i64, 300), ttlSeconds());
}

test "socketPath builds a uid-scoped path" {
    var buf: [128]u8 = undefined;
    const p = try socketPath(&buf);
    try testing.expect(std.mem.indexOf(u8, p, "secretctl-agent-") != null);
    try testing.expect(std.mem.endsWith(u8, p, ".sock"));
}
