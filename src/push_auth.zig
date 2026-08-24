//! Out-of-band approval client: the Mac half of `docs/2fa-push-approval.md`.
//!
//! Wire protocol and reasoning live in that document and in the reference
//! client it mirrors. The properties this file is responsible for, and which
//! the rest of the design rests on:
//!
//!   * every verdict is verified against a key **pinned at pairing**, never
//!     against whatever the service reports. A service that fabricates an
//!     approval produces a signature this refuses.
//!   * a pinned key never changes in place. A different key for a device
//!     already pinned is a substitution, not an update, and is refused.
//!   * the request body is sealed per device, so the relay stores an opaque
//!     blob and a second phone can still answer (nudge DESIGN §18).
//!   * everything fails closed. No error path yields "approved".

const std = @import("std");
const p256 = @import("p256.zig");
const http = @import("http.zig");
const jsonx = @import("jsonx.zig");
const fsx = @import("fsx.zig");
const clock = @import("clock.zig");
const rand = @import("rand.zig");
const tty = @import("tty.zig");
const mem_util = @import("mem.zig");
const audit = @import("audit.zig");

pub const Error = error{
    NotConfigured,
    NoPinnedDevice,
    /// A pinned device's key changed. Never an update; always a substitution.
    KeySubstituted,
    ServiceRejected,
    BadResponse,
    Denied,
    Expired,
    /// The verdict's signature did not verify against the pinned key.
    ForgedVerdict,
    OutOfMemory,
};

/// Bounded so a stuck approval cannot hold a command open forever.
pub const default_timeout_s: u32 = 120;
/// Must exceed the service's own hold (25 s) or every wait looks like a timeout.
const wait_http_timeout_ms: c_int = 32_000;

pub const Device = struct {
    device_id: []const u8,
    sign_pubkey: []const u8,
    seal_pubkey: []const u8,
    fingerprint: []const u8,
    label: []const u8,
};

pub const Config = struct {
    worker_url: []const u8,
    app_id: []const u8,
    client_id: []const u8,
    /// 32-byte ECDSA seed, base64url. Authenticates calls to the relay and
    /// grants nothing else — it cannot decrypt a secret, so it lives in the
    /// 0600 config rather than the keychain.
    client_secret: []const u8,
    devices: []Device,
    timeout_s: u32 = default_timeout_s,

    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Config) void {
        self.arena.deinit();
    }

    /// The config's own arena.
    ///
    /// Always go through this rather than keeping a separate handle to the
    /// arena the Config was built from. An ArenaAllocator held by value carries
    /// its state inline, so allocating through a *copy* made before the
    /// allocation leaves the struct's copy empty and its deinit freeing
    /// nothing. Taking the allocator from the struct makes that impossible.
    pub fn alloc(self: *Config) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn keyPair(self: *const Config) !p256.KeyPair {
        var seed_buf: [64]u8 = undefined;
        const n = try p256.b64u.Decoder.calcSizeForSlice(self.client_secret);
        if (n != 32) return Error.NotConfigured;
        try p256.b64u.Decoder.decode(seed_buf[0..n], self.client_secret);
        defer mem_util.secureZero(u8, seed_buf[0..n]);
        return p256.KeyPair.fromSeed(seed_buf[0..32].*);
    }
};

fn configPath(allocator: std.mem.Allocator, home: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/push.json", .{home});
}

pub fn configured(home: []const u8) bool {
    var buf: [1024]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/push.json", .{home}) catch return false;
    return fsx.fileExists(path);
}

pub fn load(allocator: std.mem.Allocator, home: []const u8) !Config {
    const path = try configPath(allocator, home);
    defer allocator.free(path);
    if (!fsx.fileExists(path)) return Error.NotConfigured;

    const raw = try fsx.readAllAlloc(allocator, path, 256 * 1024);
    defer allocator.free(raw);

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var parsed = try jsonx.parse(a, raw);
    const root = parsed.root();

    const str = struct {
        fn get(v: std.json.Value, key: []const u8, al: std.mem.Allocator) ![]const u8 {
            const f = jsonx.objectGet(v, key) orelse return Error.BadResponse;
            return al.dupe(u8, jsonx.asString(f) orelse return Error.BadResponse);
        }
    }.get;

    var devices: std.ArrayList(Device) = .empty;
    if (jsonx.objectGet(root, "devices")) |d| {
        if (d == .array) {
            for (d.array.items) |item| {
                try devices.append(a, .{
                    .device_id = try str(item, "device_id", a),
                    .sign_pubkey = try str(item, "sign_pubkey", a),
                    .seal_pubkey = try str(item, "seal_pubkey", a),
                    .fingerprint = try str(item, "fingerprint", a),
                    .label = str(item, "label", a) catch try a.dupe(u8, "device"),
                });
            }
        }
    }

    return .{
        .worker_url = try str(root, "worker_url", a),
        .app_id = try str(root, "app_id", a),
        .client_id = try str(root, "client_id", a),
        .client_secret = try str(root, "client_secret", a),
        .devices = try devices.toOwnedSlice(a),
        .timeout_s = if (jsonx.objectGet(root, "timeout_s")) |t|
            @intCast(jsonx.asInt(t) orelse default_timeout_s)
        else
            default_timeout_s,
        .arena = arena,
    };
}

pub fn save(allocator: std.mem.Allocator, home: []const u8, cfg: *const Config) !void {
    var enc: jsonx.Encoder = .{};
    defer enc.deinit(allocator);

    try enc.writeRaw(allocator, "{\n  \"worker_url\": ");
    try enc.writeString(allocator, cfg.worker_url);
    try enc.writeRaw(allocator, ",\n  \"app_id\": ");
    try enc.writeString(allocator, cfg.app_id);
    try enc.writeRaw(allocator, ",\n  \"client_id\": ");
    try enc.writeString(allocator, cfg.client_id);
    try enc.writeRaw(allocator, ",\n  \"client_secret\": ");
    try enc.writeString(allocator, cfg.client_secret);
    try enc.writeRaw(allocator, ",\n  \"timeout_s\": ");
    try enc.writeNumber(allocator, cfg.timeout_s);
    try enc.writeRaw(allocator, ",\n  \"devices\": [");
    for (cfg.devices, 0..) |d, i| {
        if (i > 0) try enc.writeRaw(allocator, ",");
        try enc.writeRaw(allocator, "\n    {\"device_id\": ");
        try enc.writeString(allocator, d.device_id);
        try enc.writeRaw(allocator, ", \"sign_pubkey\": ");
        try enc.writeString(allocator, d.sign_pubkey);
        try enc.writeRaw(allocator, ", \"seal_pubkey\": ");
        try enc.writeString(allocator, d.seal_pubkey);
        try enc.writeRaw(allocator, ", \"fingerprint\": ");
        try enc.writeString(allocator, d.fingerprint);
        try enc.writeRaw(allocator, ", \"label\": ");
        try enc.writeString(allocator, d.label);
        try enc.writeRaw(allocator, "}");
    }
    try enc.writeRaw(allocator, "\n  ]\n}\n");

    const path = try configPath(allocator, home);
    defer allocator.free(path);
    const body = try enc.toOwnedSlice(allocator);
    defer allocator.free(body);
    // 0600: it holds the relay identity. Not vault-critical, but nothing here
    // needs to be world-readable either.
    try fsx.writeAllAtomic(path, body, 0o600);
}

// ---------- signed calls ----------

fn signedCall(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    op: []const u8,
    method: []const u8,
    path: []const u8,
    body: []const u8,
    timeout_ms: c_int,
) !http.Response {
    const kp = try cfg.keyPair();
    const ts = clock.unixSeconds();

    const body_hash = try p256.sha256b64u(allocator, body);
    defer allocator.free(body_hash);
    const canonical = try p256.canonicalCall(allocator, op, cfg.client_id, ts, body_hash);
    defer allocator.free(canonical);
    const sig = try kp.sign(canonical);
    const sig_b64 = try p256.b64uEncodeAlloc(allocator, &sig);
    defer allocator.free(sig_b64);

    var ts_buf: [24]u8 = undefined;
    const ts_str = try std.fmt.bufPrint(&ts_buf, "{d}", .{ts});

    const headers = try http.headerList(allocator, &.{
        .{ "X-Nudge-Client", cfg.client_id },
        .{ "X-Nudge-Ts", ts_str },
        .{ "X-Nudge-Sig", sig_b64 },
        .{ "content-type", "application/json" },
    });
    defer allocator.free(headers);

    const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ cfg.worker_url, path });
    defer allocator.free(url);

    return http.send(allocator, .{
        .method = method,
        .url = url,
        .headers = headers,
        .body = body,
        .timeout_ms = timeout_ms,
    });
}

// ---------- enrolment ----------

pub const Enrolment = struct {
    pairing_code: [64]u8,
    pairing_code_len: usize,
    expires_in_s: i64,

    pub fn code(self: *const Enrolment) []const u8 {
        return self.pairing_code[0..self.pairing_code_len];
    }
};

/// Register this machine as a client and write the config.
///
/// The enrolment token is presented once and never stored: it authorises
/// creating a client under an app, and keeping it on disk would let anyone who
/// reads the config enrol further clients. The client keypair generated here is
/// what authenticates afterwards.
pub fn enroll(
    allocator: std.mem.Allocator,
    home: []const u8,
    worker_url: []const u8,
    app_id: []const u8,
    enrol_token: []const u8,
    label: []const u8,
) !Enrolment {
    const kp = p256.KeyPair.generate();
    const secret = kp.secretBytes();
    const pub_bytes = kp.publicBytes();

    const pub_b64 = try p256.b64uEncodeAlloc(allocator, &pub_bytes);
    defer allocator.free(pub_b64);
    const secret_b64 = try p256.b64uEncodeAlloc(allocator, &secret);
    defer {
        mem_util.secureZero(u8, secret_b64);
        allocator.free(secret_b64);
    }

    var enc: jsonx.Encoder = .{};
    defer enc.deinit(allocator);
    try enc.writeRaw(allocator, "{\"app_id\":");
    try enc.writeString(allocator, app_id);
    try enc.writeRaw(allocator, ",\"pubkey\":");
    try enc.writeString(allocator, pub_b64);
    try enc.writeRaw(allocator, ",\"label\":");
    try enc.writeString(allocator, label);
    try enc.writeRaw(allocator, "}");
    const body = try enc.toOwnedSlice(allocator);
    defer allocator.free(body);

    const auth = try std.fmt.allocPrint(allocator, "Bearer {s}", .{enrol_token});
    defer allocator.free(auth);
    const headers = try http.headerList(allocator, &.{
        .{ "authorization", auth },
        .{ "content-type", "application/json" },
    });
    defer allocator.free(headers);
    const url = try std.fmt.allocPrint(allocator, "{s}/v1/clients", .{worker_url});
    defer allocator.free(url);

    const res = try http.send(allocator, .{
        .method = "POST", .url = url, .headers = headers,
        .body = body, .timeout_ms = 15_000,
    });
    defer res.deinit(allocator);
    if (!res.ok()) return Error.ServiceRejected;

    var parsed = try jsonx.parse(allocator, res.body);
    defer parsed.deinit();
    const root = parsed.root();
    const client_id = jsonx.asString(jsonx.objectGet(root, "client_id") orelse return Error.BadResponse) orelse return Error.BadResponse;
    const code = jsonx.asString(jsonx.objectGet(root, "pairing_code") orelse return Error.BadResponse) orelse return Error.BadResponse;
    const ttl = if (jsonx.objectGet(root, "pairing_expires_in_s")) |t| (jsonx.asInt(t) orelse 600) else 600;

    var cfg = Config{
        .worker_url = "",
        .app_id = "",
        .client_id = "",
        .client_secret = "",
        .devices = &.{},
        .arena = std.heap.ArenaAllocator.init(allocator),
    };
    errdefer cfg.deinit();
    const a = cfg.alloc();
    cfg.worker_url = try a.dupe(u8, worker_url);
    cfg.app_id = try a.dupe(u8, app_id);
    cfg.client_id = try a.dupe(u8, client_id);
    cfg.client_secret = try a.dupe(u8, secret_b64);
    try save(allocator, home, &cfg);
    cfg.deinit();

    var out = Enrolment{ .pairing_code = undefined, .pairing_code_len = 0, .expires_in_s = ttl };
    const n = @min(code.len, out.pairing_code.len);
    @memcpy(out.pairing_code[0..n], code[0..n]);
    out.pairing_code_len = n;
    return out;
}

// ---------- pairing ----------

pub const PairingResult = struct {
    paired: bool,
    newly_pinned: usize,
};

/// Poll for pairing and pin every device the service reports.
///
/// Pins the whole set, not the first: any paired device may answer, so a single
/// pinned key would reject a genuine verdict from the second phone. That was a
/// real bug in the reference client, invisible until a second device existed.
pub fn refreshDevices(
    allocator: std.mem.Allocator,
    home: []const u8,
    cfg: *Config,
) !PairingResult {
    const path = try std.fmt.allocPrint(allocator, "/v1/clients/{s}/pairing", .{cfg.client_id});
    defer allocator.free(path);

    const res = try signedCall(allocator, cfg, "pairing", "GET", path, "", 15_000);
    defer res.deinit(allocator);
    if (!res.ok()) return Error.ServiceRejected;

    var parsed = try jsonx.parse(allocator, res.body);
    defer parsed.deinit();
    const list = jsonx.objectGet(parsed.root(), "devices") orelse return Error.BadResponse;
    if (list != .array) return Error.BadResponse;

    const a = cfg.alloc();
    var out: std.ArrayList(Device) = .empty;
    var newly: usize = 0;

    for (list.array.items) |item| {
        const id = jsonx.asString(jsonx.objectGet(item, "device_id") orelse return Error.BadResponse) orelse return Error.BadResponse;
        const sign = jsonx.asString(jsonx.objectGet(item, "sign_pubkey") orelse return Error.BadResponse) orelse return Error.BadResponse;
        const seal_pk = jsonx.asString(jsonx.objectGet(item, "seal_pubkey") orelse return Error.BadResponse) orelse return Error.BadResponse;
        const fp = jsonx.asString(jsonx.objectGet(item, "fingerprint") orelse return Error.BadResponse) orelse return Error.BadResponse;
        const label = if (jsonx.objectGet(item, "label")) |l| (jsonx.asString(l) orelse "device") else "device";

        // A key that differs for a device already pinned is a substitution.
        // Refuse loudly rather than accepting an "update": accepting it would
        // hand the relay the ability to swap in its own key at any time, which
        // is the single thing pinning exists to prevent.
        for (cfg.devices) |old| {
            if (std.mem.eql(u8, old.device_id, id)) {
                if (!std.mem.eql(u8, old.sign_pubkey, sign) or
                    !std.mem.eql(u8, old.seal_pubkey, seal_pk))
                {
                    return Error.KeySubstituted;
                }
            }
        }
        var known = false;
        for (cfg.devices) |old| {
            if (std.mem.eql(u8, old.device_id, id)) known = true;
        }
        if (!known) newly += 1;

        try out.append(a, .{
            .device_id = try a.dupe(u8, id),
            .sign_pubkey = try a.dupe(u8, sign),
            .seal_pubkey = try a.dupe(u8, seal_pk),
            .fingerprint = try a.dupe(u8, fp),
            .label = try a.dupe(u8, label),
        });
    }

    cfg.devices = try out.toOwnedSlice(a);
    try save(allocator, home, cfg);
    return .{ .paired = cfg.devices.len > 0, .newly_pinned = newly };
}

// ---------- asking ----------

pub const Verdict = struct {
    approved: bool,
    grace_s: u32,
    /// Fingerprint of the device that signed, for the audit log.
    device_fingerprint: []const u8,
};

/// Ask for approval and block until answered, denied, or the deadline passes.
///
/// `purpose_json` is the render envelope the human reads. It is sealed to each
/// device before it leaves this machine, so the relay never sees which secrets
/// are involved.
pub fn requestApproval(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    purpose_json: []const u8,
) !Verdict {
    if (cfg.devices.len == 0) return Error.NoPinnedDevice;

    var req_raw: [16]u8 = undefined;
    rand.bytes(&req_raw);
    const req_id = try p256.b64uEncodeAlloc(allocator, &req_raw);
    defer allocator.free(req_id);

    // One sealed copy per device: sealing is per-key, so a single copy would
    // leave every other paired phone woken and unable to read anything.
    var enc: jsonx.Encoder = .{};
    defer enc.deinit(allocator);
    try enc.writeRaw(allocator, "{\"req_id\":");
    try enc.writeString(allocator, req_id);
    try enc.writeRaw(allocator, ",\"ttl_s\":");
    try enc.writeNumber(allocator, cfg.timeout_s);
    try enc.writeRaw(allocator, ",\"seals\":{");
    for (cfg.devices, 0..) |d, i| {
        if (i > 0) try enc.writeRaw(allocator, ",");
        // sealB64: the key comes out of the config as base64url text.
        const sealed = try p256.sealB64(allocator, d.seal_pubkey, req_id, cfg.app_id, purpose_json);
        defer allocator.free(sealed);
        const sealed_b64 = try p256.b64uEncodeAlloc(allocator, sealed);
        defer allocator.free(sealed_b64);
        try enc.writeString(allocator, d.device_id);
        try enc.writeRaw(allocator, ":");
        try enc.writeString(allocator, sealed_b64);
    }
    try enc.writeRaw(allocator, "}}");
    const body = try enc.toOwnedSlice(allocator);
    defer allocator.free(body);

    {
        const res = try signedCall(allocator, cfg, "request", "POST", "/v1/requests", body, 15_000);
        defer res.deinit(allocator);
        if (!res.ok()) return Error.ServiceRejected;

        // Report what the push service said. Without this, "waiting for
        // approval" is indistinguishable from "no notification was ever
        // delivered", and the operator finds out only when the request
        // expires 120 s later.
        var parsed = jsonx.parse(allocator, res.body) catch {
            return Error.BadResponse;
        };
        defer parsed.deinit();
        var accepted: usize = 0;
        var gone: usize = 0;
        if (jsonx.objectGet(parsed.root(), "push")) |pushes| {
            if (pushes == .array) {
                for (pushes.array.items) |item| {
                    const st = if (jsonx.objectGet(item, "status")) |x| (jsonx.asInt(x) orelse 0) else 0;
                    if (st >= 200 and st < 300) accepted += 1;
                    if (jsonx.objectGet(item, "gone")) |g| {
                        if (g == .bool and g.bool) gone += 1;
                    }
                }
            }
        }
        var msg: [160]u8 = undefined;
        const line = std.fmt.bufPrint(&msg,
            "pushed to {d} device(s), {d} accepted{s}\n",
            .{ cfg.devices.len, accepted,
               if (gone > 0) ", 1 or more subscriptions are dead" else "" }) catch "";
        tty.writeStderr(line);
        if (accepted == 0) {
            // Nothing was delivered, so nothing can answer. Say so now rather
            // than waiting out the deadline in silence.
            tty.writeStderr("no push was accepted; the phone will not be asked\n");
            return Error.ServiceRejected;
        }
    }

    // Held GET, re-issued until the deadline. The service bounds each hold at
    // 25 s, so this is a handful of round trips rather than a poll loop.
    const deadline = clock.unixSeconds() + @as(i64, cfg.timeout_s);
    const wait_path = try std.fmt.allocPrint(allocator, "/v1/requests/{s}", .{req_id});
    defer allocator.free(wait_path);

    while (clock.unixSeconds() < deadline) {
        const res = signedCall(allocator, cfg, "wait", "GET", wait_path, "", wait_http_timeout_ms) catch |e| {
            // A transport hiccup mid-wait is not a denial yet; there is still
            // time on the deadline, so retry rather than refuse.
            if (e == http.Error.Timeout or e == http.Error.Transport) continue;
            return e;
        };
        defer res.deinit(allocator);
        if (!res.ok()) return Error.ServiceRejected;

        var parsed = try jsonx.parse(allocator, res.body);
        defer parsed.deinit();
        const state = jsonx.asString(jsonx.objectGet(parsed.root(), "state") orelse return Error.BadResponse) orelse return Error.BadResponse;

        if (std.mem.eql(u8, state, "pending")) continue;
        if (std.mem.eql(u8, state, "expired")) return Error.Expired;

        return try verifyVerdict(allocator, cfg, req_id, parsed.root());
    }
    // The deadline is a denial, not an error to be retried.
    return Error.Expired;
}

/// Check a verdict against the key pinned for the device that signed it.
///
/// This is the whole basis for not trusting the relay, so it is deliberately
/// strict: an unpinned signer, a bad signature, or a missing field is a
/// refusal, never a fallback.
fn verifyVerdict(
    allocator: std.mem.Allocator,
    cfg: *const Config,
    req_id: []const u8,
    root: std.json.Value,
) !Verdict {
    const device_id = jsonx.asString(jsonx.objectGet(root, "device_id") orelse return Error.BadResponse) orelse return Error.BadResponse;
    const sig_b64 = jsonx.asString(jsonx.objectGet(root, "sig") orelse return Error.BadResponse) orelse return Error.BadResponse;
    const ts = jsonx.asInt(jsonx.objectGet(root, "ts") orelse return Error.BadResponse) orelse return Error.BadResponse;
    const grace_s: u32 = if (jsonx.objectGet(root, "grace_s")) |g|
        @intCast(@max(0, jsonx.asInt(g) orelse 0))
    else
        0;

    // "resolved" carries the verdict in its own field; the state field carries
    // it otherwise.
    const verdict_str = blk: {
        if (jsonx.objectGet(root, "verdict")) |v| {
            if (jsonx.asString(v)) |s| break :blk s;
        }
        break :blk jsonx.asString(jsonx.objectGet(root, "state") orelse return Error.BadResponse) orelse return Error.BadResponse;
    };

    const signer = blk: {
        for (cfg.devices) |d| {
            if (std.mem.eql(u8, d.device_id, device_id)) break :blk d;
        }
        // Signed by something this machine never pinned. Refusing is the point.
        return Error.ForgedVerdict;
    };

    const canonical = try p256.canonicalVerdict(allocator, req_id, verdict_str, grace_s, ts);
    defer allocator.free(canonical);

    // verifyB64: both the pinned key and the signature are base64url here.
    p256.verifyB64(allocator, signer.sign_pubkey, canonical, sig_b64) catch
        return Error.ForgedVerdict;

    if (!std.mem.eql(u8, verdict_str, "approved")) return Error.Denied;
    return .{
        .approved = true,
        .grace_s = grace_s,
        .device_fingerprint = signer.fingerprint,
    };
}

/// Build the envelope the human reads. `require_device_unlock` forces the phone
/// out of the notification-button path and into the app, which requires the
/// phone to be unlocked — used where a one-tap lock-screen approval would be
/// too cheap for what it releases.
pub fn buildPurpose(
    allocator: std.mem.Allocator,
    title: []const u8,
    body: []const u8,
    details: []const [2][]const u8,
    require_device_unlock: bool,
) ![]u8 {
    var enc: jsonx.Encoder = .{};
    defer enc.deinit(allocator);
    try enc.writeRaw(allocator, "{\"title\":");
    try enc.writeString(allocator, title);
    try enc.writeRaw(allocator, ",\"body\":");
    try enc.writeString(allocator, body);
    try enc.writeRaw(allocator, ",\"details\":[");
    for (details, 0..) |d, i| {
        if (i > 0) try enc.writeRaw(allocator, ",");
        try enc.writeRaw(allocator, "[");
        try enc.writeString(allocator, d[0]);
        try enc.writeRaw(allocator, ",");
        try enc.writeString(allocator, d[1]);
        try enc.writeRaw(allocator, "]");
    }
    try enc.writeRaw(allocator, "],\"grace_options_s\":[0,300,900],\"require_device_unlock\":");
    try enc.writeBool(allocator, require_device_unlock);
    try enc.writeRaw(allocator, "}");
    return enc.toOwnedSlice(allocator);
}

/// Ask a paired device to approve one unlock, reporting progress and every
/// failure on stderr. Returns true only for an approving verdict whose
/// signature verified against a key pinned at pairing.
///
/// Lives here rather than in `cli.zig` because the MCP server needs the same
/// decision and cannot reach a private CLI helper. That matters more than the
/// tidiness: an agent asking for a secret through MCP is the case that started
/// this work, and an MCP server has no interactive channel at all — fd 0 is the
/// JSON-RPC transport (`mcp_tools.unlockSession`), so approval from another
/// device is its *only* way past a locked screen.
///
/// stderr is safe from both: the CLI prints there already, and for MCP stdout
/// is the protocol channel while stderr is the server log.
pub fn approveOrExplain(
    allocator: std.mem.Allocator,
    home: []const u8,
    transport: audit.Transport,
    /// What is being authorised, shown on the phone. Distinguishes an agent's
    /// request from one typed at the keyboard, which is the whole reason a
    /// human is being asked.
    title: []const u8,
    reason: []const u8,
) bool {
    var cfg = load(allocator, home) catch {
        tty.writeStderr("cannot read push.json; run `secretctl 2fa status`\n");
        return false;
    };
    defer cfg.deinit();

    if (cfg.devices.len == 0) {
        tty.writeStderr("no paired device; pair a phone first\n");
        return false;
    }

    const purpose = buildPurpose(
        allocator,
        title,
        reason,
        &.{
            .{ "via", transport.str() },
            .{ "reason", reason },
        },
        // Releasing vault access is not a one-tap-from-a-lock-screen decision.
        true,
    ) catch return false;
    defer allocator.free(purpose);

    tty.writeStderr("waiting for approval on your phone…\n");
    const verdict = requestApproval(allocator, &cfg, purpose) catch |e| {
        switch (e) {
            Error.Denied => tty.writeStderr("denied on the phone\n"),
            Error.Expired => tty.writeStderr("no answer before the request expired\n"),
            Error.ForgedVerdict => tty.writeStderr(
                "REFUSING: the verdict was not signed by a pinned device key.\n" ++
                    "This is not a transient error. Do not retry until you know why.\n"),
            Error.NoPinnedDevice => tty.writeStderr("no paired device\n"),
            else => {
                tty.writeStderr("approval failed: ");
                tty.writeStderr(@errorName(e));
                tty.writeStderr("\n");
            },
        }
        return false;
    };

    audit.log("authz.approved", transport, &.{
        audit.s("device", verdict.device_fingerprint),
    });
    tty.writeStderr("approved by ");
    tty.writeStderr(verdict.device_fingerprint);
    tty.writeStderr("\n");
    return true;
}

test "buildPurpose emits the envelope shape the PWA renders" {
    const a = std.testing.allocator;
    const j = try buildPurpose(a, "secretctl · unlock", "list --json", &.{
        .{ "command", "list --json" },
        .{ "secrets", "A, B" },
    }, true);
    defer a.free(j);

    var parsed = try jsonx.parse(a, j);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("secretctl · unlock",
        jsonx.asString(jsonx.objectGet(parsed.root(), "title").?).?);
    try std.testing.expect(jsonx.objectGet(parsed.root(), "require_device_unlock").?.bool);
    try std.testing.expectEqual(@as(usize, 2),
        jsonx.objectGet(parsed.root(), "details").?.array.items.len);
}

test "an unconfigured home reports not configured" {
    try std.testing.expect(!configured("/nonexistent/secretctl-home"));
    try std.testing.expectError(Error.NotConfigured,
        load(std.testing.allocator, "/nonexistent/secretctl-home"));
}

test "config round-trips through save and load" {
    const a = std.testing.allocator;
    // A plain temp directory rather than std.testing.tmpDir: Io.Dir in Zig
    // 0.16 has no realpath, and this code takes a path rather than a handle.
    var name_raw: [8]u8 = undefined;
    rand.bytes(&name_raw);
    const suffix = try p256.b64uEncodeAlloc(a, &name_raw);
    defer a.free(suffix);
    const home = try std.fmt.allocPrint(a, "/tmp/secretctl-pushcfg-{s}", .{suffix});
    defer a.free(home);
    try fsx.mkdirAll(home, 0o700);
    defer {
        var buf: [1024]u8 = undefined;
        const cfgp = std.fmt.bufPrint(&buf, "{s}/push.json", .{home}) catch unreachable;
        fsx.unlinkIfExists(cfgp);
    }

    var cfg = Config{
        .worker_url = "https://example.invalid",
        .app_id = "app-1",
        .client_id = "client-1",
        .client_secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        .devices = &.{},
        .arena = std.heap.ArenaAllocator.init(a),
    };
    // Through cfg.alloc(), not a separate handle: see the note on Config.alloc.
    const devs = try cfg.alloc().alloc(Device, 1);
    devs[0] = .{
        .device_id = "dev-1", .sign_pubkey = "sp", .seal_pubkey = "ep",
        .fingerprint = "1111-2222-3333-4444", .label = "iPhone",
    };
    cfg.devices = devs;
    try save(a, home, &cfg);
    cfg.deinit();

    var back = try load(a, home);
    defer back.deinit();
    try std.testing.expectEqualStrings("https://example.invalid", back.worker_url);
    try std.testing.expectEqual(@as(usize, 1), back.devices.len);
    try std.testing.expectEqualStrings("iPhone", back.devices[0].label);
    try std.testing.expectEqualStrings("1111-2222-3333-4444", back.devices[0].fingerprint);
}
