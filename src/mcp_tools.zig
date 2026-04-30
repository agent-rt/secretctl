//! MCP tool implementations + registry. Phase 2 ships 3 tools:
//!   list_secrets / check_secret_available / run_with_secrets
//!
//! Each tool's handler returns a JSON text payload that gets wrapped as
//! the first MCP content block by the server framework.

const std = @import("std");
const jsonx = @import("jsonx.zig");
const mcp = @import("mcp.zig");
const vault_mod = @import("vault.zig");
const envelope_mod = @import("envelope.zig");
const policy_mod = @import("policy.zig");
const paths_mod = @import("paths.zig");
const fsx = @import("fsx.zig");
const master_key_mod = @import("master_key.zig");
const aes = @import("aes_gcm.zig");
const mem_util = @import("mem.zig");
const tty = @import("tty.zig");

pub const list_secrets_schema =
    \\{"type":"object","properties":{"tag":{"type":"string","description":"Filter to secrets carrying this tag."}}}
;

pub const check_secret_available_schema =
    \\{"type":"object","required":["name"],"properties":{"name":{"type":"string","description":"Secret name to check."}}}
;

pub const run_with_secrets_schema =
    \\{"type":"object","required":["command"],"properties":{"command":{"type":"string","description":"Executable name (basename must be in .secretctl.toml allow.commands)."},"args":{"type":"array","items":{"type":"string"},"description":"Arguments passed to the command."},"tags":{"type":"array","items":{"type":"string"},"description":"Inject every secret carrying any of these tags."},"only":{"type":"array","items":{"type":"string"},"description":"Inject these named secrets only."}}}
;

pub const all_tools = [_]mcp.Tool{
    .{
        .name = "list_secrets",
        .description = "List secret names, tags, and timestamps. Never returns the value.",
        .input_schema_json = list_secrets_schema,
        .handler = handleListSecrets,
    },
    .{
        .name = "check_secret_available",
        .description = "Check whether a named secret exists in the vault.",
        .input_schema_json = check_secret_available_schema,
        .handler = handleCheckSecretAvailable,
    },
    .{
        .name = "run_with_secrets",
        .description = "Run an allowlisted command with selected secrets injected as environment variables. Returns the child's stdout, stderr, and exit code.",
        .input_schema_json = run_with_secrets_schema,
        .handler = handleRunWithSecrets,
    },
};

// ------- shared session helper -------

const Session = struct {
    paths: paths_mod.Paths,
    master_key: [aes.key_len]u8,
    master_key_id: [16]u8,
    master_key_version: u32,
    body: vault_mod.VaultBody,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Session) void {
        self.body.deinit(self.allocator);
        mem_util.secureZero(u8, &self.master_key);
        self.paths.deinit();
    }
};

fn unlockSession(allocator: std.mem.Allocator) !Session {
    var p = try paths_mod.resolve(allocator);
    var ok = false;
    defer if (!ok) p.deinit();

    if (!fsx.fileExists(p.master_key)) return error.NoVault;
    const blob = try fsx.readAllAlloc(allocator, p.master_key, 1 * 1024 * 1024);
    defer allocator.free(blob);

    var master_key: [aes.key_len]u8 = undefined;
    // Try keychain unlock silently; fall back to password (read from /dev/tty
    // via tty module so we don't read from JSON-RPC stdin).
    const keychain_attempt = master_key_mod.parseAndUnlock(allocator, blob, null, &master_key) catch |e| switch (e) {
        master_key_mod.Error.AuthenticationFailed,
        master_key_mod.Error.NoUsableProtector,
        => null_block: {
            break :null_block @as(?master_key_mod.MasterFile, null);
        },
        else => return e,
    };

    var parsed: master_key_mod.MasterFile = if (keychain_attempt) |kp| kp else blk: {
        // Need password — write prompt to stderr (stdout reserved for JSON-RPC).
        tty.writeStderr("master password (mcp unlock): ");
        var pw = try tty.readPassword(allocator, "");
        defer pw.deinit();
        break :blk try master_key_mod.parseAndUnlock(allocator, blob, pw.bytes, &master_key);
    };
    errdefer parsed.deinit(allocator);

    const vresult = try vault_mod.loadFromFile(allocator, p.vault, &master_key, null);
    parsed.deinit(allocator);

    ok = true;
    return Session{
        .paths = p,
        .master_key = master_key,
        .master_key_id = vresult.master_key_id,
        .master_key_version = vresult.master_key_version,
        .body = vresult.body,
        .allocator = allocator,
    };
}

fn loadPolicy(allocator: std.mem.Allocator, opts: *const mcp.Options) policy_mod.Policy {
    const dir = if (opts.cwd) |c| c else blk: {
        var cwd_buf: [1024]u8 = undefined;
        const cwd_ptr = getcwd(&cwd_buf, cwd_buf.len);
        if (cwd_ptr) |ptr| {
            const z: [*:0]const u8 = @ptrCast(ptr);
            break :blk std.mem.span(z);
        }
        break :blk "";
    };
    return policy_mod.load(allocator, dir) catch policy_mod.empty;
}

extern "c" fn getcwd(buf: [*]u8, size: usize) ?[*]u8;

// ------- list_secrets -------

fn handleListSecrets(allocator: std.mem.Allocator, args: std.json.Value, opts: *const mcp.Options) anyerror!mcp.ToolResult {
    _ = opts;
    const tag_filter: ?[]const u8 = if (jsonx.objectGet(args, "tag")) |v| jsonx.asString(v) else null;

    var sess = unlockSession(allocator) catch |e| return errorResult(allocator, e);
    defer sess.deinit();

    var enc: jsonx.Encoder = .{};
    errdefer enc.deinit(allocator);

    try enc.writeByte(allocator, '{');
    var first = true;
    try jsonx.writeKey(&enc, allocator, "secrets", &first);
    try enc.writeByte(allocator, '[');
    var emitted: usize = 0;
    for (sess.body.secrets.items) |s| {
        if (tag_filter) |tag| {
            var matches = false;
            for (s.tags) |t| if (std.mem.eql(u8, t, tag)) {
                matches = true;
                break;
            };
            if (!matches) continue;
        }
        if (emitted > 0) try enc.writeByte(allocator, ',');
        emitted += 1;
        try enc.writeByte(allocator, '{');
        var sf = true;
        try jsonx.writeKey(&enc, allocator, "name", &sf);
        try enc.writeString(allocator, s.name);
        try jsonx.writeKey(&enc, allocator, "tags", &sf);
        try enc.writeByte(allocator, '[');
        for (s.tags, 0..) |t, ti| {
            if (ti > 0) try enc.writeByte(allocator, ',');
            try enc.writeString(allocator, t);
        }
        try enc.writeByte(allocator, ']');
        try jsonx.writeKey(&enc, allocator, "created_at", &sf);
        try enc.writeNumber(allocator, s.created_at);
        try jsonx.writeKey(&enc, allocator, "updated_at", &sf);
        try enc.writeNumber(allocator, s.updated_at);
        try enc.writeByte(allocator, '}');
    }
    try enc.writeByte(allocator, ']');
    try enc.writeByte(allocator, '}');
    return .{ .json_text = try enc.toOwnedSlice(allocator), .is_error = false };
}

// ------- check_secret_available -------

fn handleCheckSecretAvailable(allocator: std.mem.Allocator, args: std.json.Value, opts: *const mcp.Options) anyerror!mcp.ToolResult {
    _ = opts;
    const name_v = jsonx.objectGet(args, "name") orelse return errorResultMsg(allocator, "missing 'name'");
    const name = jsonx.asString(name_v) orelse return errorResultMsg(allocator, "'name' must be string");

    var sess = unlockSession(allocator) catch |e| return errorResult(allocator, e);
    defer sess.deinit();

    const exists = sess.body.findIndex(name) != null;

    var enc: jsonx.Encoder = .{};
    errdefer enc.deinit(allocator);
    try enc.writeByte(allocator, '{');
    var first = true;
    try jsonx.writeKey(&enc, allocator, "exists", &first);
    try enc.writeBool(allocator, exists);
    try enc.writeByte(allocator, '}');
    return .{ .json_text = try enc.toOwnedSlice(allocator), .is_error = false };
}

// ------- run_with_secrets -------

extern "c" fn pipe(fds: *[2]c_int) c_int;
extern "c" fn fork() c_int;
extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;
extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern "c" fn waitpid(pid: c_int, stat_loc: *c_int, options: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;
extern "c" fn _exit(status: c_int) noreturn;

const max_capture_per_stream: usize = 1 * 1024 * 1024;

fn drainFd(allocator: std.mem.Allocator, fd: c_int, cap: usize) !struct { data: []u8, truncated: bool } {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    var truncated = false;
    while (true) {
        const n = read(fd, &chunk, chunk.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        const remaining = if (cap > buf.items.len) cap - buf.items.len else 0;
        const to_take: usize = @min(@as(usize, @intCast(n)), remaining);
        if (to_take > 0) try buf.appendSlice(allocator, chunk[0..to_take]);
        if (@as(usize, @intCast(n)) > to_take) {
            truncated = true;
            // Drain rest to let child finish; but cap silently.
        }
    }
    return .{ .data = try buf.toOwnedSlice(allocator), .truncated = truncated };
}

fn isUtf8(bytes: []const u8) bool {
    return std.unicode.utf8ValidateSlice(bytes);
}

fn collectStringArray(args: std.json.Value, key: []const u8, out: *std.ArrayList([]const u8), allocator: std.mem.Allocator) !void {
    const v = jsonx.objectGet(args, key) orelse return;
    const arr = jsonx.asArray(v) orelse return;
    for (arr.items) |item| {
        const s = jsonx.asString(item) orelse continue;
        try out.append(allocator, s);
    }
}

fn handleRunWithSecrets(allocator: std.mem.Allocator, args: std.json.Value, opts: *const mcp.Options) anyerror!mcp.ToolResult {
    // Parse args.
    const command_v = jsonx.objectGet(args, "command") orelse return errorResultMsg(allocator, "missing 'command'");
    const command = jsonx.asString(command_v) orelse return errorResultMsg(allocator, "'command' must be string");

    var cli_args: std.ArrayList([]const u8) = .empty;
    defer cli_args.deinit(allocator);
    try collectStringArray(args, "args", &cli_args, allocator);

    var tag_filter: std.ArrayList([]const u8) = .empty;
    defer tag_filter.deinit(allocator);
    try collectStringArray(args, "tags", &tag_filter, allocator);

    var only_filter: std.ArrayList([]const u8) = .empty;
    defer only_filter.deinit(allocator);
    try collectStringArray(args, "only", &only_filter, allocator);

    if (tag_filter.items.len == 0 and only_filter.items.len == 0)
        return errorResultMsg(allocator, "no secret selection — pass 'tags' or 'only'");

    // Policy gate (mirrors CLI exec, including tag check on selected secrets).
    var pol = loadPolicy(allocator, opts);
    defer if (pol.present) pol.deinit();
    if (!pol.allowsCommand(command))
        return errorResultMsg(allocator, "command not in .secretctl.toml allowlist");
    for (tag_filter.items) |t| if (!pol.allowsTag(t))
        return errorResultMsg(allocator, "tag not in .secretctl.toml allowlist");

    var sess = unlockSession(allocator) catch |e| return errorResult(allocator, e);
    defer sess.deinit();

    // Resolve selected secrets.
    var selected: std.ArrayList(usize) = .empty;
    defer selected.deinit(allocator);
    for (only_filter.items) |name| {
        const idx = sess.body.findIndex(name) orelse return errorResultMsg(allocator, "unknown secret in 'only'");
        try selected.append(allocator, idx);
    }
    for (sess.body.secrets.items, 0..) |s, idx| {
        outer: for (tag_filter.items) |needle| {
            for (s.tags) |t| if (std.mem.eql(u8, t, needle)) {
                try selected.append(allocator, idx);
                break :outer;
            };
        }
    }
    if (selected.items.len == 0)
        return errorResultMsg(allocator, "no secrets matched the selection");

    // Re-check selected-secrets-tags vs allowlist (closes --only bypass, same
    // as CLI exec).
    if (pol.present) {
        for (selected.items) |idx| {
            const s = sess.body.secrets.items[idx];
            var ok2 = false;
            for (s.tags) |t| if (pol.allowsTag(t)) {
                ok2 = true;
                break;
            };
            if (!ok2) return errorResultMsg(allocator, "selected secret has no tag in allowlist");
        }
    }

    // Decrypt secrets and setenv.
    var pts: std.ArrayList(mem_util.Plaintext) = .empty;
    defer {
        for (pts.items) |*pt| pt.deinit();
        pts.deinit(allocator);
    }
    var injected_names: std.ArrayList([]const u8) = .empty;
    defer {
        for (injected_names.items) |n| allocator.free(n);
        injected_names.deinit(allocator);
    }
    for (selected.items) |idx| {
        const rec = sess.body.secrets.items[idx];
        const pt = try envelope_mod.decrypt(allocator, &sess.master_key, &sess.master_key_id, &rec.id, &rec.envelope);
        try pts.append(allocator, pt);

        const name_z = try allocator.allocSentinel(u8, rec.name.len, 0);
        defer allocator.free(name_z);
        @memcpy(name_z, rec.name);
        const value_z = try allocator.allocSentinel(u8, pt.bytes.len, 0);
        defer allocator.free(value_z);
        @memcpy(value_z, pt.bytes);
        if (setenv(name_z.ptr, value_z.ptr, 1) != 0) return errorResultMsg(allocator, "setenv failed");

        try injected_names.append(allocator, try allocator.dupe(u8, rec.name));
    }

    // Build child argv.
    var argv_storage: std.ArrayList([:0]u8) = .empty;
    defer {
        for (argv_storage.items) |s| allocator.free(s);
        argv_storage.deinit(allocator);
    }
    const cmd_z = try allocator.allocSentinel(u8, command.len, 0);
    @memcpy(cmd_z, command);
    try argv_storage.append(allocator, cmd_z);
    for (cli_args.items) |a| {
        const z = try allocator.allocSentinel(u8, a.len, 0);
        @memcpy(z, a);
        try argv_storage.append(allocator, z);
    }
    const argv_array = try allocator.alloc(?[*:0]const u8, argv_storage.items.len + 1);
    defer allocator.free(argv_array);
    for (argv_storage.items, 0..) |s, i| argv_array[i] = s.ptr;
    argv_array[argv_storage.items.len] = null;

    // pipes for stdout / stderr.
    var pipe_out: [2]c_int = undefined;
    var pipe_err: [2]c_int = undefined;
    if (pipe(&pipe_out) != 0 or pipe(&pipe_err) != 0) {
        return errorResultMsg(allocator, "pipe failed");
    }

    const pid = fork();
    if (pid < 0) return errorResultMsg(allocator, "fork failed");
    if (pid == 0) {
        _ = dup2(pipe_out[1], 1);
        _ = dup2(pipe_err[1], 2);
        _ = close(pipe_out[0]);
        _ = close(pipe_out[1]);
        _ = close(pipe_err[0]);
        _ = close(pipe_err[1]);
        const argv_terminated: [*:null]const ?[*:0]const u8 = @ptrCast(argv_array.ptr);
        _ = execvp(argv_array[0].?, argv_terminated);
        const errno_val = std.c._errno().*;
        const ENOENT: c_int = 2;
        const EACCES: c_int = 13;
        if (errno_val == ENOENT) _exit(127);
        if (errno_val == EACCES) _exit(126);
        _exit(127);
    }

    _ = close(pipe_out[1]);
    _ = close(pipe_err[1]);

    // Drain pipes (sequentially is fine for capped output; for true streams
    // would need select, but 1 MiB cap covers typical tool output).
    const out_drain = drainFd(allocator, pipe_out[0], max_capture_per_stream) catch |e| {
        _ = close(pipe_out[0]);
        _ = close(pipe_err[0]);
        return errorResult(allocator, e);
    };
    defer allocator.free(out_drain.data);
    _ = close(pipe_out[0]);
    const err_drain = drainFd(allocator, pipe_err[0], max_capture_per_stream) catch |e| {
        _ = close(pipe_err[0]);
        return errorResult(allocator, e);
    };
    defer allocator.free(err_drain.data);
    _ = close(pipe_err[0]);

    var status: c_int = 0;
    _ = waitpid(pid, &status, 0);
    var exit_code: i64 = 0;
    if ((status & 0x7f) == 0) {
        exit_code = @intCast((status >> 8) & 0xff);
    } else {
        exit_code = 128 + @as(i64, @intCast(status & 0x7f));
    }

    // Unset env vars to clean up parent process state.
    for (injected_names.items) |name| {
        const name_z = allocator.allocSentinel(u8, name.len, 0) catch continue;
        defer allocator.free(name_z);
        @memcpy(name_z, name);
        _ = unsetenv(name_z.ptr);
    }
    // secureZero plaintexts (defer above will deinit, but explicit zero now).
    for (pts.items) |*pt| mem_util.secureZero(u8, pt.bytes);

    // Encode result.
    const out_is_utf8 = isUtf8(out_drain.data);
    const err_is_utf8 = isUtf8(err_drain.data);
    var out_text: []u8 = undefined;
    var out_owned = false;
    if (out_is_utf8) {
        out_text = out_drain.data;
    } else {
        out_text = try jsonx.base64Encode(allocator, out_drain.data);
        out_owned = true;
    }
    defer if (out_owned) allocator.free(out_text);

    var err_text: []u8 = undefined;
    var err_owned = false;
    if (err_is_utf8) {
        err_text = err_drain.data;
    } else {
        err_text = try jsonx.base64Encode(allocator, err_drain.data);
        err_owned = true;
    }
    defer if (err_owned) allocator.free(err_text);

    var enc: jsonx.Encoder = .{};
    errdefer enc.deinit(allocator);
    try enc.writeByte(allocator, '{');
    var first = true;
    try jsonx.writeKey(&enc, allocator, "exit_code", &first);
    try enc.writeNumber(allocator, exit_code);
    try jsonx.writeKey(&enc, allocator, "stdout", &first);
    try enc.writeString(allocator, out_text);
    try jsonx.writeKey(&enc, allocator, "stdout_encoding", &first);
    try enc.writeString(allocator, if (out_is_utf8) "utf8" else "base64");
    try jsonx.writeKey(&enc, allocator, "stderr", &first);
    try enc.writeString(allocator, err_text);
    try jsonx.writeKey(&enc, allocator, "stderr_encoding", &first);
    try enc.writeString(allocator, if (err_is_utf8) "utf8" else "base64");
    if (out_drain.truncated) {
        try jsonx.writeKey(&enc, allocator, "stdout_truncated", &first);
        try enc.writeBool(allocator, true);
    }
    if (err_drain.truncated) {
        try jsonx.writeKey(&enc, allocator, "stderr_truncated", &first);
        try enc.writeBool(allocator, true);
    }
    try enc.writeByte(allocator, '}');

    return .{ .json_text = try enc.toOwnedSlice(allocator), .is_error = false };
}

// ------- error helpers -------

fn errorResultMsg(allocator: std.mem.Allocator, msg: []const u8) anyerror!mcp.ToolResult {
    var enc: jsonx.Encoder = .{};
    errdefer enc.deinit(allocator);
    try enc.writeByte(allocator, '{');
    var first = true;
    try jsonx.writeKey(&enc, allocator, "error", &first);
    try enc.writeString(allocator, msg);
    try enc.writeByte(allocator, '}');
    return .{ .json_text = try enc.toOwnedSlice(allocator), .is_error = true };
}

fn errorResult(allocator: std.mem.Allocator, e: anyerror) anyerror!mcp.ToolResult {
    var msg_buf: [128]u8 = undefined;
    const msg = std.fmt.bufPrint(&msg_buf, "{s}", .{@errorName(e)}) catch "error";
    return errorResultMsg(allocator, msg);
}
