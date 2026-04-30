//! MCP (Model Context Protocol) server. JSON-RPC 2.0 over stdio,
//! newline-delimited messages, MCP 2024-11-05.
//!
//! Tools:
//!   list_secrets({tag?})            → secret name+tags+timestamps
//!   check_secret_available({name})  → bool
//!   run_with_secrets({command, args?, tags?, only?})  → stdout/stderr/exit
//!
//! Stdio discipline: stdout is JSON-RPC frames only; any user-facing message
//! goes to stderr. Audit log records every tool call with transport=mcp.

const std = @import("std");
const jsonx = @import("jsonx.zig");
const tty = @import("tty.zig");
const audit_mod = @import("audit.zig");

extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;
extern "c" fn write(fd: c_int, buf: [*]const u8, count: usize) isize;

const STDIN: c_int = 0;
const STDOUT: c_int = 1;

pub const protocol_version = "2024-11-05";
pub const server_name = "secretctl";
pub const server_version = "0.5.1";

pub const Options = struct {
    /// Project root for `.secretctl.toml` lookup. Defaults to cwd if null.
    cwd: ?[]const u8 = null,
    /// When true, expose `get_secret` (returns plaintext, gated by Touch ID
    /// per call). Refuses to start if biometrics aren't available.
    dangerous: bool = false,
};

/// JSON-RPC error codes (subset).
pub const ErrorCode = struct {
    pub const parse_error: i64 = -32700;
    pub const invalid_request: i64 = -32600;
    pub const method_not_found: i64 = -32601;
    pub const invalid_params: i64 = -32602;
    pub const internal_error: i64 = -32603;
};

const max_line_len: usize = 16 * 1024 * 1024; // 16 MiB

/// Read one newline-terminated line from stdin into `buf`. Returns null on EOF.
fn readLine(allocator: std.mem.Allocator) !?[]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var c: [1]u8 = undefined;
    while (true) {
        const n = read(STDIN, &c, 1);
        if (n < 0) return error.ReadFailed;
        if (n == 0) {
            if (buf.items.len == 0) {
                buf.deinit(allocator);
                return null;
            }
            break;
        }
        if (c[0] == '\n') break;
        if (buf.items.len >= max_line_len) return error.LineTooLong;
        try buf.append(allocator, c[0]);
    }
    return try buf.toOwnedSlice(allocator);
}

fn writeLine(line: []const u8) void {
    var off: usize = 0;
    while (off < line.len) {
        const n = write(STDOUT, line[off..].ptr, line.len - off);
        if (n <= 0) return;
        off += @intCast(n);
    }
    _ = write(STDOUT, "\n", 1);
}

/// Tool dispatch — implementations registered later. The handler must
/// return a fully-encoded JSON value (object) for `result.content[0].text`,
/// or set `is_error=true` and return an error message.
pub const ToolResult = struct {
    /// Owned JSON text representing the tool's structured output. Encoded
    /// as the `text` field of the first MCP content block.
    json_text: []u8,
    is_error: bool,

    pub fn deinit(self: *ToolResult, allocator: std.mem.Allocator) void {
        allocator.free(self.json_text);
        self.json_text = &.{};
    }
};

pub const ToolFn = *const fn (allocator: std.mem.Allocator, args: std.json.Value, opts: *const Options) anyerror!ToolResult;

pub const Tool = struct {
    name: []const u8,
    description: []const u8,
    /// Pre-encoded inputSchema JSON object.
    input_schema_json: []const u8,
    handler: ToolFn,
};

// Registry of tools. Implementations live in mcp_tools.zig.
const mcp_tools = @import("mcp_tools.zig");

fn activeTools(opts: *const Options) []const Tool {
    return if (opts.dangerous) &mcp_tools.all_dangerous_tools else &mcp_tools.all_tools;
}

// ------- request handling -------

fn writeRpcError(allocator: std.mem.Allocator, id_raw: ?[]const u8, code: i64, message: []const u8) void {
    var enc: jsonx.Encoder = .{};
    defer enc.deinit(allocator);
    var first = true;
    enc.writeByte(allocator, '{') catch return;
    jsonx.writeKey(&enc, allocator, "jsonrpc", &first) catch return;
    enc.writeString(allocator, "2.0") catch return;
    jsonx.writeKey(&enc, allocator, "id", &first) catch return;
    if (id_raw) |raw| {
        enc.writeRaw(allocator, raw) catch return;
    } else {
        enc.writeNull(allocator) catch return;
    }
    jsonx.writeKey(&enc, allocator, "error", &first) catch return;
    enc.writeByte(allocator, '{') catch return;
    var ef = true;
    jsonx.writeKey(&enc, allocator, "code", &ef) catch return;
    enc.writeNumber(allocator, code) catch return;
    jsonx.writeKey(&enc, allocator, "message", &ef) catch return;
    enc.writeString(allocator, message) catch return;
    enc.writeByte(allocator, '}') catch return;
    enc.writeByte(allocator, '}') catch return;

    writeLine(enc.buf.items);
}

fn writeRpcResult(allocator: std.mem.Allocator, id_raw: []const u8, result_json: []const u8) void {
    var enc: jsonx.Encoder = .{};
    defer enc.deinit(allocator);
    var first = true;
    enc.writeByte(allocator, '{') catch return;
    jsonx.writeKey(&enc, allocator, "jsonrpc", &first) catch return;
    enc.writeString(allocator, "2.0") catch return;
    jsonx.writeKey(&enc, allocator, "id", &first) catch return;
    enc.writeRaw(allocator, id_raw) catch return;
    jsonx.writeKey(&enc, allocator, "result", &first) catch return;
    enc.writeRaw(allocator, result_json) catch return;
    enc.writeByte(allocator, '}') catch return;

    writeLine(enc.buf.items);
}

/// Extract the raw `id` field bytes from a request line so we can echo it
/// back unchanged in the response. Returns null if absent (notification) or
/// on parse error.
fn extractIdRaw(line: []const u8) ?[]const u8 {
    // Look for `"id":` and capture the next JSON value verbatim.
    const needle = "\"id\":";
    const start = std.mem.indexOf(u8, line, needle) orelse return null;
    var i = start + needle.len;
    while (i < line.len and (line[i] == ' ' or line[i] == '\t')) i += 1;
    if (i >= line.len) return null;
    const value_start = i;
    if (line[i] == '"') {
        i += 1;
        while (i < line.len and line[i] != '"') {
            if (line[i] == '\\' and i + 1 < line.len) i += 2 else i += 1;
        }
        if (i < line.len) i += 1; // include closing "
        return line[value_start..i];
    }
    while (i < line.len and line[i] != ',' and line[i] != '}' and line[i] != ' ' and line[i] != '\t') i += 1;
    return line[value_start..i];
}

fn buildInitializeResult(allocator: std.mem.Allocator) ![]u8 {
    var enc: jsonx.Encoder = .{};
    errdefer enc.deinit(allocator);
    var first = true;
    try enc.writeByte(allocator, '{');
    try jsonx.writeKey(&enc, allocator, "protocolVersion", &first);
    try enc.writeString(allocator, protocol_version);
    try jsonx.writeKey(&enc, allocator, "capabilities", &first);
    try enc.writeRaw(allocator, "{\"tools\":{}}");
    try jsonx.writeKey(&enc, allocator, "serverInfo", &first);
    try enc.writeByte(allocator, '{');
    var sf = true;
    try jsonx.writeKey(&enc, allocator, "name", &sf);
    try enc.writeString(allocator, server_name);
    try jsonx.writeKey(&enc, allocator, "version", &sf);
    try enc.writeString(allocator, server_version);
    try enc.writeByte(allocator, '}');
    try enc.writeByte(allocator, '}');
    return enc.toOwnedSlice(allocator);
}

fn buildToolsListResult(allocator: std.mem.Allocator, opts: *const Options) ![]u8 {
    const tools = activeTools(opts);
    var enc: jsonx.Encoder = .{};
    errdefer enc.deinit(allocator);
    try enc.writeByte(allocator, '{');
    var first = true;
    try jsonx.writeKey(&enc, allocator, "tools", &first);
    try enc.writeByte(allocator, '[');
    for (tools, 0..) |t, i| {
        if (i > 0) try enc.writeByte(allocator, ',');
        try enc.writeByte(allocator, '{');
        var tf = true;
        try jsonx.writeKey(&enc, allocator, "name", &tf);
        try enc.writeString(allocator, t.name);
        try jsonx.writeKey(&enc, allocator, "description", &tf);
        try enc.writeString(allocator, t.description);
        try jsonx.writeKey(&enc, allocator, "inputSchema", &tf);
        try enc.writeRaw(allocator, t.input_schema_json);
        try enc.writeByte(allocator, '}');
    }
    try enc.writeByte(allocator, ']');
    try enc.writeByte(allocator, '}');
    return enc.toOwnedSlice(allocator);
}

fn buildToolCallResult(allocator: std.mem.Allocator, content_text: []const u8, is_error: bool) ![]u8 {
    var enc: jsonx.Encoder = .{};
    errdefer enc.deinit(allocator);
    try enc.writeByte(allocator, '{');
    var first = true;
    try jsonx.writeKey(&enc, allocator, "content", &first);
    try enc.writeByte(allocator, '[');
    try enc.writeByte(allocator, '{');
    var cf = true;
    try jsonx.writeKey(&enc, allocator, "type", &cf);
    try enc.writeString(allocator, "text");
    try jsonx.writeKey(&enc, allocator, "text", &cf);
    try enc.writeString(allocator, content_text);
    try enc.writeByte(allocator, '}');
    try enc.writeByte(allocator, ']');
    if (is_error) {
        try jsonx.writeKey(&enc, allocator, "isError", &first);
        try enc.writeBool(allocator, true);
    }
    try enc.writeByte(allocator, '}');
    return enc.toOwnedSlice(allocator);
}

fn handleRequest(allocator: std.mem.Allocator, line: []const u8, opts: *const Options) void {
    const id_raw = extractIdRaw(line);

    var parsed = jsonx.parse(allocator, line) catch {
        writeRpcError(allocator, id_raw, ErrorCode.parse_error, "parse error");
        return;
    };
    defer parsed.deinit();

    const root = parsed.root();
    const method_v = jsonx.objectGet(root, "method") orelse {
        writeRpcError(allocator, id_raw, ErrorCode.invalid_request, "missing method");
        return;
    };
    const method = jsonx.asString(method_v) orelse {
        writeRpcError(allocator, id_raw, ErrorCode.invalid_request, "method not a string");
        return;
    };

    if (std.mem.eql(u8, method, "initialize")) {
        const result = buildInitializeResult(allocator) catch {
            writeRpcError(allocator, id_raw, ErrorCode.internal_error, "encode failed");
            return;
        };
        defer allocator.free(result);
        if (id_raw) |raw| writeRpcResult(allocator, raw, result);
        audit_mod.log("mcp.initialize", .mcp, &.{});
        return;
    }
    if (std.mem.eql(u8, method, "notifications/initialized")) {
        // Notification — no response expected.
        return;
    }
    if (std.mem.eql(u8, method, "tools/list")) {
        const result = buildToolsListResult(allocator, opts) catch {
            writeRpcError(allocator, id_raw, ErrorCode.internal_error, "encode failed");
            return;
        };
        defer allocator.free(result);
        if (id_raw) |raw| writeRpcResult(allocator, raw, result);
        audit_mod.log("mcp.tools_list", .mcp, &.{});
        return;
    }
    if (std.mem.eql(u8, method, "tools/call")) {
        const params_v = jsonx.objectGet(root, "params") orelse {
            writeRpcError(allocator, id_raw, ErrorCode.invalid_params, "missing params");
            return;
        };
        const name_v = jsonx.objectGet(params_v, "name") orelse {
            writeRpcError(allocator, id_raw, ErrorCode.invalid_params, "missing tool name");
            return;
        };
        const tool_name = jsonx.asString(name_v) orelse {
            writeRpcError(allocator, id_raw, ErrorCode.invalid_params, "tool name not a string");
            return;
        };
        const args_v = jsonx.objectGet(params_v, "arguments") orelse std.json.Value{ .null = {} };

        const tool = blk: {
            for (activeTools(opts)) |t| if (std.mem.eql(u8, t.name, tool_name)) break :blk t;
            writeRpcError(allocator, id_raw, ErrorCode.invalid_params, "unknown tool");
            audit_mod.log("mcp.tools_call", .mcp, &.{ audit_mod.s("tool", tool_name), audit_mod.s("status", "unknown") });
            return;
        };

        var tres = tool.handler(allocator, args_v, opts) catch |e| {
            const msg = std.fmt.allocPrint(allocator, "tool error: {s}", .{@errorName(e)}) catch "tool error";
            defer if (!std.mem.eql(u8, msg, "tool error")) allocator.free(msg);
            const result = buildToolCallResult(allocator, msg, true) catch {
                writeRpcError(allocator, id_raw, ErrorCode.internal_error, "encode failed");
                return;
            };
            defer allocator.free(result);
            if (id_raw) |raw| writeRpcResult(allocator, raw, result);
            audit_mod.log("mcp.tools_call", .mcp, &.{ audit_mod.s("tool", tool_name), audit_mod.s("status", "error"), audit_mod.s("err", @errorName(e)) });
            return;
        };
        defer tres.deinit(allocator);

        const result = buildToolCallResult(allocator, tres.json_text, tres.is_error) catch {
            writeRpcError(allocator, id_raw, ErrorCode.internal_error, "encode failed");
            return;
        };
        defer allocator.free(result);
        if (id_raw) |raw| writeRpcResult(allocator, raw, result);
        audit_mod.log("mcp.tools_call", .mcp, &.{
            audit_mod.s("tool", tool_name),
            audit_mod.s("status", if (tres.is_error) "tool_error" else "ok"),
        });
        return;
    }
    if (std.mem.eql(u8, method, "shutdown") or std.mem.eql(u8, method, "exit")) {
        // Graceful exit.
        if (id_raw) |raw| writeRpcResult(allocator, raw, "null");
        std.process.exit(0);
    }

    writeRpcError(allocator, id_raw, ErrorCode.method_not_found, "method not found");
}

pub fn serve(allocator: std.mem.Allocator, opts: Options) u8 {
    if (opts.dangerous) {
        const local_auth = @import("local_auth.zig");
        if (!local_auth.available()) {
            tty.writeStderr("--allow-secret-read requires Touch ID hardware (LocalAuthentication unavailable)\n");
            return 2;
        }
        tty.writeStderr("secretctl mcp dangerous mode: get_secret enabled (per-call Touch ID)\n");
    }
    tty.writeStderr("secretctl mcp listening on stdio\n");
    while (true) {
        const maybe_line = readLine(allocator) catch |e| {
            tty.writeStderr("mcp: read error\n");
            tty.writeStderr(@errorName(e));
            tty.writeStderr("\n");
            return 1;
        };
        const line = maybe_line orelse break; // EOF
        defer allocator.free(line);
        if (line.len == 0) continue;
        handleRequest(allocator, line, &opts);
    }
    return 0;
}

// ------- tests -------

const testing = std.testing;

test "extractIdRaw numeric" {
    const line = "{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"x\"}";
    const id = extractIdRaw(line).?;
    try testing.expectEqualSlices(u8, "7", id);
}

test "extractIdRaw string" {
    const line = "{\"jsonrpc\":\"2.0\",\"id\":\"abc-1\",\"method\":\"x\"}";
    const id = extractIdRaw(line).?;
    try testing.expectEqualSlices(u8, "\"abc-1\"", id);
}

test "extractIdRaw missing" {
    const line = "{\"jsonrpc\":\"2.0\",\"method\":\"x\"}";
    try testing.expect(extractIdRaw(line) == null);
}

test "buildInitializeResult shape" {
    const a = testing.allocator;
    const out = try buildInitializeResult(a);
    defer a.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "\"protocolVersion\":\"2024-11-05\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"name\":\"secretctl\"") != null);
    try testing.expect(std.mem.indexOf(u8, out, "\"capabilities\":{\"tools\":{}}") != null);
}

test "buildToolsListResult safe mode" {
    const a = testing.allocator;
    const opts: Options = .{};
    const out = try buildToolsListResult(a, &opts);
    defer a.free(out);
    for (activeTools(&opts)) |t| {
        try testing.expect(std.mem.indexOf(u8, out, t.name) != null);
    }
    try testing.expect(std.mem.indexOf(u8, out, "get_secret") == null);
}

test "buildToolsListResult dangerous mode" {
    const a = testing.allocator;
    const opts: Options = .{ .dangerous = true };
    const out = try buildToolsListResult(a, &opts);
    defer a.free(out);
    try testing.expect(std.mem.indexOf(u8, out, "get_secret") != null);
    try testing.expect(std.mem.indexOf(u8, out, "list_secrets") != null);
}
