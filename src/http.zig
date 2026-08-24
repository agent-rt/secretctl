//! Thin Zig wrapper over the NSURLSession bridge in `http.m`.
//!
//! The response buffer is caller-owned and nothing crosses the boundary
//! allocated, so there is no free() to forget on either side.

const std = @import("std");

extern "c" fn secretctl_http(
    method: [*:0]const u8,
    url: [*:0]const u8,
    headers: [*:0]const u8,
    body: ?[*]const u8,
    body_len: usize,
    timeout_ms: c_int,
    out_status: *c_int,
    out_buf: ?[*]u8,
    out_cap: usize,
    out_len: *usize,
) c_int;

pub const Error = error{
    BadArgs,
    Transport,
    Timeout,
    ResponseTooLarge,
    OutOfMemory,
};

pub const Response = struct {
    status: u16,
    /// Owned by the caller-supplied allocator.
    body: []u8,

    pub fn deinit(self: Response, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
    }

    pub fn ok(self: Response) bool {
        return self.status >= 200 and self.status < 300;
    }
};

pub const Request = struct {
    method: []const u8 = "GET",
    url: []const u8,
    /// "Key: Value\n" lines. Built by the caller; see headerList.
    headers: []const u8 = "",
    body: []const u8 = "",
    /// Must exceed the service's hold (25 s) for the waiting call, or every
    /// wait would look like a timeout.
    timeout_ms: c_int = 15_000,
    /// Approval payloads are small envelopes; a cap keeps a hostile or broken
    /// service from being able to make this allocate without bound.
    max_response: usize = 256 * 1024,
};

pub fn send(allocator: std.mem.Allocator, req: Request) Error!Response {
    const method_z = allocator.dupeZ(u8, req.method) catch return Error.OutOfMemory;
    defer allocator.free(method_z);
    const url_z = allocator.dupeZ(u8, req.url) catch return Error.OutOfMemory;
    defer allocator.free(url_z);
    const headers_z = allocator.dupeZ(u8, req.headers) catch return Error.OutOfMemory;
    defer allocator.free(headers_z);

    const buf = allocator.alloc(u8, req.max_response) catch return Error.OutOfMemory;
    errdefer allocator.free(buf);

    var status: c_int = 0;
    var out_len: usize = 0;
    const rc = secretctl_http(
        method_z,
        url_z,
        headers_z,
        if (req.body.len > 0) req.body.ptr else null,
        req.body.len,
        req.timeout_ms,
        &status,
        buf.ptr,
        buf.len,
        &out_len,
    );

    switch (rc) {
        0 => {},
        -1 => return Error.BadArgs,
        -3 => return Error.Timeout,
        -4 => return Error.ResponseTooLarge,
        else => return Error.Transport,
    }

    // Shrink to what arrived. The caller frees whatever comes back.
    const body = allocator.realloc(buf, out_len) catch buf[0..out_len];
    return .{ .status = @intCast(status), .body = body };
}

/// Build a "Key: Value\n" blob. Caller owns the result.
pub fn headerList(
    allocator: std.mem.Allocator,
    pairs: []const [2][]const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (pairs) |kv| {
        // A newline or colon smuggled into a header value would let a caller
        // inject additional headers. Values here are ids and base64url, so
        // rejecting is right and silently stripping would hide a bug.
        if (std.mem.indexOfAny(u8, kv[1], "\r\n") != null) return error.BadHeaderValue;
        try out.appendSlice(allocator, kv[0]);
        try out.appendSlice(allocator, ": ");
        try out.appendSlice(allocator, kv[1]);
        try out.append(allocator, '\n');
    }
    return out.toOwnedSlice(allocator);
}

test "headerList formats and rejects injected newlines" {
    const a = std.testing.allocator;

    const h = try headerList(a, &.{
        .{ "X-Nudge-Client", "abc" },
        .{ "content-type", "application/json" },
    });
    defer a.free(h);
    try std.testing.expectEqualStrings(
        "X-Nudge-Client: abc\ncontent-type: application/json\n", h);

    try std.testing.expectError(error.BadHeaderValue, headerList(a, &.{
        .{ "X-Nudge-Sig", "abc\r\nX-Nudge-Client: someone-else" },
    }));
}

test "plaintext http is refused before any connection is attempted" {
    const a = std.testing.allocator;
    // Signed requests and sealed bodies must never go out in clear, and the
    // only way such a URL reaches here is a mistake or a tampered config.
    try std.testing.expectError(Error.BadArgs, send(a, .{
        .url = "http://example.invalid/v1/health",
        .timeout_ms = 1000,
    }));
}
