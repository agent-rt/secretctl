//! Argon2id wrapper. Picks parameters appropriate for macOS-class hardware
//! and exposes a simple deriveKey() entry point.
//!
//! Parameter rationale (locked for v1; see TECH-DESIGN §6 once benchmarked):
//!   m = 65536 KiB (64 MiB) — well above OWASP minimum (19 MiB), still fits
//!     comfortably on every Mac sold this decade.
//!   t = 3 iterations — produces ~200-400 ms unlock time on Apple Silicon.
//!   p = 1 lane — single-user, single-core path is fine.
//! These values are persisted in the protector body, so changing the defaults
//! later does not lock out existing vaults.

const std = @import("std");

pub const Params = struct {
    m_kib: u32,
    t: u32,
    p: u24,
    /// Argon2 algorithm version, 0x13 = v1.3.
    version: u32 = 0x13,

    pub const default: Params = .{ .m_kib = 64 * 1024, .t = 3, .p = 1 };

    pub fn toStd(self: Params) std.crypto.pwhash.argon2.Params {
        return .{ .t = self.t, .m = self.m_kib, .p = self.p };
    }
};

pub const Error = error{
    OutOfMemory,
    WeakParameters,
    OutputTooLong,
    Unexpected,
};

/// Derive `out.len` bytes from `password` and `salt` using Argon2id.
/// `salt` must be at least 8 bytes; `out` at least 4 bytes.
pub fn deriveKey(
    allocator: std.mem.Allocator,
    password: []const u8,
    salt: []const u8,
    params: Params,
    out: []u8,
) Error!void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    std.crypto.pwhash.argon2.kdf(
        allocator,
        out,
        password,
        salt,
        params.toStd(),
        .argon2id,
        io,
    ) catch |err| switch (err) {
        error.OutOfMemory => return Error.OutOfMemory,
        error.WeakParameters => return Error.WeakParameters,
        error.OutputTooLong => return Error.OutputTooLong,
        else => return Error.Unexpected,
    };
}

test "deriveKey produces stable output for fixed input" {
    const a = std.testing.allocator;
    // Use weakest acceptable params to keep tests fast.
    const params: Params = .{ .m_kib = 8, .t = 1, .p = 1 };
    const password = "hunter2hunter2";
    const salt = "saltysalt";
    var k1: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    try deriveKey(a, password, salt, params, &k1);
    try deriveKey(a, password, salt, params, &k2);
    try std.testing.expectEqualSlices(u8, &k1, &k2);
}

test "deriveKey is sensitive to password" {
    const a = std.testing.allocator;
    const params: Params = .{ .m_kib = 8, .t = 1, .p = 1 };
    const salt = "saltysalt";
    var k1: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    try deriveKey(a, "passworda", salt, params, &k1);
    try deriveKey(a, "passwordb", salt, params, &k2);
    try std.testing.expect(!std.mem.eql(u8, &k1, &k2));
}

test "deriveKey is sensitive to salt" {
    const a = std.testing.allocator;
    const params: Params = .{ .m_kib = 8, .t = 1, .p = 1 };
    const password = "samepassword";
    var k1: [32]u8 = undefined;
    var k2: [32]u8 = undefined;
    try deriveKey(a, password, "salt-A--", params, &k1);
    try deriveKey(a, password, "salt-B--", params, &k2);
    try std.testing.expect(!std.mem.eql(u8, &k1, &k2));
}
