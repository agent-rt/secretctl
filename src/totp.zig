//! RFC 6238 TOTP — the offline approval channel.
//!
//! What this is: a **consent gate**. Six digits carry about 20 bits, so a code
//! can never be key material — brute-forcing 10^6 against an AEAD tag is
//! instant. Verification therefore needs the seed stored locally, and anything
//! that can read the seed can mint codes.
//!
//! What makes that worth having anyway is M5 (`docs/2fa-design.md` §1.1): a
//! binary the keychain item's ACL does not name cannot read it. The seed lives
//! under that same ACL, so a hostile local process can neither read the seed
//! nor bypass this check — its only route to the vault is through this binary,
//! which enforces the gate. An earlier revision of the design doc dismissed
//! TOTP as "another `if` that does not move the adversary's cost"; that rested
//! on the over-read of M3 which M5 falsified.
//!
//! SHA-1, 6 digits, 30 s. Not a security choice — it is what every
//! authenticator app defaults to, and a seed nobody can enrol is worth nothing.
//! HMAC-SHA1 is not broken for this construction (it needs PRF, not collision
//! resistance).

const std = @import("std");
const clock = @import("clock.zig");
const mem_util = @import("mem.zig");

const HmacSha1 = std.crypto.auth.hmac.HmacSha1;

/// 20 bytes = one SHA-1 block worth of key, and what every authenticator
/// expects. Longer seeds are legal and silently unhelpful.
pub const seed_len = 20;
pub const digits = 6;
pub const period_s: i64 = 30;

/// How many steps either side of "now" are accepted. One step each way covers
/// the clock skew between a Mac and a phone plus the time it takes a human to
/// read six digits and paste them. Wider would multiply the replay surface for
/// no practical gain.
pub const skew_steps: i64 = 1;

pub const Error = error{
    /// The code did not match any accepted step.
    Mismatch,
    /// The code was right but has already been used. See `Consumed`.
    Replayed,
    /// Not six digits.
    Malformed,
};

/// One HOTP value (RFC 4226 §5.3) for an explicit counter.
///
/// Split out from `code()` because the RFC's test vectors are stated in terms
/// of the counter, so this is the function the tests can pin exactly.
pub fn hotp(seed: []const u8, counter: u64, n_digits: u32) u32 {
    var ctr: [8]u8 = undefined;
    std.mem.writeInt(u64, &ctr, counter, .big);

    var mac: [HmacSha1.mac_length]u8 = undefined;
    HmacSha1.create(&mac, &ctr, seed);

    // Dynamic truncation. The low nibble of the last byte picks the offset;
    // masking the high bit of the first byte keeps the result positive in
    // languages with signed 32-bit ints, and every implementation copies it.
    const offset: usize = mac[mac.len - 1] & 0x0f;
    const bin: u32 = (@as(u32, mac[offset] & 0x7f) << 24) |
        (@as(u32, mac[offset + 1]) << 16) |
        (@as(u32, mac[offset + 2]) << 8) |
        @as(u32, mac[offset + 3]);

    var modulus: u32 = 1;
    var i: u32 = 0;
    while (i < n_digits) : (i += 1) modulus *= 10;
    return bin % modulus;
}

/// The counter for a unix timestamp.
pub fn stepFor(unix_s: i64) u64 {
    // Negative time would wrap the cast. It cannot happen from clock.unixSeconds
    // on a sane host, but a garbage clock should not produce a valid-looking
    // step.
    if (unix_s < 0) return 0;
    return @intCast(@divFloor(unix_s, period_s));
}

/// Format a code zero-padded, which is how authenticators display it and how a
/// user will type it. `042317` must not become `42317`.
pub fn format(value: u32, out: *[digits]u8) void {
    var v = value;
    var i: usize = digits;
    while (i > 0) {
        i -= 1;
        out[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
    }
}

/// Constant-time comparison of two six-digit strings.
///
/// Six digits is a small space and a code is single-use, so a timing oracle
/// here is not the likeliest attack. It costs nothing to not have one.
fn eqlConstantTime(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

/// Which step a code matched, so the caller can record it against replay.
pub const Match = struct { step: u64 };

/// Verify `input` against the seed at `now`, accepting ±`skew_steps`.
///
/// `last_used` is the most recent step already spent; a match at or below it is
/// `Replayed` rather than `Mismatch`, because the two need different messages —
/// one means "wrong code", the other means "that one is gone, wait 30 s".
///
/// Replay protection is not optional here. The code travels through whatever
/// channel the operator used to hand it over — a chat window, a terminal
/// someone can scroll back — and stays valid for the rest of its step. Without
/// this, reading the transcript within 30 s is enough to unlock again.
pub fn verify(
    seed: []const u8,
    input: []const u8,
    now_unix_s: i64,
    last_used: ?u64,
) Error!Match {
    if (input.len != digits) return Error.Malformed;
    for (input) |c| if (c < '0' or c > '9') return Error.Malformed;

    const centre = stepFor(now_unix_s);
    var replayed = false;

    var d: i64 = -skew_steps;
    while (d <= skew_steps) : (d += 1) {
        const step_i: i64 = @as(i64, @intCast(centre)) + d;
        if (step_i < 0) continue;
        const step: u64 = @intCast(step_i);

        var buf: [digits]u8 = undefined;
        format(hotp(seed, step, digits), &buf);
        if (!eqlConstantTime(&buf, input)) continue;

        if (last_used) |used| {
            if (step <= used) {
                // Keep scanning: a later step in the window might also match
                // and still be unspent. Only report replay if nothing does.
                replayed = true;
                continue;
            }
        }
        return .{ .step = step };
    }
    return if (replayed) Error.Replayed else Error.Mismatch;
}

/// Verify against the host clock.
pub fn verifyNow(seed: []const u8, input: []const u8, last_used: ?u64) Error!Match {
    return verify(seed, input, clock.unixSeconds(), last_used);
}

// ---------------- base32 (RFC 4648) ----------------

const b32_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Encoded length, unpadded. Authenticator apps accept unpadded and it keeps
/// the otpauth URI free of `=` that would need percent-encoding.
pub fn base32Len(n: usize) usize {
    return (n * 8 + 4) / 5;
}

/// Encode `src` into `out`, which must be `base32Len(src.len)` bytes.
pub fn base32Encode(src: []const u8, out: []u8) void {
    std.debug.assert(out.len == base32Len(src.len));
    // u32 accumulator with an explicit bit count: 8 incoming bits plus at most
    // 4 left over never exceeds 12, so nothing can overflow, and the shift
    // amounts stay in range without casting gymnastics.
    var acc: u32 = 0;
    var bits: u5 = 0;
    var oi: usize = 0;
    for (src) |byte| {
        acc = (acc << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[oi] = b32_alphabet[(acc >> bits) & 0x1f];
            oi += 1;
        }
    }
    if (bits > 0) {
        out[oi] = b32_alphabet[(acc << (5 - bits)) & 0x1f];
        oi += 1;
    }
    std.debug.assert(oi == out.len);
}

/// Build the `otpauth://` URI an authenticator scans or imports.
///
/// `algorithm`, `digits` and `period` are stated explicitly even though they
/// are the defaults: some apps quietly assume different ones, and a URI that
/// enrols at the wrong period produces codes that never verify, with nothing
/// to point at.
pub fn otpauthUri(
    allocator: std.mem.Allocator,
    seed: []const u8,
    account_label: []const u8,
) ![]u8 {
    const b32 = try allocator.alloc(u8, base32Len(seed.len));
    defer {
        mem_util.secureZero(u8, b32);
        allocator.free(b32);
    }
    base32Encode(seed, b32);
    return std.fmt.allocPrint(
        allocator,
        "otpauth://totp/secretctl:{s}?secret={s}&issuer=secretctl&algorithm=SHA1&digits={d}&period={d}",
        .{ account_label, b32, digits, period_s },
    );
}

// ---------------- tests ----------------

const testing = std.testing;

test "RFC 6238 appendix B vectors, SHA-1" {
    // The RFC states 8-digit values for the seed "12345678901234567890".
    // Pinning the published vectors rather than self-generated ones is the
    // whole point: it proves interoperability with the authenticator apps that
    // have to produce these same codes, which a round-trip test cannot.
    const seed = "12345678901234567890";
    const cases = [_]struct { t: i64, want: u32 }{
        .{ .t = 59, .want = 94287082 },
        .{ .t = 1111111109, .want = 7081804 },
        .{ .t = 1111111111, .want = 14050471 },
        .{ .t = 1234567890, .want = 89005924 },
        .{ .t = 2000000000, .want = 69279037 },
        .{ .t = 20000000000, .want = 65353130 },
    };
    for (cases) |c| {
        try testing.expectEqual(c.want, hotp(seed, stepFor(c.t), 8));
    }
}

test "six-digit codes are the low six digits of the RFC vectors" {
    const seed = "12345678901234567890";
    try testing.expectEqual(@as(u32, 287082), hotp(seed, stepFor(59), 6));
    try testing.expectEqual(@as(u32, 81804), hotp(seed, stepFor(1111111109), 6));
}

test "format zero-pads" {
    var buf: [digits]u8 = undefined;
    format(81804, &buf);
    try testing.expectEqualStrings("081804", &buf);
    format(0, &buf);
    try testing.expectEqualStrings("000000", &buf);
    format(999999, &buf);
    try testing.expectEqualStrings("999999", &buf);
}

test "verify accepts the current step" {
    const seed = "12345678901234567890";
    const now: i64 = 1111111109;
    var buf: [digits]u8 = undefined;
    format(hotp(seed, stepFor(now), digits), &buf);
    const m = try verify(seed, &buf, now, null);
    try testing.expectEqual(stepFor(now), m.step);
}

test "verify accepts one step of skew either way, and rejects two" {
    const seed = "12345678901234567890";
    const now: i64 = 1111111109;
    const centre = stepFor(now);
    for ([_]i64{ -1, 0, 1 }) |d| {
        var buf: [digits]u8 = undefined;
        const step: u64 = @intCast(@as(i64, @intCast(centre)) + d);
        format(hotp(seed, step, digits), &buf);
        _ = try verify(seed, &buf, now, null);
    }
    for ([_]i64{ -2, 2 }) |d| {
        var buf: [digits]u8 = undefined;
        const step: u64 = @intCast(@as(i64, @intCast(centre)) + d);
        format(hotp(seed, step, digits), &buf);
        try testing.expectError(Error.Mismatch, verify(seed, &buf, now, null));
    }
}

test "a spent code is Replayed, not Mismatch" {
    // The distinction is the whole reason the caller tracks a step: a wrong
    // code and a reused one need different advice.
    const seed = "12345678901234567890";
    const now: i64 = 1111111109;
    const step = stepFor(now);
    var buf: [digits]u8 = undefined;
    format(hotp(seed, step, digits), &buf);

    _ = try verify(seed, &buf, now, null);
    try testing.expectError(Error.Replayed, verify(seed, &buf, now, step));
    // And anything older than the spent step is also refused.
    try testing.expectError(Error.Replayed, verify(seed, &buf, now, step + 5));
}

test "an unspent later step still verifies while an earlier one is spent" {
    // Guards the scan order: reporting Replayed on the first spent match would
    // reject a perfectly good newer code.
    const seed = "12345678901234567890";
    const now: i64 = 1111111109;
    const centre = stepFor(now);
    var buf: [digits]u8 = undefined;
    format(hotp(seed, centre + 1, digits), &buf);
    const m = try verify(seed, &buf, now, centre);
    try testing.expectEqual(centre + 1, m.step);
}

test "malformed input is refused before any comparison" {
    const seed = "12345678901234567890";
    try testing.expectError(Error.Malformed, verify(seed, "12345", 59, null));
    try testing.expectError(Error.Malformed, verify(seed, "1234567", 59, null));
    try testing.expectError(Error.Malformed, verify(seed, "12a456", 59, null));
    try testing.expectError(Error.Malformed, verify(seed, "", 59, null));
}

test "a different seed does not verify" {
    const now: i64 = 1111111109;
    var buf: [digits]u8 = undefined;
    format(hotp("12345678901234567890", stepFor(now), digits), &buf);
    try testing.expectError(Error.Mismatch, verify("09876543210987654321", &buf, now, null));
}

test "base32 matches RFC 4648 test vectors" {
    const cases = [_]struct { in: []const u8, want: []const u8 }{
        .{ .in = "", .want = "" },
        .{ .in = "f", .want = "MY" },
        .{ .in = "fo", .want = "MZXQ" },
        .{ .in = "foo", .want = "MZXW6" },
        .{ .in = "foob", .want = "MZXW6YQ" },
        .{ .in = "fooba", .want = "MZXW6YTB" },
        .{ .in = "foobar", .want = "MZXW6YTBOI" },
    };
    for (cases) |c| {
        const out = try testing.allocator.alloc(u8, base32Len(c.in.len));
        defer testing.allocator.free(out);
        base32Encode(c.in, out);
        try testing.expectEqualStrings(c.want, out);
    }
}

test "otpauth URI carries every parameter an app needs" {
    const a = testing.allocator;
    const uri = try otpauthUri(a, "12345678901234567890", "this-mac");
    defer a.free(uri);
    try testing.expect(std.mem.indexOf(u8, uri, "secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ") != null);
    try testing.expect(std.mem.indexOf(u8, uri, "algorithm=SHA1") != null);
    try testing.expect(std.mem.indexOf(u8, uri, "digits=6") != null);
    try testing.expect(std.mem.indexOf(u8, uri, "period=30") != null);
    try testing.expect(std.mem.indexOf(u8, uri, "issuer=secretctl") != null);
}

test "negative clock cannot produce a plausible step" {
    try testing.expectEqual(@as(u64, 0), stepFor(-1));
    try testing.expectEqual(@as(u64, 0), stepFor(-999999));
}
