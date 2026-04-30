//! Wall-clock timestamp helper. Uses libc's `time(2)` to avoid threading
//! `Io` through every call site in 0.16. Unix seconds, signed, may be wound
//! back by the user — see SPEC: timestamps are not a security boundary.

const std = @import("std");

// time_t is 64-bit on macOS aarch64+x86_64 LP64.
extern "c" fn time(tloc: ?*i64) i64;

pub fn unixSeconds() i64 {
    return time(null);
}

test "unixSeconds is plausible" {
    const t = unixSeconds();
    // After 2024-01-01 and before 2100-01-01.
    try std.testing.expect(t > 1_704_067_200);
    try std.testing.expect(t < 4_102_444_800);
}
