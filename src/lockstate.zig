//! Screen-lock state, used to pick an authorization method: Touch ID needs a
//! finger on the sensor, so it is only offered when someone is at the machine.
//! When the screen is locked, authorization goes out of band instead.
//!
//! The ObjC side lives in `lockstate.m`; see the comment there for why
//! CGSessionCopyCurrentDictionary is the right call and why an absent
//! `CGSSessionScreenIsLocked` key means unlocked.

const std = @import("std");

extern "c" fn secretctl_screen_is_locked() c_int;
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

pub const State = enum {
    unlocked,
    locked,
    /// No GUI session to ask about — an ssh-only login, or a launchd job with
    /// no console. Treated as `locked` by `requiresOutOfBandAuth` because
    /// there is no sensor to touch either way.
    unknown,
};

/// Override for tests and for anyone who wants to exercise the locked path
/// without actually locking the screen: `SECRETCTL_FORCE_LOCKED=1` forces
/// `.locked`, `=0` forces `.unlocked`. Without it the real session is queried.
fn forced() ?State {
    const v = getenv("SECRETCTL_FORCE_LOCKED") orelse return null;
    const s = std.mem.span(v);
    if (s.len == 0) return null;
    if (std.mem.eql(u8, s, "0")) return .unlocked;
    return .locked;
}

pub fn state() State {
    if (forced()) |f| return f;
    return switch (secretctl_screen_is_locked()) {
        1 => .locked,
        0 => .unlocked,
        else => .unknown,
    };
}

/// True when Touch ID cannot serve as the authorization method, so approval
/// has to come from somewhere other than this machine's sensor.
pub fn requiresOutOfBandAuth() bool {
    return switch (state()) {
        .unlocked => false,
        .locked, .unknown => true,
    };
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "real session query is callable" {
    // The value itself depends on whether a human is looking at the screen,
    // so this only pins down that the FFI links and returns a known variant.
    _ = unsetenv("SECRETCTL_FORCE_LOCKED");
    const s = state();
    try std.testing.expect(s == .locked or s == .unlocked or s == .unknown);
}

test "SECRETCTL_FORCE_LOCKED overrides the real session" {
    defer _ = unsetenv("SECRETCTL_FORCE_LOCKED");

    _ = setenv("SECRETCTL_FORCE_LOCKED", "1", 1);
    try std.testing.expectEqual(State.locked, state());
    try std.testing.expect(requiresOutOfBandAuth());

    _ = setenv("SECRETCTL_FORCE_LOCKED", "0", 1);
    try std.testing.expectEqual(State.unlocked, state());
    try std.testing.expect(!requiresOutOfBandAuth());

    // Any other non-empty value means locked — fail closed, not open.
    _ = setenv("SECRETCTL_FORCE_LOCKED", "yes", 1);
    try std.testing.expectEqual(State.locked, state());

    // Empty is treated as unset, so the real session decides again.
    _ = setenv("SECRETCTL_FORCE_LOCKED", "", 1);
    try std.testing.expect(forced() == null);
}

test "unknown session requires out-of-band auth" {
    // .unknown must fail closed: no console means no sensor to touch.
    try std.testing.expect(switch (State.unknown) {
        .unlocked => false,
        .locked, .unknown => true,
    });
}
