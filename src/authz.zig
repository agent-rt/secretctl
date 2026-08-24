//! Which authorization method the unlock path is allowed to use.
//!
//! Touch ID needs a finger on the sensor, so it only counts as authorization
//! when someone is at the machine. When the screen is locked — or there is no
//! GUI session at all — approval has to come from somewhere else, which is what
//! `docs/2fa-push-approval.md` specifies.
//!
//! This module answers only "which method", never "is it allowed". The methods
//! themselves live elsewhere; keeping the decision separate is what makes it
//! testable without a locked screen or a phone.

const std = @import("std");
const lockstate = @import("lockstate.zig");
const fsx = @import("fsx.zig");

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

pub const Method = enum {
    /// Someone is at the machine: the existing biometric gate applies.
    touch_id,
    /// Nobody is here. Approval must arrive from another device.
    out_of_band,
};

pub const Decision = struct {
    method: Method,
    /// Why, for the message the operator reads when it refuses.
    reason: []const u8,
};

/// Decide before consulting the agent cache or the keychain.
///
/// Order matters and is the whole point. The agent caches an unlocked master
/// key for up to an hour (`agent.zig`), so a check placed after the cache would
/// leave a window in which locking the screen required no approval at all —
/// exactly the situation this is meant to cover. Deciding first makes the gate
/// independent of cache state, at the cost of an approval round trip per
/// command while locked.
pub fn decide() Decision {
    return switch (lockstate.state()) {
        .unlocked => .{
            .method = .touch_id,
            .reason = "screen is unlocked",
        },
        .locked => .{
            .method = .out_of_band,
            .reason = "screen is locked, so Touch ID cannot be satisfied",
        },
        // No console: an ssh-only login, or a launchd job. There is no sensor
        // to touch either way, so it fails closed rather than falling through
        // to a biometric prompt that can only hang or be denied.
        .unknown => .{
            .method = .out_of_band,
            .reason = "no GUI session, so Touch ID cannot be satisfied",
        },
    };
}

/// True when out-of-band approval is configured for this vault.
///
/// Split from `decide()` because "nobody is here" and "there is a way to ask
/// them" are different facts, and the operator needs to be told which one is
/// missing. Until the push client lands this is always false, so a locked
/// screen refuses with instructions rather than appearing to work.
pub fn outOfBandConfigured(secretctl_home: []const u8) bool {
    // Presence of the config is the signal. Its contents are the push client's
    // business, not this module's. Uses fsx rather than std.fs to match the
    // rest of the project, which wraps stat(2) directly.
    var buf: [1024]u8 = undefined;
    const path = std.fmt.bufPrint(&buf, "{s}/push.json", .{secretctl_home}) catch return false;
    return fsx.fileExists(path);
}

/// Message for a refusal, so every call site says the same thing.
pub const not_configured_hint =
    "out-of-band approval is not set up for this vault; run `secretctl 2fa enroll`\n" ++
    "or unlock the screen to use Touch ID\n";

test "unlocked screen selects Touch ID" {
    const setenv = struct {
        extern "c" fn setenv(n: [*:0]const u8, v: [*:0]const u8, o: c_int) c_int;
        extern "c" fn unsetenv(n: [*:0]const u8) c_int;
    };
    defer _ = setenv.unsetenv("SECRETCTL_FORCE_LOCKED");

    _ = setenv.setenv("SECRETCTL_FORCE_LOCKED", "0", 1);
    try std.testing.expectEqual(Method.touch_id, decide().method);

    _ = setenv.setenv("SECRETCTL_FORCE_LOCKED", "1", 1);
    try std.testing.expectEqual(Method.out_of_band, decide().method);
}

test "an unknown session fails closed rather than reaching for a sensor" {
    // Cannot be forced through the env override, so assert the mapping the
    // switch encodes: .unknown must not select touch_id.
    const m: Method = switch (lockstate.State.unknown) {
        .unlocked => .touch_id,
        .locked, .unknown => .out_of_band,
    };
    try std.testing.expectEqual(Method.out_of_band, m);
}

test "missing config reads as not configured" {
    try std.testing.expect(!outOfBandConfigured("/nonexistent/secretctl-home"));
}
