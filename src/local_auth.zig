//! LocalAuthentication bridge — biometric (Touch ID) prompt for unlock and
//! `get_secret`. The actual ObjC code lives in `local_auth.m`; this file is
//! a thin extern wrapper plus a Zig-friendly API.
//!
//! Why ObjC: the LAContext API uses Objective-C blocks for its async reply,
//! and dispatch_semaphore to pin it down to a synchronous call. Hand-rolling
//! both via objc_msgSend in Zig is significantly more code and several
//! footguns (Block_layout struct, _NSConcreteGlobalBlock, NSString lifetime)
//! than just letting the system Objective-C compiler handle it.

const std = @import("std");

extern "c" fn secretctl_la_available() c_int;
extern "c" fn secretctl_la_evaluate(reason: [*:0]const u8) c_int;

/// True if Touch ID / Face ID is available and enrolled on this device.
pub fn available() bool {
    return secretctl_la_available() == 1;
}

/// Synchronously prompt for biometric authentication. Blocks until the user
/// responds (success / cancel) or the OS times out. Returns true on success.
/// `reason` is shown in the system prompt; passed as a NUL-terminated string.
pub fn evaluate(reason: [*:0]const u8) bool {
    return secretctl_la_evaluate(reason) == 1;
}

test "available is callable" {
    // We don't assert true/false because CI runners may or may not have
    // Touch ID hardware; just call into it to make sure the FFI links.
    _ = available();
}
