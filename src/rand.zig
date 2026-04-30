//! CSPRNG entropy source. macOS-only — uses arc4random_buf which is the
//! Apple-recommended kernel-backed entropy syscall. Cannot fail, so the API
//! is infallible (matches earlier std.crypto.random.bytes).

const std = @import("std");

extern "c" fn arc4random_buf(buf: [*]u8, nbytes: usize) void;

pub fn bytes(buf: []u8) void {
    if (buf.len == 0) return;
    arc4random_buf(buf.ptr, buf.len);
}

test "bytes fills slice with non-zero entropy" {
    var b: [64]u8 = undefined;
    @memset(&b, 0);
    bytes(&b);
    var any_nonzero = false;
    for (b) |x| if (x != 0) {
        any_nonzero = true;
        break;
    };
    try std.testing.expect(any_nonzero);
}
