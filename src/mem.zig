//! Plaintext type and best-effort secure memory zeroing.
//!
//! Plaintext owns a buffer that is zeroed on deinit. The type intentionally
//! has no Display/Format implementation — printing it should be a compile
//! error in user code, surfacing accidental leaks at review time.
//!
//! secureZero wraps std.crypto.utils.secureZero, which uses a volatile-write
//! loop that the compiler cannot legally elide. Verify with objdump.

const std = @import("std");

pub fn secureZero(comptime T: type, slice: []T) void {
    std.crypto.secureZero(T, slice);
}

pub const Plaintext = struct {
    bytes: []u8,
    allocator: std.mem.Allocator,

    /// Take ownership of an existing buffer. The buffer must have been
    /// allocated by `allocator` and will be zeroed + freed on deinit.
    pub fn fromOwnedSlice(allocator: std.mem.Allocator, bytes: []u8) Plaintext {
        return .{ .bytes = bytes, .allocator = allocator };
    }

    /// Allocate a zero-filled buffer of `len` bytes.
    pub fn initLen(allocator: std.mem.Allocator, n: usize) !Plaintext {
        const buf = try allocator.alloc(u8, n);
        @memset(buf, 0);
        return .{ .bytes = buf, .allocator = allocator };
    }

    /// Copy `src` into a new allocation owned by the Plaintext.
    pub fn dupe(allocator: std.mem.Allocator, src: []const u8) !Plaintext {
        const buf = try allocator.alloc(u8, src.len);
        @memcpy(buf, src);
        return .{ .bytes = buf, .allocator = allocator };
    }

    pub fn deinit(self: *Plaintext) void {
        secureZero(u8, self.bytes);
        self.allocator.free(self.bytes);
        self.bytes = &.{};
    }

    pub fn len(self: *const Plaintext) usize {
        return self.bytes.len;
    }
};

test "Plaintext.initLen zeros buffer" {
    const a = std.testing.allocator;
    var pt = try Plaintext.initLen(a, 32);
    defer pt.deinit();
    try std.testing.expectEqual(@as(usize, 32), pt.len());
    for (pt.bytes) |b| try std.testing.expectEqual(@as(u8, 0), b);
}

test "Plaintext.dupe copies bytes" {
    const a = std.testing.allocator;
    var pt = try Plaintext.dupe(a, "hello");
    defer pt.deinit();
    try std.testing.expectEqualSlices(u8, "hello", pt.bytes);
}

test "Plaintext.fromOwnedSlice takes ownership" {
    const a = std.testing.allocator;
    const buf = try a.alloc(u8, 16);
    @memset(buf, 0xAA);
    var pt = Plaintext.fromOwnedSlice(a, buf);
    defer pt.deinit();
    for (pt.bytes) |b| try std.testing.expectEqual(@as(u8, 0xAA), b);
}

test "secureZero clears bytes" {
    var buf: [64]u8 = undefined;
    @memset(&buf, 0xFF);
    secureZero(u8, &buf);
    for (buf) |b| try std.testing.expectEqual(@as(u8, 0), b);
}
