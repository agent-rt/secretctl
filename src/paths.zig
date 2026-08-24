//! Resolve standard secretctl paths under $SECRETCTL_HOME (default ~/.secretctl).

const std = @import("std");

extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

pub const Paths = struct {
    home: []u8,
    vault: []u8,
    master_key: []u8,
    config: []u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Paths) void {
        self.allocator.free(self.home);
        self.allocator.free(self.vault);
        self.allocator.free(self.master_key);
        self.allocator.free(self.config);
    }
};

pub fn resolve(allocator: std.mem.Allocator) !Paths {
    const home: []u8 = if (getenv("SECRETCTL_HOME")) |h| blk: {
        const s = std.mem.span(h);
        break :blk try allocator.dupe(u8, s);
    } else if (getenv("HOME")) |h| blk: {
        const s = std.mem.span(h);
        break :blk try std.fmt.allocPrint(allocator, "{s}/.secretctl", .{s});
    } else try allocator.dupe(u8, "");
    errdefer allocator.free(home);

    const vault = try std.fmt.allocPrint(allocator, "{s}/vault", .{home});
    errdefer allocator.free(vault);
    const master_key = try std.fmt.allocPrint(allocator, "{s}/master.key", .{home});
    errdefer allocator.free(master_key);
    const config = try std.fmt.allocPrint(allocator, "{s}/config.toml", .{home});

    return .{
        .home = home,
        .vault = vault,
        .master_key = master_key,
        .config = config,
        .allocator = allocator,
    };
}

const testing = std.testing;

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;

test "resolve uses HOME by default" {
    // Pinned, because this asserts the *default* and $SECRETCTL_HOME overrides
    // it: with that variable exported — which anyone driving a test vault has
    // done — this failed for a reason that had nothing to do with the code.
    // Same discipline as the e2e suites pinning SECRETCTL_FORCE_LOCKED.
    const saved = std.c.getenv("SECRETCTL_HOME");
    defer if (saved) |v| {
        _ = setenv("SECRETCTL_HOME", v, 1);
    } else {
        _ = unsetenv("SECRETCTL_HOME");
    };
    _ = unsetenv("SECRETCTL_HOME");

    const a = testing.allocator;
    var p = try resolve(a);
    defer p.deinit();
    try testing.expect(std.mem.endsWith(u8, p.home, "/.secretctl"));
    try testing.expect(std.mem.endsWith(u8, p.vault, "/.secretctl/vault"));
}

test "SECRETCTL_HOME overrides the default" {
    // The override had no test at all, which is why nothing noticed that the
    // one above depended on it being unset.
    defer _ = unsetenv("SECRETCTL_HOME");
    _ = setenv("SECRETCTL_HOME", "/tmp/secretctl-paths-test", 1);

    const a = testing.allocator;
    var p = try resolve(a);
    defer p.deinit();
    try testing.expectEqualStrings("/tmp/secretctl-paths-test", p.home);
    try testing.expectEqualStrings("/tmp/secretctl-paths-test/vault", p.vault);
}
