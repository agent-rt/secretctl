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

test "resolve uses HOME by default" {
    const a = testing.allocator;
    var p = try resolve(a);
    defer p.deinit();
    try testing.expect(std.mem.endsWith(u8, p.home, "/.secretctl"));
    try testing.expect(std.mem.endsWith(u8, p.vault, "/.secretctl/vault"));
}
