const std = @import("std");
const cli = @import("cli.zig");

pub fn main(init: std.process.Init) u8 {
    const allocator = init.gpa;
    const argv_slice = init.minimal.args.toSlice(init.arena.allocator()) catch return 1;

    // Convert []const [:0]const u8 to []const []const u8 (drop sentinel).
    var args_buf = allocator.alloc([]const u8, argv_slice.len) catch return 1;
    defer allocator.free(args_buf);
    for (argv_slice, 0..) |a, i| args_buf[i] = a;

    return cli.run(allocator, args_buf);
}
