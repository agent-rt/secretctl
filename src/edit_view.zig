//! Secret-entry prompt flow. Replaces the originally-planned libvaxis edit
//! view (see SPEC architecture note in tty.zig). The flow is:
//!   1. show name (already chosen on the CLI)
//!   2. prompt for value with non-echoing input (Plaintext result)
//!   3. prompt for tags (comma-separated, single line, plain echo)

const std = @import("std");
const tty = @import("tty.zig");
const mem_util = @import("mem.zig");

pub const Result = struct {
    value: mem_util.Plaintext,
    /// Owned slice of owned slices.
    tags: [][]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Result) void {
        self.value.deinit();
        for (self.tags) |t| self.allocator.free(t);
        self.allocator.free(self.tags);
        self.tags = &.{};
    }
};

pub const Error = tty.ReadError || error{NoTty};

/// Prompt the user for a secret value and tag list. Tags may be omitted with
/// `--tag` already provided on the CLI; pass an empty `extra_tags` slice
/// when the caller wants to keep the CLI-provided tags only.
extern "c" fn getenv(name: [*:0]const u8) ?[*:0]const u8;

pub fn prompt(
    allocator: std.mem.Allocator,
    name: []const u8,
    cli_tags: []const []const u8,
) Error!Result {
    if (!tty.isStdinTty() and getenv("SECRETCTL_BATCH") == null) return error.NoTty;

    var name_buf: [128]u8 = undefined;
    const name_line = std.fmt.bufPrint(&name_buf, "Name:        {s}\n", .{name}) catch name;
    tty.writeStdout(name_line);
    var value = try tty.readPassword(allocator, "Value:       ");

    // If the CLI already supplied tags, skip prompting; otherwise ask.
    var tags_owned: std.ArrayList([]u8) = .empty;
    errdefer {
        for (tags_owned.items) |t| allocator.free(t);
        tags_owned.deinit(allocator);
        value.deinit();
    }

    if (cli_tags.len > 0) {
        for (cli_tags) |t| {
            const dup = allocator.dupe(u8, t) catch return error.OutOfMemory;
            tags_owned.append(allocator, dup) catch return error.OutOfMemory;
        }
    } else {
        tty.writeStdout("Tags (comma-separated, optional): ");
        const line = try tty.readLine(allocator, 256);
        defer allocator.free(line);
        var it = std.mem.tokenizeScalar(u8, line, ',');
        while (it.next()) |raw| {
            const trimmed = std.mem.trim(u8, raw, " \t");
            if (trimmed.len == 0) continue;
            const dup = allocator.dupe(u8, trimmed) catch return error.OutOfMemory;
            tags_owned.append(allocator, dup) catch return error.OutOfMemory;
        }
    }

    const tags_slice = tags_owned.toOwnedSlice(allocator) catch return error.OutOfMemory;
    return .{ .value = value, .tags = tags_slice, .allocator = allocator };
}
