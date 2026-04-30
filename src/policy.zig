//! Project-level allowlist for `secretctl exec`. Reads `.secretctl.toml`
//! from the current working directory upward, parses the `[allow]` table,
//! and exposes membership predicates.
//!
//! Format (intentionally minimal — not a general TOML parser):
//!
//!   [allow]
//!   tags     = ["npm", "github"]
//!   commands = ["npm", "yarn", "pnpm", "gh", "curl", "node"]
//!
//! Anything outside `[allow]` is ignored. Whitespace and `#` comments OK.

const std = @import("std");
const fsx = @import("fsx.zig");

pub const Policy = struct {
    /// Allocator used for owned strings.
    allocator: std.mem.Allocator,
    /// nil ↦ "no policy file in scope". When nil, exec falls back to
    /// CLI-only checks.
    present: bool,
    tags: [][]u8,
    commands: [][]u8,
    /// Path that was loaded; for diagnostics. May be empty when present=false.
    source: []u8,

    pub fn deinit(self: *Policy) void {
        for (self.tags) |t| self.allocator.free(t);
        self.allocator.free(self.tags);
        for (self.commands) |c| self.allocator.free(c);
        self.allocator.free(self.commands);
        self.allocator.free(self.source);
    }

    pub fn allowsTag(self: *const Policy, name: []const u8) bool {
        if (!self.present) return true;
        for (self.tags) |t| if (std.ascii.eqlIgnoreCase(t, name)) return true;
        return false;
    }

    pub fn allowsCommand(self: *const Policy, argv0: []const u8) bool {
        if (!self.present) return true;
        const base = std.fs.path.basename(argv0);
        for (self.commands) |c| if (std.mem.eql(u8, c, base)) return true;
        return false;
    }
};

pub const empty: Policy = .{
    .allocator = undefined,
    .present = false,
    .tags = &.{},
    .commands = &.{},
    .source = &.{},
};

/// Walk up from `start_dir` looking for `.secretctl.toml`. Returns Policy
/// with `present=false` when none is found.
pub fn load(allocator: std.mem.Allocator, start_dir: []const u8) !Policy {
    var dir_buf: [1024]u8 = undefined;
    @memcpy(dir_buf[0..start_dir.len], start_dir);
    var dir_len = start_dir.len;

    while (true) {
        const candidate_len = dir_len + 1 + ".secretctl.toml".len;
        if (candidate_len >= dir_buf.len) break;
        var path_buf: [1024]u8 = undefined;
        @memcpy(path_buf[0..dir_len], dir_buf[0..dir_len]);
        path_buf[dir_len] = '/';
        @memcpy(path_buf[dir_len + 1 ..][0..".secretctl.toml".len], ".secretctl.toml");
        const path = path_buf[0..candidate_len];

        if (fsx.fileExists(path)) {
            const content = fsx.readAllAlloc(allocator, path, 64 * 1024) catch break;
            defer allocator.free(content);
            return try parse(allocator, content, path);
        }

        // Move up one directory.
        if (dir_len == 0 or (dir_len == 1 and dir_buf[0] == '/')) break;
        var i: usize = dir_len;
        while (i > 0 and dir_buf[i - 1] != '/') : (i -= 1) {}
        if (i == 0) break;
        if (i == 1) {
            dir_len = 1;
        } else {
            dir_len = i - 1;
        }
    }

    return Policy{
        .allocator = allocator,
        .present = false,
        .tags = &.{},
        .commands = &.{},
        .source = try allocator.dupe(u8, ""),
    };
}

pub fn parse(allocator: std.mem.Allocator, content: []const u8, source_path: []const u8) !Policy {
    var tags: std.ArrayList([]u8) = .empty;
    var commands: std.ArrayList([]u8) = .empty;
    errdefer {
        for (tags.items) |t| allocator.free(t);
        tags.deinit(allocator);
        for (commands.items) |c| allocator.free(c);
        commands.deinit(allocator);
    }

    var in_allow = false;
    var line_iter = std.mem.splitScalar(u8, content, '\n');
    while (line_iter.next()) |raw_line| {
        const line = stripComment(std.mem.trim(u8, raw_line, " \t\r"));
        if (line.len == 0) continue;
        if (line[0] == '[' and line[line.len - 1] == ']') {
            const section = std.mem.trim(u8, line[1 .. line.len - 1], " \t");
            in_allow = std.mem.eql(u8, section, "allow");
            continue;
        }
        if (!in_allow) continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (value.len == 0 or value[0] != '[' or value[value.len - 1] != ']') continue;
        const inner = value[1 .. value.len - 1];

        var into = if (std.mem.eql(u8, key, "tags")) &tags else if (std.mem.eql(u8, key, "commands")) &commands else continue;
        var item_iter = std.mem.tokenizeScalar(u8, inner, ',');
        while (item_iter.next()) |raw_item| {
            const trimmed = std.mem.trim(u8, raw_item, " \t");
            if (trimmed.len < 2) continue;
            if (trimmed[0] != '"' or trimmed[trimmed.len - 1] != '"') continue;
            const s = trimmed[1 .. trimmed.len - 1];
            const dup = try allocator.dupe(u8, s);
            try into.append(allocator, dup);
        }
    }

    return Policy{
        .allocator = allocator,
        .present = true,
        .tags = try tags.toOwnedSlice(allocator),
        .commands = try commands.toOwnedSlice(allocator),
        .source = try allocator.dupe(u8, source_path),
    };
}

fn stripComment(s: []const u8) []const u8 {
    var in_string = false;
    for (s, 0..) |c, i| {
        if (c == '"') in_string = !in_string;
        if (c == '#' and !in_string) return std.mem.trim(u8, s[0..i], " \t");
    }
    return s;
}

const testing = std.testing;

test "no policy file → present=false, allows all" {
    const a = testing.allocator;
    var p = try load(a, "/tmp/secretctl-no-policy-xyz-12345");
    defer p.deinit();
    try testing.expectEqual(false, p.present);
    try testing.expectEqual(true, p.allowsTag("anything"));
    try testing.expectEqual(true, p.allowsCommand("/bin/sh"));
}

test "parse [allow]" {
    const a = testing.allocator;
    const text =
        \\# top comment
        \\[other]
        \\foo = ["x"]
        \\
        \\[allow]
        \\tags = ["npm", "github"]
        \\commands = ["npm", "yarn", "gh"]
    ;
    var p = try parse(a, text, "<test>");
    defer p.deinit();
    try testing.expectEqual(true, p.present);
    try testing.expectEqual(true, p.allowsTag("npm"));
    try testing.expectEqual(true, p.allowsTag("NPM"));
    try testing.expectEqual(false, p.allowsTag("aws"));
    try testing.expectEqual(true, p.allowsCommand("/usr/local/bin/npm"));
    try testing.expectEqual(true, p.allowsCommand("yarn"));
    try testing.expectEqual(false, p.allowsCommand("/bin/sh"));
}

test "command match is by basename only" {
    const a = testing.allocator;
    const text =
        \\[allow]
        \\commands = ["curl"]
    ;
    var p = try parse(a, text, "<t>");
    defer p.deinit();
    try testing.expectEqual(true, p.allowsCommand("/usr/bin/curl"));
    try testing.expectEqual(true, p.allowsCommand("./curl"));
    try testing.expectEqual(false, p.allowsCommand("curll"));
    try testing.expectEqual(false, p.allowsCommand("sh -c curl"));
}
