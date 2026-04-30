//! Plain-text table renderer for `secretctl list`. ANSI color when stdout is
//! a tty; LF-separated, value-free output for pipes.

const std = @import("std");
const vault = @import("vault.zig");
const tty = @import("tty.zig");

const reset = "\x1b[0m";
const dim = "\x1b[2m";
const bold = "\x1b[1m";

pub fn renderTable(allocator: std.mem.Allocator, body: *const vault.VaultBody) !void {
    const colorize = tty.isStdoutTty();
    var name_w: usize = 4;
    for (body.secrets.items) |s| if (s.name.len > name_w) {
        name_w = s.name.len;
    };
    if (name_w > 40) name_w = 40;

    var tag_w: usize = 4;
    for (body.secrets.items) |s| {
        var l: usize = 0;
        for (s.tags, 0..) |t, i| {
            l += t.len;
            if (i + 1 < s.tags.len) l += 2;
        }
        if (l > tag_w) tag_w = l;
    }
    if (tag_w > 40) tag_w = 40;

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);

    if (colorize) try out.appendSlice(allocator, bold);
    try padTo(&out, allocator, "NAME", name_w);
    try out.appendSlice(allocator, "  ");
    try padTo(&out, allocator, "TAGS", tag_w);
    try out.appendSlice(allocator, "  UPDATED\n");
    if (colorize) try out.appendSlice(allocator, reset);

    for (body.secrets.items) |s| {
        var tag_buf: [256]u8 = undefined;
        var tw: usize = 0;
        for (s.tags, 0..) |t, i| {
            const need = t.len + (if (i + 1 < s.tags.len) @as(usize, 2) else 0);
            if (tw + need > tag_buf.len) break;
            @memcpy(tag_buf[tw .. tw + t.len], t);
            tw += t.len;
            if (i + 1 < s.tags.len) {
                @memcpy(tag_buf[tw .. tw + 2], ", ");
                tw += 2;
            }
        }
        const tags_str = tag_buf[0..tw];

        try padTo(&out, allocator, s.name, name_w);
        try out.appendSlice(allocator, "  ");
        try padTo(&out, allocator, tags_str, tag_w);
        try out.appendSlice(allocator, "  ");
        if (colorize) try out.appendSlice(allocator, dim);
        try out.print(allocator, "{d}\n", .{s.updated_at});
        if (colorize) try out.appendSlice(allocator, reset);
    }

    tty.writeStdout(out.items);
}

fn padTo(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8, w: usize) !void {
    try out.appendSlice(allocator, s);
    if (s.len < w) {
        var i: usize = s.len;
        while (i < w) : (i += 1) try out.append(allocator, ' ');
    }
}

pub fn renderJson(allocator: std.mem.Allocator, body: *const vault.VaultBody) !void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(allocator);
    try out.append(allocator, '[');
    for (body.secrets.items, 0..) |s, i| {
        if (i > 0) try out.append(allocator, ',');
        try out.appendSlice(allocator, "{\"name\":");
        try writeJsonString(&out, allocator, s.name);
        try out.appendSlice(allocator, ",\"tags\":[");
        for (s.tags, 0..) |t, j| {
            if (j > 0) try out.append(allocator, ',');
            try writeJsonString(&out, allocator, t);
        }
        try out.print(allocator, "],\"created_at\":{d},\"updated_at\":{d}", .{ s.created_at, s.updated_at });
        try out.append(allocator, '}');
    }
    try out.appendSlice(allocator, "]\n");
    tty.writeStdout(out.items);
}

fn writeJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, s: []const u8) !void {
    try out.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            else => {
                if (c < 0x20) {
                    var buf: [6]u8 = undefined;
                    const escaped = std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{c}) catch unreachable;
                    try out.appendSlice(allocator, escaped);
                } else {
                    try out.append(allocator, c);
                }
            },
        }
    }
    try out.append(allocator, '"');
}
