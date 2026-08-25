//! Terminal QR rendering. The matrix comes from CoreImage (`qr.m`); this turns
//! it into something a phone camera can read off a terminal.
//!
//! Half-block characters, two module rows per text row. A terminal cell is
//! roughly twice as tall as it is wide, so one module per cell produces a QR
//! stretched 2:1 vertically — which scanners do reject. `▀` with independent
//! foreground and background colours gives square modules and halves the height.
//!
//! Colours are set explicitly rather than inherited. A QR drawn in the
//! terminal's own palette is unreadable on a dark theme, since scanners need
//! dark modules on a light field and not the reverse.

const std = @import("std");

extern "c" fn secretctl_qr_matrix(text: [*:0]const u8, out: [*]u8, out_cap: c_int) c_int;

/// Largest matrix we will render. Version 40 is 177 modules plus quiet zone;
/// nothing this tool encodes comes close, but the buffer is sized so a
/// surprising input fails the capacity check instead of overflowing.
const max_side = 200;

pub const Error = error{
    /// CoreImage could not encode it, or it needs more modules than max_side.
    EncodeFailed,
    /// The rendered code is wider than the terminal, so it would wrap and be
    /// unscannable. Better to say so than to print confetti.
    TooWide,
};

/// Upper bound on the text a caller can hand us, so the null-terminated copy
/// has a fixed home.
pub const max_text = 1024;

/// Render `text` as a QR into `writer`.
///
/// `term_cols` is the terminal width; pass 0 to skip the fit check (piping to a
/// file, say, where wrapping is not a concern).
pub fn render(
    text: []const u8,
    term_cols: usize,
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
) Error!void {
    if (text.len >= max_text) return Error.EncodeFailed;
    var zbuf: [max_text]u8 = undefined;
    @memcpy(zbuf[0..text.len], text);
    zbuf[text.len] = 0;

    var matrix: [max_side * max_side]u8 = undefined;
    const side = secretctl_qr_matrix(@ptrCast(&zbuf), &matrix, @intCast(matrix.len));
    if (side <= 0) return Error.EncodeFailed;
    const n: usize = @intCast(side);

    // One cell per module horizontally. The check is a courtesy, not a
    // correctness issue — but a wrapped QR looks like a rendering bug rather
    // than a window that is too narrow, so it is worth naming.
    if (term_cols != 0 and n > term_cols) return Error.TooWide;

    // Two module rows per text row, rounded up: an odd module count leaves the
    // last row with only a top half, whose bottom must be light (quiet zone).
    var y: usize = 0;
    while (y < n) : (y += 2) {
        var x: usize = 0;
        while (x < n) : (x += 1) {
            const top = matrix[y * n + x] == 1;
            const bottom = if (y + 1 < n) matrix[(y + 1) * n + x] == 1 else false;
            // Foreground paints the upper half, background the lower.
            // 30 = black fg, 97 = white fg; 40 = black bg, 107 = white bg.
            const fg: []const u8 = if (top) "30" else "97";
            const bg: []const u8 = if (bottom) "40" else "107";
            out.appendSlice(allocator, "\x1b[") catch return Error.EncodeFailed;
            out.appendSlice(allocator, fg) catch return Error.EncodeFailed;
            out.appendSlice(allocator, ";") catch return Error.EncodeFailed;
            out.appendSlice(allocator, bg) catch return Error.EncodeFailed;
            out.appendSlice(allocator, "m\u{2580}") catch return Error.EncodeFailed;
        }
        out.appendSlice(allocator, "\x1b[0m\n") catch return Error.EncodeFailed;
    }
}

const testing = std.testing;

test "renders a matrix of plausible size" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try render("otpauth://totp/secretctl:vault?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0, &out, testing.allocator);

    // Every emitted cell is a half-block, and each row ends with a reset. Not a
    // scannability check — only a phone can do that — but it catches an empty
    // or malformed render, which is the failure this can have.
    try testing.expect(std.mem.indexOf(u8, out.items, "\u{2580}") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "\x1b[0m") != null);
    const rows = std.mem.count(u8, out.items, "\n");
    try testing.expect(rows >= 10 and rows <= max_side);
}

test "both module colours appear" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    // A matrix rendered all-light or all-dark would still satisfy the test
    // above while being unscannable, so pin that both states are emitted.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try render("otpauth://totp/x?secret=AAAAAAAAAAAAAAAA", 0, &out, testing.allocator);
    try testing.expect(std.mem.indexOf(u8, out.items, "\x1b[30;40m") != null or
        std.mem.indexOf(u8, out.items, "\x1b[30;107m") != null);
    try testing.expect(std.mem.indexOf(u8, out.items, "\x1b[97;107m") != null);
}

test "a terminal narrower than the code is refused, not wrapped" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try testing.expectError(Error.TooWide, render("otpauth://totp/secretctl:vault?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 10, &out, testing.allocator));
}

test "oversized input fails instead of truncating" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    const big = [_]u8{'a'} ** (max_text + 1);
    try testing.expectError(Error.EncodeFailed, render(&big, 0, &out, testing.allocator));
}
