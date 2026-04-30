//! Library root. Pulls in every module so test discovery and the
//! executable can share a single import graph.

pub const mem = @import("mem.zig");
pub const rand = @import("rand.zig");
pub const clock = @import("clock.zig");
pub const aes = @import("aes_gcm.zig");
pub const argon2 = @import("argon2.zig");
pub const protector = @import("protector.zig");
pub const keychain = @import("keychain.zig");
pub const security_framework = @import("security_framework.zig");
pub const master_key = @import("master_key.zig");
pub const envelope = @import("envelope.zig");
pub const codec = @import("codec.zig");
pub const fsx = @import("fsx.zig");
pub const vault = @import("vault.zig");
pub const tty = @import("tty.zig");
pub const edit_view = @import("edit_view.zig");
pub const list_view = @import("list_view.zig");
pub const policy = @import("policy.zig");
pub const audit = @import("audit.zig");
pub const paths = @import("paths.zig");
pub const cli = @import("cli.zig");
pub const editor = @import("editor.zig");

test {
    const std = @import("std");
    std.testing.refAllDecls(@This());
    inline for (.{ mem, rand, clock, aes, argon2, protector, keychain, master_key, envelope, codec, fsx, vault, tty, edit_view, list_view, policy, audit, paths, cli, editor }) |m| {
        std.testing.refAllDecls(m);
    }
}
