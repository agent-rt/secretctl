//! AES-256-GCM wrapper around std.crypto.aead.aes_gcm.Aes256Gcm.
//!
//! All AEAD operations in secretctl funnel through this module so that
//! algorithm selection, error mapping, and constant exposure live in one place.

const std = @import("std");
const Aes = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const key_len: usize = Aes.key_length;
pub const nonce_len: usize = Aes.nonce_length;
pub const tag_len: usize = Aes.tag_length;

pub const Key = [key_len]u8;
pub const Nonce = [nonce_len]u8;
pub const Tag = [tag_len]u8;

pub const Error = error{AuthenticationFailed};

/// Encrypt in-place into `out_ct` (must equal plaintext.len) and `out_tag`.
pub fn encrypt(
    key: *const Key,
    nonce: *const Nonce,
    aad: []const u8,
    plaintext: []const u8,
    out_ct: []u8,
    out_tag: *Tag,
) void {
    std.debug.assert(out_ct.len == plaintext.len);
    Aes.encrypt(out_ct, out_tag, plaintext, aad, nonce.*, key.*);
}

/// Decrypt and verify tag. Returns AuthenticationFailed on any mismatch.
pub fn decrypt(
    key: *const Key,
    nonce: *const Nonce,
    aad: []const u8,
    ciphertext: []const u8,
    tag: *const Tag,
    out_pt: []u8,
) Error!void {
    std.debug.assert(out_pt.len == ciphertext.len);
    Aes.decrypt(out_pt, ciphertext, tag.*, aad, nonce.*, key.*) catch return Error.AuthenticationFailed;
}

test "round-trip" {
    var key: Key = undefined;
    @memset(&key, 0x42);
    var nonce: Nonce = undefined;
    @memset(&nonce, 0x07);
    const aad = "secretctl/test v1";
    const pt = "the quick brown fox jumps over the lazy dog";
    var ct: [pt.len]u8 = undefined;
    var tag: Tag = undefined;
    encrypt(&key, &nonce, aad, pt, &ct, &tag);

    var out: [pt.len]u8 = undefined;
    try decrypt(&key, &nonce, aad, &ct, &tag, &out);
    try std.testing.expectEqualSlices(u8, pt, &out);
}

test "tampered ciphertext is rejected" {
    var key: Key = undefined;
    @memset(&key, 0x42);
    var nonce: Nonce = undefined;
    @memset(&nonce, 0x07);
    const pt = "secret payload bytes";
    var ct: [pt.len]u8 = undefined;
    var tag: Tag = undefined;
    encrypt(&key, &nonce, "", pt, &ct, &tag);

    ct[0] ^= 0x01;
    var out: [pt.len]u8 = undefined;
    try std.testing.expectError(Error.AuthenticationFailed, decrypt(&key, &nonce, "", &ct, &tag, &out));
}

test "AAD mismatch is rejected" {
    var key: Key = undefined;
    @memset(&key, 0x42);
    var nonce: Nonce = undefined;
    @memset(&nonce, 0x07);
    const pt = "secret payload bytes";
    var ct: [pt.len]u8 = undefined;
    var tag: Tag = undefined;
    encrypt(&key, &nonce, "aad-A", pt, &ct, &tag);

    var out: [pt.len]u8 = undefined;
    try std.testing.expectError(Error.AuthenticationFailed, decrypt(&key, &nonce, "aad-B", &ct, &tag, &out));
}

test "wrong key is rejected" {
    var key1: Key = undefined;
    var key2: Key = undefined;
    @memset(&key1, 0x42);
    @memset(&key2, 0x43);
    var nonce: Nonce = undefined;
    @memset(&nonce, 0x07);
    const pt = "x";
    var ct: [1]u8 = undefined;
    var tag: Tag = undefined;
    encrypt(&key1, &nonce, "", pt, &ct, &tag);

    var out: [1]u8 = undefined;
    try std.testing.expectError(Error.AuthenticationFailed, decrypt(&key2, &nonce, "", &ct, &tag, &out));
}
