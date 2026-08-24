//! macOS Keychain protector. Stores a 32-byte wrapping_key in the user's
//! Keychain and keeps the master_key ciphertext in master.key. Both
//! artifacts are required to recover the master_key.
//!
//! Body layout:
//!   service_len u16 | service bytes
//!   account_len u16 | account bytes
//!   nonce[12]
//!   ct_len u16 (=32) | ct[32]
//!   tag[16]

const std = @import("std");
const aes = @import("aes_gcm.zig");
const sf = @import("security_framework.zig");
const mem_util = @import("mem.zig");
const rand = @import("rand.zig");
const clock = @import("clock.zig");
const protector = @import("protector.zig");
const local_auth = @import("local_auth.zig");
const tty = @import("tty.zig");

pub const Error = error{
    OutOfMemory,
    KeychainError,
    KeychainItemNotFound,
    AuthenticationFailed,
    // The item exists but reading it would require user interaction (a stale
    // trusted-app ACL prompt) that we suppressed. Signals the caller to fall
    // back to passphrase and then heal the keychain protector.
    InteractionRequired,
    MalformedBody,
    Unexpected,
};

const default_service = "secretctl";

/// Magic prefix for v0.2 protector bodies. Earlier (v0.1.x) bodies started
/// directly with service_len (u16 LE), so we sniff the first 2 bytes.
const body_magic_v2 = "S2";

/// Body flags (v0.2+).
pub const Flags = enum(u8) {
    default = 0x00,
    touch_id = 0x01,
};

/// Whether `unwrap` may skip a `touch_id` body's biometric gate.
///
/// The gate is enforced in this process, before `SecItemCopyMatching` — it is
/// not an ACL on the *biometric* requirement (that would need a data-protection
/// item and a Developer ID signature; `docs/2fa-design.md` §1.1 M3). So for this
/// binary the gate is skippable code rather than a barrier.
///
/// It is not the only thing in the way, and an earlier version of this comment
/// said it was. The item does carry a legacy trusted-app ACL, and M5 measures
/// that a foreign binary gets `errSecAuthFailed` — so a hostile local process
/// cannot take the wrap key, only ask us for it and meet whatever gates we then
/// apply.
///
/// That is what makes skipping this one safe *when* out-of-band approval has
/// already been obtained: it cannot be satisfied while the screen is locked
/// (measured: it fails after 13 s, `2fa-push-approval.md` §2.2b), and one gate
/// has already been passed in its place. It does not make approval a
/// cryptographic factor, and per `docs/2of2-protector.md` the design that would
/// is deliberately not being built.
pub const Gate = enum {
    /// Default. A `touch_id` body prompts for a fingerprint.
    require_biometric,
    /// Someone approved this operation from another device. Read the item
    /// without prompting for a finger that is, by definition, not here.
    approved_out_of_band,
};

fn buildAad(
    allocator: std.mem.Allocator,
    master_key_id: *const [16]u8,
    protector_id: *const [16]u8,
) ![]u8 {
    const prefix = "secretctl/master.key v1\x00macos_keychain";
    var buf = try allocator.alloc(u8, prefix.len + 16 + 16);
    @memcpy(buf[0..prefix.len], prefix);
    @memcpy(buf[prefix.len..][0..16], master_key_id);
    @memcpy(buf[prefix.len + 16 ..][0..16], protector_id);
    return buf;
}

/// Convert master_key_id bytes to lowercase hex; this becomes the Keychain account name.
fn hexAccount(master_key_id: *const [16]u8, out: *[32]u8) void {
    const hex_chars = "0123456789abcdef";
    for (master_key_id, 0..) |b, i| {
        out[i * 2] = hex_chars[b >> 4];
        out[i * 2 + 1] = hex_chars[b & 0x0f];
    }
}

/// Build a SecAccessRef whose ACL trusts only the current binary. Without
/// this, the keychain item gets a default ACL that prompts the user on
/// every access, even when called from the same code-signed binary that
/// created it. Returns null on failure (caller proceeds without an ACL —
/// degrades to "always prompt" UX but stays correct).
fn buildSelfTrustedAccess() sf.SecAccessRef {
    var self_app: sf.SecTrustedApplicationRef = null;
    if (sf.SecTrustedApplicationCreateFromPath(null, &self_app) != sf.errSecSuccess) return null;
    if (self_app == null) return null;

    const apps_array = sf.CFArrayCreate(
        sf.kCFAllocatorDefault,
        @ptrCast(&self_app),
        1,
        @ptrCast(&sf.kCFTypeArrayCallBacks),
    );
    sf.CFRelease(self_app);
    if (apps_array == null) return null;
    defer sf.CFRelease(apps_array);

    const label = sf.cfString("secretctl wrapping key") orelse return null;
    defer sf.CFRelease(label);

    var access: sf.SecAccessRef = null;
    if (sf.SecAccessCreate(label, apps_array, &access) != sf.errSecSuccess) return null;
    return access;
}

fn keychainStore(service: []const u8, account: []const u8, value: []const u8, flags: Flags) Error!void {
    const cf_service = sf.cfString(service) orelse return Error.Unexpected;
    defer sf.CFRelease(cf_service);
    const cf_account = sf.cfString(account) orelse return Error.Unexpected;
    defer sf.CFRelease(cf_account);
    const cf_value = sf.cfData(value) orelse return Error.Unexpected;
    defer sf.CFRelease(cf_value);

    const dict = sf.CFDictionaryCreateMutable(
        sf.kCFAllocatorDefault,
        6,
        @ptrCast(&sf.kCFTypeDictionaryKeyCallBacks),
        @ptrCast(&sf.kCFTypeDictionaryValueCallBacks),
    ) orelse return Error.Unexpected;
    defer sf.CFRelease(dict);

    sf.CFDictionarySetValue(dict, @ptrCast(sf.kSecClass), @ptrCast(sf.kSecClassGenericPassword));
    sf.CFDictionarySetValue(dict, @ptrCast(sf.kSecAttrService), @ptrCast(cf_service));
    sf.CFDictionarySetValue(dict, @ptrCast(sf.kSecAttrAccount), @ptrCast(cf_account));
    sf.CFDictionarySetValue(dict, @ptrCast(sf.kSecValueData), @ptrCast(cf_value));
    sf.CFDictionarySetValue(dict, @ptrCast(sf.kSecAttrAccessible), @ptrCast(sf.kSecAttrAccessibleWhenUnlocked));

    // The keychain item itself always carries the trusted-app ACL.
    // Touch ID gating happens in unwrap() via LocalAuthentication.framework
    // before SecItemCopyMatching is called — the body's `flags` byte tells
    // the unwrap path whether to issue that LA prompt.
    _ = flags;
    const access_ref = buildSelfTrustedAccess();
    defer if (access_ref) |ar| sf.CFRelease(ar);
    if (access_ref) |ar| {
        sf.CFDictionarySetValue(dict, @ptrCast(sf.kSecAttrAccess), @ptrCast(ar));
    }

    const status = sf.SecItemAdd(dict, null);
    if (status == sf.errSecDuplicateItem) {
        // Replace existing.
        try keychainDelete(service, account);
        const status2 = sf.SecItemAdd(dict, null);
        if (status2 != sf.errSecSuccess) return Error.KeychainError;
        return;
    }
    if (status != sf.errSecSuccess) return Error.KeychainError;
}

fn keychainFetch(allocator: std.mem.Allocator, service: []const u8, account: []const u8) Error![]u8 {
    const cf_service = sf.cfString(service) orelse return Error.Unexpected;
    defer sf.CFRelease(cf_service);
    const cf_account = sf.cfString(account) orelse return Error.Unexpected;
    defer sf.CFRelease(cf_account);

    const query = sf.CFDictionaryCreateMutable(
        sf.kCFAllocatorDefault,
        5,
        @ptrCast(&sf.kCFTypeDictionaryKeyCallBacks),
        @ptrCast(&sf.kCFTypeDictionaryValueCallBacks),
    ) orelse return Error.Unexpected;
    defer sf.CFRelease(query);

    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecClass), @ptrCast(sf.kSecClassGenericPassword));
    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecAttrService), @ptrCast(cf_service));
    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecAttrAccount), @ptrCast(cf_account));
    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecReturnData), @ptrCast(sf.kCFBooleanTrue));
    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecMatchLimit), @ptrCast(sf.kSecMatchLimitOne));

    // Interactive sessions suppress the macOS ACL password dialog: if the
    // item's trusted-app ACL no longer matches this binary (e.g. after a
    // `brew upgrade` replaced it), the read fails with errSecInteractionNotAllowed
    // instead of prompting, and the caller falls back to the master password
    // and re-establishes the protector. Non-interactive sessions (Home Manager
    // activation, launchd) keep the dialog, since they have no terminal for
    // that fallback.
    // NB: our items live in the legacy keychain, so the controlling knob is
    // SecKeychainSetUserInteractionAllowed (process-global), not the
    // kSecUseAuthenticationUI query key (data-protection keychain only).
    const suppress_ui = tty.isStdinTty();
    if (suppress_ui) _ = sf.SecKeychainSetUserInteractionAllowed(0);
    defer if (suppress_ui) {
        _ = sf.SecKeychainSetUserInteractionAllowed(1);
    };

    var result: sf.CFTypeRef = null;
    const status = sf.SecItemCopyMatching(query, &result);
    if (status == sf.errSecItemNotFound) return Error.KeychainItemNotFound;
    // With UI suppressed, any non-success result (errSecAuthFailed -25293,
    // errSecInteractionNotAllowed -25308, …) means the access would have
    // required the trusted-app dialog → the ACL is stale for this binary.
    // Signal the caller to fall back to passphrase and re-establish it.
    if (suppress_ui and status != sf.errSecSuccess) return Error.InteractionRequired;
    if (status != sf.errSecSuccess) return Error.KeychainError;
    if (result == null) return Error.KeychainError;

    const data: sf.CFDataRef = @ptrCast(result);
    defer sf.CFRelease(result);
    const len: usize = @intCast(sf.CFDataGetLength(data));
    const ptr = sf.CFDataGetBytePtr(data);
    const buf = try allocator.alloc(u8, len);
    @memcpy(buf, ptr[0..len]);
    return buf;
}

fn keychainDelete(service: []const u8, account: []const u8) Error!void {
    const cf_service = sf.cfString(service) orelse return Error.Unexpected;
    defer sf.CFRelease(cf_service);
    const cf_account = sf.cfString(account) orelse return Error.Unexpected;
    defer sf.CFRelease(cf_account);

    const query = sf.CFDictionaryCreateMutable(
        sf.kCFAllocatorDefault,
        3,
        @ptrCast(&sf.kCFTypeDictionaryKeyCallBacks),
        @ptrCast(&sf.kCFTypeDictionaryValueCallBacks),
    ) orelse return Error.Unexpected;
    defer sf.CFRelease(query);

    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecClass), @ptrCast(sf.kSecClassGenericPassword));
    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecAttrService), @ptrCast(cf_service));
    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecAttrAccount), @ptrCast(cf_account));

    const status = sf.SecItemDelete(query);
    if (status != sf.errSecSuccess and status != sf.errSecItemNotFound) return Error.KeychainError;
}

/// Wrap master_key with a fresh wrapping_key, store wrapping_key in Keychain,
/// and produce a Protector containing the master_key ciphertext.
pub fn wrap(
    allocator: std.mem.Allocator,
    master_key: *const [aes.key_len]u8,
    master_key_id: *const [16]u8,
) Error!protector.Protector {
    return wrapWithFlags(allocator, master_key, master_key_id, .default);
}

pub fn wrapWithFlags(
    allocator: std.mem.Allocator,
    master_key: *const [aes.key_len]u8,
    master_key_id: *const [16]u8,
    flags: Flags,
) Error!protector.Protector {
    var protector_id: [16]u8 = undefined;
    rand.bytes(&protector_id);

    var wrap_key: aes.Key = undefined;
    rand.bytes(&wrap_key);
    defer mem_util.secureZero(u8, &wrap_key);

    var nonce: aes.Nonce = undefined;
    rand.bytes(&nonce);

    const aad = buildAad(allocator, master_key_id, &protector_id) catch return Error.OutOfMemory;
    defer allocator.free(aad);

    var ct: [aes.key_len]u8 = undefined;
    var tag: aes.Tag = undefined;
    aes.encrypt(&wrap_key, &nonce, aad, master_key, &ct, &tag);

    const service = default_service;
    var account_buf: [32]u8 = undefined;
    hexAccount(master_key_id, &account_buf);
    const account = account_buf[0..];

    try keychainStore(service, account, &wrap_key, flags);

    // Serialize body. v0.2 layout: magic "S2" | flags u8 | service_len u16 | service | account_len u16 | account | nonce[12] | ct_len u16 | ct | tag[16].
    const body_len = body_magic_v2.len + 1 + 2 + service.len + 2 + account.len + 12 + 2 + ct.len + 16;
    var body = try allocator.alloc(u8, body_len);
    var w: usize = 0;
    @memcpy(body[w .. w + body_magic_v2.len], body_magic_v2);
    w += body_magic_v2.len;
    body[w] = @intFromEnum(flags);
    w += 1;
    std.mem.writeInt(u16, body[w..][0..2], @intCast(service.len), .little);
    w += 2;
    @memcpy(body[w .. w + service.len], service);
    w += service.len;
    std.mem.writeInt(u16, body[w..][0..2], @intCast(account.len), .little);
    w += 2;
    @memcpy(body[w .. w + account.len], account);
    w += account.len;
    @memcpy(body[w .. w + 12], &nonce);
    w += 12;
    std.mem.writeInt(u16, body[w..][0..2], @intCast(ct.len), .little);
    w += 2;
    @memcpy(body[w .. w + ct.len], &ct);
    w += ct.len;
    @memcpy(body[w .. w + 16], &tag);
    w += 16;
    std.debug.assert(w == body_len);

    return .{
        .id = protector_id,
        .type_id = @intFromEnum(protector.ProtectorType.macos_keychain),
        .created_at = clock.unixSeconds(),
        .body = body,
    };
}

pub fn unwrap(
    allocator: std.mem.Allocator,
    body: []const u8,
    master_key_id: *const [16]u8,
    protector_id: *const [16]u8,
    gate: Gate,
    out_master_key: *[aes.key_len]u8,
) Error!void {
    if (body.len < 2) return Error.MalformedBody;
    var r: usize = 0;
    var body_flags: u8 = 0;
    // Sniff v0.2 magic. If absent, treat as v0.1 layout (no flags byte).
    if (body.len >= body_magic_v2.len and std.mem.eql(u8, body[0..body_magic_v2.len], body_magic_v2)) {
        r += body_magic_v2.len;
        if (body.len < r + 1) return Error.MalformedBody;
        body_flags = body[r];
        r += 1;
    }
    // Touch ID gate: prompt for biometric auth before reading the keychain.
    // On cancel/failure, surface as AuthenticationFailed so the caller falls
    // back to the next protector (passphrase).
    //
    // Skipped when approval already arrived from another device. See `Gate` for
    // why that is not a downgrade, and why it is the only thing that makes a
    // locked screen unlockable at all.
    if (body_flags == @intFromEnum(Flags.touch_id) and gate == .require_biometric) {
        const ok = local_auth.evaluate("Unlock secretctl vault");
        if (!ok) return Error.AuthenticationFailed;
    }
    if (body.len < r + 2) return Error.MalformedBody;
    const service_len = std.mem.readInt(u16, body[r..][0..2], .little);
    r += 2;
    if (body.len < r + service_len + 2) return Error.MalformedBody;
    const service = body[r .. r + service_len];
    r += service_len;
    const account_len = std.mem.readInt(u16, body[r..][0..2], .little);
    r += 2;
    if (body.len < r + account_len + 12 + 2) return Error.MalformedBody;
    const account = body[r .. r + account_len];
    r += account_len;
    var nonce: aes.Nonce = undefined;
    @memcpy(&nonce, body[r .. r + 12]);
    r += 12;
    const ct_len = std.mem.readInt(u16, body[r..][0..2], .little);
    r += 2;
    if (ct_len != aes.key_len) return Error.MalformedBody;
    if (body.len < r + ct_len + 16) return Error.MalformedBody;
    var ct: [aes.key_len]u8 = undefined;
    @memcpy(&ct, body[r .. r + ct_len]);
    r += ct_len;
    var tag: aes.Tag = undefined;
    @memcpy(&tag, body[r .. r + 16]);
    r += 16;

    var wrap_key: aes.Key = undefined;
    const fetched = try keychainFetch(allocator, service, account);
    defer {
        mem_util.secureZero(u8, fetched);
        allocator.free(fetched);
    }
    if (fetched.len != aes.key_len) return Error.MalformedBody;
    @memcpy(&wrap_key, fetched);
    defer mem_util.secureZero(u8, &wrap_key);

    const aad = buildAad(allocator, master_key_id, protector_id) catch return Error.OutOfMemory;
    defer allocator.free(aad);

    aes.decrypt(&wrap_key, &nonce, aad, &ct, &tag, out_master_key) catch return Error.AuthenticationFailed;
}

/// Remove the Keychain item for a given master_key_id.
pub fn deleteFor(master_key_id: *const [16]u8) Error!void {
    var account_buf: [32]u8 = undefined;
    hexAccount(master_key_id, &account_buf);
    try keychainDelete(default_service, account_buf[0..]);
}

/// Write the keychain account string for a master_key_id (32 lowercase hex
/// chars) into `out`. Matches the account used by wrap/unwrap/deleteFor.
pub fn accountFor(master_key_id: *const [16]u8, out: *[32]u8) void {
    hexAccount(master_key_id, out);
}

/// List the accounts of every `secretctl` generic-password item in the
/// keychain. Caller owns the returned slice and each entry. Used to find
/// stale wrap-key items left by past inits/upgrades.
pub fn listAccounts(allocator: std.mem.Allocator) Error![][]u8 {
    const cf_service = sf.cfString(default_service) orelse return Error.Unexpected;
    defer sf.CFRelease(cf_service);

    const query = sf.CFDictionaryCreateMutable(
        sf.kCFAllocatorDefault,
        4,
        @ptrCast(&sf.kCFTypeDictionaryKeyCallBacks),
        @ptrCast(&sf.kCFTypeDictionaryValueCallBacks),
    ) orelse return Error.Unexpected;
    defer sf.CFRelease(query);

    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecClass), @ptrCast(sf.kSecClassGenericPassword));
    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecAttrService), @ptrCast(cf_service));
    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecMatchLimit), @ptrCast(sf.kSecMatchLimitAll));
    sf.CFDictionarySetValue(query, @ptrCast(sf.kSecReturnAttributes), @ptrCast(sf.kCFBooleanTrue));

    var result: sf.CFTypeRef = null;
    const status = sf.SecItemCopyMatching(query, &result);
    if (status == sf.errSecItemNotFound) return allocator.alloc([]u8, 0);
    if (status != sf.errSecSuccess or result == null) return Error.KeychainError;
    defer sf.CFRelease(result);

    const arr: sf.CFArrayRef = @ptrCast(result);
    const count = sf.CFArrayGetCount(arr);
    var out = std.ArrayList([]u8).empty;
    errdefer {
        for (out.items) |a| allocator.free(a);
        out.deinit(allocator);
    }
    var i: sf.CFIndex = 0;
    while (i < count) : (i += 1) {
        const dict: sf.CFDictionaryRef = @ptrCast(@constCast(sf.CFArrayGetValueAtIndex(arr, i)));
        if (dict == null) continue;
        const acct_ref = sf.CFDictionaryGetValue(dict, @ptrCast(sf.kSecAttrAccount));
        if (acct_ref == null) continue;
        var buf: [256]u8 = undefined;
        if (sf.CFStringGetCString(@ptrCast(@constCast(acct_ref)), &buf, buf.len, sf.kCFStringEncodingUTF8) == 0) continue;
        const s = std.mem.sliceTo(&buf, 0);
        const dup = allocator.dupe(u8, s) catch return Error.OutOfMemory;
        out.append(allocator, dup) catch {
            allocator.free(dup);
            return Error.OutOfMemory;
        };
    }
    return out.toOwnedSlice(allocator) catch Error.OutOfMemory;
}

/// Delete a `secretctl` keychain item by account string.
pub fn deleteAccount(account: []const u8) Error!void {
    try keychainDelete(default_service, account);
}

const testing = std.testing;

test "wrap/unwrap round-trip via real Keychain" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);
    defer deleteFor(&mk_id) catch {};

    var p = try wrap(a, &mk, &mk_id);
    defer p.deinit(a);

    var recovered: [aes.key_len]u8 = undefined;
    try unwrap(a, p.body, &mk_id, &p.id, .require_biometric, &recovered);
    try testing.expectEqualSlices(u8, &mk, &recovered);
}

test "unwrap with wrong protector_id fails" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);
    defer deleteFor(&mk_id) catch {};

    var p = try wrap(a, &mk, &mk_id);
    defer p.deinit(a);

    var fake_pid: [16]u8 = undefined;
    rand.bytes(&fake_pid);
    var recovered: [aes.key_len]u8 = undefined;
    try testing.expectError(Error.AuthenticationFailed, unwrap(a, p.body, &mk_id, &fake_pid, .require_biometric, &recovered));
}

test "out-of-band approval reads a Touch-ID-gated body without prompting" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    // This is the whole locked-screen fix, and it is testable precisely because
    // a passing run must involve no human: under `.require_biometric` the same
    // body would raise an LA prompt, which in a test run nobody answers. So a
    // green result here means the gate really was skipped, not merely that the
    // unwrap succeeded.
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);
    defer deleteFor(&mk_id) catch {};

    var p = try wrapWithFlags(a, &mk, &mk_id, .touch_id);
    defer p.deinit(a);
    // Guard the premise: if the body were not actually flagged there would be
    // no gate to skip and the test would prove nothing.
    try testing.expectEqual(@intFromEnum(Flags.touch_id), p.body[body_magic_v2.len]);

    var recovered: [aes.key_len]u8 = undefined;
    try unwrap(a, p.body, &mk_id, &p.id, .approved_out_of_band, &recovered);
    try testing.expectEqualSlices(u8, &mk, &recovered);
}

test "skipping the gate does not skip the AEAD" {
    if (@import("builtin").os.tag != .macos) return error.SkipZigTest;
    // Approval replaces a gate on *who may ask*, never the binding between a
    // body and its vault. Without this, `.approved_out_of_band` could quietly
    // become a way to unwrap a protector lifted from another master.key.
    const a = testing.allocator;
    var mk: [aes.key_len]u8 = undefined;
    rand.bytes(&mk);
    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);
    defer deleteFor(&mk_id) catch {};

    var p = try wrapWithFlags(a, &mk, &mk_id, .touch_id);
    defer p.deinit(a);

    var other_mk_id: [16]u8 = undefined;
    rand.bytes(&other_mk_id);
    var recovered: [aes.key_len]u8 = undefined;
    try testing.expectError(
        Error.AuthenticationFailed,
        unwrap(a, p.body, &other_mk_id, &p.id, .approved_out_of_band, &recovered),
    );
}
