//! Command dispatch for secretctl. The seven commands are:
//!   init add rm list exec render reveal
//! Plus help/version. Anything else exits 2 with a usage hint.

const std = @import("std");
const paths_mod = @import("paths.zig");
const fsx = @import("fsx.zig");
const tty = @import("tty.zig");
const mem_util = @import("mem.zig");
const rand = @import("rand.zig");
const argon2 = @import("argon2.zig");
const aes = @import("aes_gcm.zig");
const protector_mod = @import("protector.zig");
const keychain_mod = @import("keychain.zig");
const totp = @import("totp.zig");
const master_key_mod = @import("master_key.zig");
const vault_mod = @import("vault.zig");
const edit_view = @import("edit_view.zig");
const list_view = @import("list_view.zig");
const policy_mod = @import("policy.zig");
const audit_mod = @import("audit.zig");
const editor_mod = @import("editor.zig");
const envelope_mod = @import("envelope.zig");
const local_auth = @import("local_auth.zig");
const authz = @import("authz.zig");
const clock_mod = @import("clock.zig");
const agent_mod = @import("agent.zig");
extern "c" fn dup2(oldfd: c_int, newfd: c_int) c_int;
extern "c" fn close(fd: c_int) c_int;
extern "c" fn read(fd: c_int, buf: [*]u8, count: usize) isize;

pub const ExitCode = enum(u8) {
    success = 0,
    internal = 1,
    usage = 2,
    not_executable = 126,
    not_found = 127,
    _,
};

/// Shown when a passphrase is needed but there is neither a terminal nor a
/// configured passphrase channel. See tty.passphraseFd for why the passphrase
/// is never taken from fd 0 in batch mode.
const passphrase_channel_hint =
    "no terminal for the master password; pass it on a dedicated fd, e.g.\n" ++
    "  SECRETCTL_PASSPHRASE_FD=3 secretctl ... 3<<<\"$PASSPHRASE\"\n";

pub const usage_text =
    \\secretctl — single-binary local secret manager
    \\
    \\USAGE:
    \\  secretctl init [--no-touch-id]
    \\  secretctl add NAME [--tag X,Y] [--editor | --file PATH | --stdin]
    \\      # --file/--stdin import exact bytes (multi-line/binary, e.g. a .p8 key)
    \\  secretctl edit NAME
    \\  secretctl rm NAME
    \\  secretctl list [--json] [--tag X]
    \\  secretctl exec [--tag X] [--only N1,N2] [--raw-env-names] -- COMMAND ARGS...
    \\      # secrets inject as env vars; names are normalized to UPPER_SNAKE_CASE
    \\      # (e.g. my-api-key -> MY_API_KEY). --raw-env-names keeps them verbatim.
    \\  secretctl render TEMPLATE --out PATH
    \\  secretctl materialize NAME --out PATH [--mode MODE] [--mkdir]
    \\  secretctl reveal NAME
    \\  secretctl tag NAME X,Y[,Z]            # replace tags of a secret (doesn't re-encrypt value)
    \\  secretctl key add-keychain-protector [--no-touch-id]   # add another machine's keychain unlock path
    \\  secretctl sync                       # git pull/commit/push the vault dir
    \\  secretctl reinstall-keychain [--no-touch-id]   # rebuild keychain protector
    \\  secretctl prune-keychain [--yes]     # remove stale secretctl keychain items from old vaults
    \\  secretctl agent [run|status|stop]    # cache the unlocked key to skip repeat Touch ID
    \\  secretctl 2fa [enroll|status|test|disable]  # TOTP code when the screen is locked
    \\
    \\ENV:
    \\  $VISUAL / $EDITOR control which editor `edit` and `add --editor` launch.
    \\  $SECRETCTL_AGENT=1 caches the unlocked master key in a background agent
    \\      so repeated commands skip the Touch ID prompt (auto-spawned).
    \\  $SECRETCTL_AGENT_TTL sets the sliding cache lifetime in seconds (default 120).
    \\  $SECRETCTL_FORCE_LOCKED=1 treats the screen as locked (0 as unlocked), which
    \\      is the only way to exercise the locked-screen authorization path without
    \\      actually locking the screen.
    \\  $SECRETCTL_TOTP_FD=N reads the 6-digit code from fd N (never argv: ps is public).
    \\  $SECRETCTL_PASSPHRASE_FD=N reads the master passphrase from fd N instead of
    \\      the terminal, for automation:  secretctl list 3<<<"$PASSPHRASE"
    \\      Never from stdin: stdin carries secret values, and whether an unlock
    \\      consumes a line depends on keychain/agent state.
    \\
;

pub fn run(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len < 2) {
        tty.writeStderr(usage_text);
        return @intFromEnum(ExitCode.usage);
    }
    const cmd = args[1];
    if (std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h") or std.mem.eql(u8, cmd, "help")) {
        tty.writeStdout(usage_text);
        return 0;
    }
    if (std.mem.eql(u8, cmd, "--version")) {
        tty.writeStdout("secretctl 0.8.2\n");
        return 0;
    }

    const tail = args[2..];
    if (std.mem.eql(u8, cmd, "init")) return runInit(allocator, tail);
    if (std.mem.eql(u8, cmd, "add")) return runAdd(allocator, tail);
    if (std.mem.eql(u8, cmd, "edit")) return runEdit(allocator, tail);
    if (std.mem.eql(u8, cmd, "rm")) return runRm(allocator, tail);
    if (std.mem.eql(u8, cmd, "list")) return runList(allocator, tail);
    if (std.mem.eql(u8, cmd, "exec")) return runExec(allocator, tail);
    if (std.mem.eql(u8, cmd, "render")) return runRender(allocator, tail);
    if (std.mem.eql(u8, cmd, "materialize")) return runMaterialize(allocator, tail);
    if (std.mem.eql(u8, cmd, "reveal")) return runReveal(allocator, tail);
    if (std.mem.eql(u8, cmd, "key")) return runKey(allocator, tail);
    if (std.mem.eql(u8, cmd, "tag")) return runTag(allocator, tail);
    if (std.mem.eql(u8, cmd, "sync")) return runSync(allocator, tail);
    if (std.mem.eql(u8, cmd, "reinstall-keychain")) return runReinstallKeychain(allocator, tail);
    if (std.mem.eql(u8, cmd, "prune-keychain")) return runPruneKeychain(allocator, tail);
    if (std.mem.eql(u8, cmd, "agent")) return runAgent(allocator, tail);
    if (std.mem.eql(u8, cmd, "2fa")) return runTwoFactor(allocator, tail);

    tty.writeStderr("unknown command: ");
    tty.writeStderr(cmd);
    tty.writeStderr("\n\n");
    tty.writeStderr(usage_text);
    return @intFromEnum(ExitCode.usage);
}

// ------- init -------

fn runInit(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    // Touch ID is the default when biometrics are available. Pass
    // --no-touch-id to fall back to the trusted-app ACL (no fingerprint
    // prompt, but every brew upgrade re-prompts "Always Allow").
    var touch_id_flag: ?bool = null;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--touch-id")) {
            touch_id_flag = true;
        } else if (std.mem.eql(u8, a, "--no-touch-id")) {
            touch_id_flag = false;
        } else {
            tty.writeStderr("unknown init flag: ");
            tty.writeStderr(a);
            tty.writeStderr("\n");
            return 2;
        }
    }
    var p = paths_mod.resolve(allocator) catch return errExit("cannot resolve paths");
    defer p.deinit();

    if (fsx.fileExists(p.master_key)) {
        tty.writeStderr("vault already exists at ");
        tty.writeStderr(p.master_key);
        tty.writeStderr("\nrefusing to overwrite\n");
        return 1;
    }

    fsx.mkdirP(p.home, 0o700) catch return errExit("mkdir failed");

    const batch = c_getenv("SECRETCTL_BATCH") != null;
    if (!tty.isStdinTty() and !batch) {
        tty.writeStderr("secretctl init must be run from a terminal (set SECRETCTL_BATCH=1 to override for testing)\n");
        return 2;
    }

    // readNewPassword handles the batch/automation case itself, via the
    // dedicated $SECRETCTL_PASSPHRASE_FD channel. It must not be read from
    // fd 0: that is the secret-value channel, and sharing them is what let the
    // master passphrase end up stored as a secret. See tty.passphraseFd.
    var pw = tty.readNewPassword(allocator, 8) catch |e| return errExit(switch (e) {
        tty.ReadError.PassphraseChannelRequired => "SECRETCTL_BATCH needs the passphrase on $SECRETCTL_PASSPHRASE_FD (e.g. SECRETCTL_PASSPHRASE_FD=3 ... 3<<<\"$PASS\")",
        else => "password input failed",
    });
    defer pw.deinit();

    // Batch mode (testing) keeps Keychain off by default. This no longer
    // affects how many stdin lines are consumed — the passphrase has its own
    // channel now — but a test that wants a keychain protector must still ask
    // for one. Tests that need Keychain set
    // SECRETCTL_BATCH_KEYCHAIN=1.
    const use_keychain = if (batch)
        c_getenv("SECRETCTL_BATCH_KEYCHAIN") != null
    else
        tty.confirm("Use macOS Keychain to skip password on subsequent runs?", true) catch true;

    var master_key: [aes.key_len]u8 = undefined;
    rand.bytes(&master_key);
    defer mem_util.secureZero(u8, &master_key);

    var mk_id: [16]u8 = undefined;
    rand.bytes(&mk_id);

    var protectors: [2]protector_mod.Protector = undefined;
    var protector_count: usize = 0;

    const pass_p = protector_mod.wrapPassphrase(allocator, pw.bytes, &master_key, &mk_id, argon2.Params.default) catch return errExit("derive failed");
    protectors[protector_count] = pass_p;
    protector_count += 1;

    if (use_keychain) {
        // Resolve effective Touch ID setting:
        //   explicit --touch-id          → require, error if unavailable
        //   explicit --no-touch-id       → never
        //   batch mode (CI)              → default off (CI can't fingerprint)
        //   interactive + biometry avail → default on
        //   interactive + no biometry    → off
        const touch_id = blk: {
            if (touch_id_flag) |v| {
                if (v and !local_auth.available()) {
                    tty.writeStderr("--touch-id requested but Touch ID/Face ID is not available\n");
                    return 2;
                }
                break :blk v;
            }
            if (batch) break :blk false;
            break :blk local_auth.available();
        };
        const flags: keychain_mod.Flags = if (touch_id) .touch_id else .default;
        const kp = keychain_mod.wrapWithFlags(allocator, &master_key, &mk_id, flags) catch |e| switch (e) {
            else => {
                tty.writeStderr("warning: Keychain protector failed; continuing with passphrase only\n");
                return finishInit(allocator, &p, &mk_id, &master_key, protectors[0..protector_count]);
            },
        };
        protectors[protector_count] = kp;
        protector_count += 1;
        if (touch_id) {
            tty.writeStderr("Touch ID protector enabled — vault unlock will require fingerprint.\n");
        } else {
            tty.writeStderr("Keychain protector enabled (passwordless via 'Always Allow').\n");
        }
    }

    return finishInit(allocator, &p, &mk_id, &master_key, protectors[0..protector_count]);
}

fn finishInit(
    allocator: std.mem.Allocator,
    p: *paths_mod.Paths,
    mk_id: *const [16]u8,
    master_key: *const [aes.key_len]u8,
    protectors: []protector_mod.Protector,
) u8 {
    defer for (protectors) |*pr| pr.deinit(allocator);

    const file: master_key_mod.MasterFile = .{
        .master_key_id = mk_id.*,
        .master_key_version = 1,
        .protectors = protectors,
    };
    const blob = master_key_mod.serialize(allocator, &file, master_key) catch return errExit("serialize failed");
    defer allocator.free(blob);
    fsx.writeAllAtomic(p.master_key, blob, 0o600) catch return errExit("write master.key failed");

    var body = vault_mod.VaultBody.empty();
    defer body.deinit(allocator);
    vault_mod.saveToFile(allocator, p.vault, &body, master_key, mk_id, 1) catch return errExit("write vault failed");

    fsx.writeAllAtomic(p.config, "# secretctl config\n", 0o600) catch return errExit("write config failed");

    audit_mod.log("init", .cli, &.{audit_mod.s("home", p.home)});
    tty.writeStdout("vault created at ");
    tty.writeStdout(p.home);
    tty.writeStdout("\n");
    return 0;
}

// ------- unlock helper used by add/rm/list/exec/render/reveal -------

const Session = struct {
    paths: paths_mod.Paths,
    master_key: [aes.key_len]u8,
    master_key_id: [16]u8,
    master_key_version: u32,
    body: vault_mod.VaultBody,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Session) void {
        self.body.deinit(self.allocator);
        mem_util.secureZero(u8, &self.master_key);
        self.paths.deinit();
    }

    pub fn save(self: *Session) !void {
        try vault_mod.saveToFile(
            self.allocator,
            self.paths.vault,
            &self.body,
            &self.master_key,
            &self.master_key_id,
            self.master_key_version,
        );
    }
};

fn unlockSession(
    allocator: std.mem.Allocator,
    /// Whether the key cache may answer this. `.bypass_read` for operations
    /// whose whole purpose is handing plaintext to the caller. See
    /// agent.CachePolicy for what this does and does not buy.
    cache: agent_mod.CachePolicy,
) ?Session {
    var p = paths_mod.resolve(allocator) catch return null;
    var ok = false;
    defer if (!ok) p.deinit();

    if (!fsx.fileExists(p.master_key)) {
        tty.writeStderr("no vault found; run `secretctl init` first\n");
        return null;
    }

    const blob = fsx.readAllAlloc(allocator, p.master_key, 1 * 1024 * 1024) catch return null;
    defer allocator.free(blob);

    // Decide which authorization method applies BEFORE the agent cache and the
    // keychain. See authz.decide() for why the order is load-bearing: below the
    // cache, locking the screen would leave an hour-long window needing no
    // approval at all.
    const authz_decision = authz.decide();
    // Stays `.require_biometric` unless approval actually arrives, so every
    // path that does not go through requestTotpApproval keeps today's gate.
    var gate: keychain_mod.Gate = .require_biometric;
    if (authz_decision.method == .out_of_band) {
        // master_key_id sits in plaintext at offset 10 of the header, so the
        // TOTP seed can be located without unlocking anything first.
        if (blob.len < 26) {
            tty.writeStderr("master.key too short\n");
            return null;
        }
        var totp_mk_id: [16]u8 = undefined;
        @memcpy(&totp_mk_id, blob[10..26]);

        switch (totpState(&totp_mk_id)) {
            .enrolled => {},
            .not_enrolled => {
                // Fail closed, and say which of the two things is missing:
                // nobody is at the machine, and there is no way to ask them.
                tty.writeStderr("cannot authorize: ");
                tty.writeStderr(authz_decision.reason);
                tty.writeStderr("\n");
                tty.writeStderr(authz.not_configured_hint);
                return null;
            },
            .unreadable => {
                tty.writeStderr("cannot authorize: ");
                tty.writeStderr(authz_decision.reason);
                tty.writeStderr("\n");
                tty.writeStderr(totp_unreadable_hint);
                return null;
            },
        }
        if (!requestTotpApproval(allocator, p.home, &totp_mk_id, authz_decision.reason)) return null;
        // Approved. Fall through to the normal unlock: approval authorises the
        // operation, it does not hand over the key. The keychain protector
        // still has to produce it, so a stolen approval on its own is worth
        // nothing.
        //
        // The biometric gate inside that protector cannot be satisfied while
        // locked — measured, it fails after 13 s
        // (`docs/2fa-push-approval.md` §2.2b) — and unattended there is no
        // passphrase channel to fall back to either, so before this the
        // approved request still could not unlock. Approval stands in for the
        // gate instead; `keychain.Gate` documents why that widens nothing.
        gate = .approved_out_of_band;
    }

    var master_key: [aes.key_len]u8 = undefined;
    var attempt: u32 = 0;
    var unlocked = false;
    // Set if the keychain item exists but its trusted-app ACL is stale (the
    // binary changed, e.g. brew upgrade). Triggers a self-heal after the
    // passphrase fallback so future unlocks are prompt-free.
    var kc_stale = false;

    // master_key_id is stored in plaintext in the master.key header (offset
    // 10, 16 bytes) — read it without unlocking so the agent can be keyed by
    // it. Layout asserted in master_key.zig.
    const use_agent = agent_mod.enabled() and blob.len >= 26;
    var mk_id_hdr: [16]u8 = undefined;
    if (use_agent) {
        @memcpy(&mk_id_hdr, blob[10..26]);
        agent_mod.ensureRunning();
        if (cache == .allow and agent_mod.cacheGet(&mk_id_hdr, &master_key)) {
            // Cache hit: skip Touch ID / password entirely. Recorded, because
            // otherwise the audit trail cannot distinguish an unlock that a
            // human authorised from one the cache served for free — and with
            // the gate above the cache, that distinction is the only way to
            // see which is which after the fact.
            audit_mod.log("unlock.cached", .cli, &.{
                audit_mod.s("authorization", "none — served from the key cache"),
            });
            return finishUnlock(allocator, p, &master_key, &ok);
        }
    }

    // First try: keychain only (no password prompt).
    var parsed = master_key_mod.parseAndUnlock(allocator, blob, null, gate, &master_key, &kc_stale) catch |e| switch (e) {
        master_key_mod.Error.AuthenticationFailed,
        master_key_mod.Error.NoUsableProtector,
        => null_block: {
            // Fall through to password prompt.
            break :null_block @as(?master_key_mod.MasterFile, null);
        },
        else => {
            tty.writeStderr("vault unlock failed (file corrupt?)\n");
            return null;
        },
    } orelse blk: {
        // Need password.
        while (attempt < 3) : (attempt += 1) {
            var pw = tty.readPassword(allocator, "Master password: ") catch |e| {
                if (e == tty.ReadError.PassphraseChannelRequired) tty.writeStderr(passphrase_channel_hint);
                return null;
            };
            defer pw.deinit();
            const result = master_key_mod.parseAndUnlock(allocator, blob, pw.bytes, .require_biometric, &master_key, null) catch |e| switch (e) {
                master_key_mod.Error.AuthenticationFailed => {
                    tty.writeStderr("incorrect password\n");
                    continue;
                },
                else => {
                    tty.writeStderr("vault unlock failed\n");
                    return null;
                },
            };
            unlocked = true;
            break :blk result;
        }
        return null;
    };
    if (!unlocked) unlocked = true;

    // Keychain item was found ACL-stale (binary changed) and we unlocked via
    // passphrase — re-establish the protector so it trusts the current binary.
    if (kc_stale) healKeychainProtector(allocator, p.master_key, &parsed, &master_key);

    parsed.deinit(allocator);

    // Fresh unlock succeeded — cache the key so the next command can skip the
    // Touch ID / password prompt.
    if (use_agent) agent_mod.cachePut(&mk_id_hdr, &master_key, agent_mod.ttlSeconds());

    return finishUnlock(allocator, p, &master_key, &ok);
}

/// Re-establish the keychain protector so its Keychain item's trusted-app ACL
/// trusts the currently-running binary. Runs automatically after a passphrase
/// unlock when the existing item was found ACL-stale (e.g. a `brew upgrade`
/// replaced the binary). Best-effort: any failure is non-fatal (the unlock
/// already succeeded). NOTE: drops all keychain protectors and adds one for
/// this machine — correct for a single-keychain-protector vault; revisit if
/// per-Mac keychain protectors are added.
fn healKeychainProtector(
    allocator: std.mem.Allocator,
    master_key_path: []const u8,
    parsed: *master_key_mod.MasterFile,
    master_key: *const [aes.key_len]u8,
) void {
    keychain_mod.deleteFor(&parsed.master_key_id) catch {};

    var kept = std.ArrayList(protector_mod.Protector).empty;
    defer {
        for (kept.items) |*pr| pr.deinit(allocator);
        kept.deinit(allocator);
    }
    // Keep non-keychain protectors; move ownership out of parsed so its later
    // deinit doesn't double-free.
    for (parsed.protectors) |*pr| {
        if (pr.type_id == @intFromEnum(protector_mod.ProtectorType.macos_keychain)) continue;
        kept.append(allocator, pr.*) catch return;
        pr.* = .{ .id = undefined, .type_id = 0, .created_at = 0, .body = &.{} };
    }

    const flags: keychain_mod.Flags = if (local_auth.available()) .touch_id else .default;
    const new_kp = keychain_mod.wrapWithFlags(allocator, master_key, &parsed.master_key_id, flags) catch return;
    kept.append(allocator, new_kp) catch return;

    const new_file: master_key_mod.MasterFile = .{
        .master_key_id = parsed.master_key_id,
        .master_key_version = parsed.master_key_version,
        .protectors = kept.items,
    };
    const new_blob = master_key_mod.serialize(allocator, &new_file, master_key) catch return;
    defer allocator.free(new_blob);
    fsx.writeAllAtomic(master_key_path, new_blob, 0o600) catch return;

    tty.writeStderr("secretctl: keychain protector re-established for this binary; future unlocks won't prompt.\n");
}

/// Load the vault with an already-unlocked master key and build the Session.
/// On success sets `ok.*` so the caller's path cleanup is skipped (ownership
/// of `p` transfers into the returned Session). On failure zeroes the key.
fn finishUnlock(
    allocator: std.mem.Allocator,
    p: paths_mod.Paths,
    master_key: *[aes.key_len]u8,
    ok: *bool,
) ?Session {
    const vresult = vault_mod.loadFromFile(allocator, p.vault, master_key, null) catch |e| switch (e) {
        vault_mod.Error.AuthenticationFailed => {
            tty.writeStderr("vault contents do not match this master key\n");
            mem_util.secureZero(u8, master_key);
            return null;
        },
        else => {
            tty.writeStderr("vault read failed\n");
            mem_util.secureZero(u8, master_key);
            return null;
        },
    };

    ok.* = true;
    return Session{
        .paths = p,
        .master_key = master_key.*,
        .master_key_id = vresult.master_key_id,
        .master_key_version = vresult.master_key_version,
        .body = vresult.body,
        .allocator = allocator,
    };
}

// ------- agent -------

fn runAgent(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    _ = allocator;
    const sub = if (args.len >= 1) args[0] else "run";

    if (std.mem.eql(u8, sub, "run")) {
        agent_mod.serve(true) catch |e| switch (e) {
            agent_mod.ServeError.AlreadyRunning => {
                tty.writeStderr("agent already running\n");
                return 0;
            },
            else => {
                tty.writeStderr("agent failed to start: ");
                tty.writeStderr(@errorName(e));
                tty.writeStderr("\n");
                return 1;
            },
        };
        return 0;
    }
    if (std.mem.eql(u8, sub, "status")) {
        if (agent_mod.statusCount()) |n| {
            var buf: [64]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "agent running, {d} key(s) cached\n", .{n}) catch "agent running\n";
            tty.writeStdout(line);
        } else {
            tty.writeStdout("agent not running\n");
        }
        return 0;
    }
    if (std.mem.eql(u8, sub, "stop")) {
        if (agent_mod.stopRunning()) {
            tty.writeStdout("agent stopped\n");
        } else {
            tty.writeStdout("agent not running\n");
        }
        return 0;
    }

    tty.writeStderr("usage: secretctl agent [run|status|stop]\n");
    return 2;
}

// ------- add / rm -------

/// Read all of stdin (binary-safe, multi-line) up to 16 MiB. Returns owned
/// bytes the caller wraps in a Plaintext.
fn readAllStdin(allocator: std.mem.Allocator) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = read(0, &chunk, chunk.len);
        if (n < 0) return error.ReadFailed;
        if (n == 0) break;
        if (buf.items.len + @as(usize, @intCast(n)) > 16 * 1024 * 1024) return error.TooLarge;
        try buf.appendSlice(allocator, chunk[0..@intCast(n)]);
    }
    return buf.toOwnedSlice(allocator);
}

fn runAdd(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len == 0) {
        tty.writeStderr("usage: secretctl add NAME [--tag X,Y]\n");
        return 2;
    }
    const name = args[0];
    if (!isValidName(name)) {
        tty.writeStderr("invalid name (use letters, digits, _, -)\n");
        return 2;
    }

    var cli_tags = std.ArrayList([]const u8).empty;
    defer cli_tags.deinit(allocator);
    var use_editor = false;
    var from_stdin = false;
    var file_path: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--tag")) {
            i += 1;
            if (i >= args.len) {
                tty.writeStderr("--tag requires a value\n");
                return 2;
            }
            var tit = std.mem.tokenizeScalar(u8, args[i], ',');
            while (tit.next()) |t| cli_tags.append(allocator, t) catch return errExit("oom");
        } else if (std.mem.eql(u8, a, "--editor")) {
            use_editor = true;
        } else if (std.mem.eql(u8, a, "--stdin")) {
            from_stdin = true;
        } else if (std.mem.eql(u8, a, "--file")) {
            i += 1;
            if (i >= args.len) {
                tty.writeStderr("--file requires a path\n");
                return 2;
            }
            file_path = args[i];
        } else if (std.mem.startsWith(u8, a, "--")) {
            tty.writeStderr("unknown flag: ");
            tty.writeStderr(a);
            tty.writeStderr("\n");
            return 2;
        } else {
            // Positional arg after NAME → reject (would suggest plaintext value).
            tty.writeStderr("unexpected positional argument; secret values must be entered via TUI\n");
            return 2;
        }
    }

    {
        var modes: u8 = 0;
        if (use_editor) modes += 1;
        if (from_stdin) modes += 1;
        if (file_path != null) modes += 1;
        if (modes > 1) {
            tty.writeStderr("--editor, --stdin and --file are mutually exclusive\n");
            return 2;
        }
    }

    // Capture --file/--stdin value BEFORE unlocking: a password-based unlock
    // also reads stdin, which --stdin would otherwise have consumed. Stored as
    // exact bytes (no newline stripping) so key files round-trip via materialize.
    var preread: ?mem_util.Plaintext = null;
    errdefer if (preread) |*x| x.deinit();
    if (file_path) |fp| {
        const bytes = fsx.readAllAlloc(allocator, fp, 16 * 1024 * 1024) catch {
            tty.writeStderr("cannot read file: ");
            tty.writeStderr(fp);
            tty.writeStderr("\n");
            return 1;
        };
        preread = mem_util.Plaintext.fromOwnedSlice(allocator, bytes);
    } else if (from_stdin) {
        const bytes = readAllStdin(allocator) catch return errExit("stdin read failed");
        preread = mem_util.Plaintext.fromOwnedSlice(allocator, bytes);
    }

    var sess = unlockSession(allocator, .allow) orelse return 1;
    defer sess.deinit();

    if (sess.body.findIndex(name) != null) {
        tty.writeStderr("secret already exists: ");
        tty.writeStderr(name);
        tty.writeStderr("\n");
        return 2;
    }

    var pt: mem_util.Plaintext = undefined;
    var tags_storage = std.ArrayList([]const u8).empty;
    defer tags_storage.deinit(allocator);
    // When tags come from the interactive prompt they are heap copies owned
    // here; CLI (--tag) tags are borrowed slices into argv. Free the copies on
    // exit. (LIFO: this runs before tags_storage.deinit above.)
    var tags_owned = false;
    defer if (tags_owned) for (tags_storage.items) |t| allocator.free(t);

    if (preread) |pre| {
        pt = pre;
        preread = null; // ownership moved to pt
        if (pt.bytes.len == 0) {
            pt.deinit();
            tty.writeStderr("empty value, aborting\n");
            return 1;
        }
        for (cli_tags.items) |t| tags_storage.append(allocator, t) catch return errExit("oom");
    } else if (use_editor) {
        pt = editor_mod.editPlaintext(allocator, null) catch |e| {
            tty.writeStderr("editor failed: ");
            tty.writeStderr(@errorName(e));
            tty.writeStderr("\n");
            return 1;
        };
        if (pt.bytes.len == 0) {
            pt.deinit();
            tty.writeStderr("empty value, aborting\n");
            return 1;
        }
        for (cli_tags.items) |t| tags_storage.append(allocator, t) catch return errExit("oom");
    } else {
        var entry = edit_view.prompt(allocator, name, cli_tags.items) catch |e| switch (e) {
            error.NoTty => {
                tty.writeStderr("add must run from a terminal (try --editor, or --file PATH / --stdin to import raw bytes)\n");
                return 2;
            },
            error.Cancelled => return 1,
            else => return errExit("input failed"),
        };
        // Move the value out of entry; copy tags into our own storage so
        // ownership is clean: tags_storage owns the copies (freed via the
        // tags_owned defer) and entry frees everything it allocated.
        pt = entry.value;
        entry.value = mem_util.Plaintext.fromOwnedSlice(allocator, &.{}); // sentinel so deinit is cheap
        tags_owned = true;
        for (entry.tags) |t| {
            const dup = allocator.dupe(u8, t) catch {
                entry.deinit();
                return errExit("oom");
            };
            tags_storage.append(allocator, dup) catch {
                allocator.free(dup);
                entry.deinit();
                return errExit("oom");
            };
        }
        entry.deinit();
    }
    defer pt.deinit();

    sess.body.addSecret(
        allocator,
        &sess.master_key,
        &sess.master_key_id,
        sess.master_key_version,
        name,
        tags_storage.items,
        pt.bytes,
    ) catch |e| switch (e) {
        vault_mod.Error.DuplicateName => {
            tty.writeStderr("duplicate name\n");
            return 2;
        },
        else => return errExit("addSecret failed"),
    };

    sess.save() catch return errExit("save failed");

    audit_mod.log("add", .cli, &.{audit_mod.s("name", name)});
    tty.writeStdout("added ");
    tty.writeStdout(name);
    tty.writeStdout("\n");
    return 0;
}

// ------- edit -------

fn runEdit(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len != 1) {
        tty.writeStderr("usage: secretctl edit NAME\n");
        return 2;
    }
    const name = args[0];

    var sess = unlockSession(allocator, .allow) orelse return 1;
    defer sess.deinit();

    const idx = sess.body.findIndex(name) orelse {
        tty.writeStderr("secret not found: ");
        tty.writeStderr(name);
        tty.writeStderr("\n");
        return 2;
    };
    const original_rec = sess.body.secrets.items[idx];

    var current = envelope_mod.decrypt(allocator, &sess.master_key, &sess.master_key_id, &original_rec.id, &original_rec.envelope) catch return errExit("decrypt failed");
    defer current.deinit();

    var edited = editor_mod.editPlaintext(allocator, current.bytes) catch |e| {
        tty.writeStderr("editor failed: ");
        tty.writeStderr(@errorName(e));
        tty.writeStderr("\n");
        return 1;
    };
    defer edited.deinit();

    if (std.mem.eql(u8, edited.bytes, current.bytes)) {
        tty.writeStdout("unchanged\n");
        return 0;
    }
    if (edited.bytes.len == 0) {
        tty.writeStderr("empty value, aborting (use rm to delete)\n");
        return 1;
    }

    // Preserve tags from the original record — copy out before remove.
    const old_tags = allocator.alloc([]const u8, original_rec.tags.len) catch return errExit("oom");
    defer {
        for (old_tags) |t| allocator.free(t);
        allocator.free(old_tags);
    }
    for (original_rec.tags, 0..) |t, ti| {
        old_tags[ti] = allocator.dupe(u8, t) catch return errExit("oom");
    }

    // Remove + add (atomic at file level via saveToFile after both ops).
    sess.body.removeByName(allocator, name) catch return errExit("remove failed");
    sess.body.addSecret(
        allocator,
        &sess.master_key,
        &sess.master_key_id,
        sess.master_key_version,
        name,
        old_tags,
        edited.bytes,
    ) catch return errExit("addSecret failed");
    sess.save() catch return errExit("save failed");

    audit_mod.log("edit", .cli, &.{audit_mod.s("name", name)});
    tty.writeStdout("updated ");
    tty.writeStdout(name);
    tty.writeStdout("\n");
    return 0;
}

fn runRm(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len != 1) {
        tty.writeStderr("usage: secretctl rm NAME\n");
        return 2;
    }
    const name = args[0];
    var sess = unlockSession(allocator, .allow) orelse return 1;
    defer sess.deinit();
    sess.body.removeByName(allocator, name) catch |e| switch (e) {
        vault_mod.Error.NotFound => {
            tty.writeStderr("secret not found: ");
            tty.writeStderr(name);
            tty.writeStderr("\n");
            return 2;
        },
        else => return errExit("rm failed"),
    };
    sess.save() catch return errExit("save failed");
    audit_mod.log("rm", .cli, &.{audit_mod.s("name", name)});
    tty.writeStdout("removed ");
    tty.writeStdout(name);
    tty.writeStdout("\n");
    return 0;
}

// ------- list -------

fn runList(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var json = false;
    var tag_filter: ?[]const u8 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--json")) json = true else if (std.mem.eql(u8, a, "--tag")) {
            i += 1;
            if (i >= args.len) {
                tty.writeStderr("--tag requires a value\n");
                return 2;
            }
            tag_filter = args[i];
        } else {
            tty.writeStderr("unknown arg: ");
            tty.writeStderr(a);
            tty.writeStderr("\n");
            return 2;
        }
    }

    var sess = unlockSession(allocator, .allow) orelse return 1;
    defer sess.deinit();

    var filtered: vault_mod.VaultBody = undefined;
    var owned_filtered = false;
    defer if (owned_filtered) filtered.secrets.deinit(allocator);

    const view_body = if (tag_filter) |tag| blk: {
        filtered = .{
            .schema_version = sess.body.schema_version,
            .updated_at = sess.body.updated_at,
            .secrets = .empty,
        };
        owned_filtered = true;
        for (sess.body.secrets.items) |s| {
            for (s.tags) |t| if (std.mem.eql(u8, t, tag)) {
                filtered.secrets.append(allocator, s) catch return errExit("oom");
                break;
            };
        }
        break :blk &filtered;
    } else &sess.body;

    if (json) {
        list_view.renderJson(allocator, view_body) catch return errExit("json failed");
    } else {
        list_view.renderTable(allocator, view_body) catch return errExit("render failed");
    }
    return 0;
}

// ------- exec -------

// Use libc getenv via a renamed extern.
extern fn getenv(name: [*:0]const u8) callconv(.c) ?[*:0]const u8;
fn c_getenv(name: [*:0]const u8) ?[*:0]const u8 {
    return getenv(name);
}
extern "c" fn execvp(file: [*:0]const u8, argv: [*:null]const ?[*:0]const u8) c_int;
extern "c" fn fork() c_int;
extern "c" fn waitpid(pid: c_int, stat_loc: *c_int, options: c_int) c_int;
extern "c" fn _exit(status: c_int) noreturn;
extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn getcwd(buf: [*]u8, size: usize) ?[*]u8;

/// Normalize a vault secret name into a canonical environment-variable name:
/// ASCII letters uppercased, digits kept, every other byte (including '-' and
/// '.') replaced with '_'. A leading digit gets an '_' prefix so the result is
/// a valid POSIX identifier (`[A-Za-z_][A-Za-z0-9_]*`). Caller owns the
/// returned NUL-terminated slice.
fn envNameFromSecret(allocator: std.mem.Allocator, name: []const u8) error{ OutOfMemory, EmptyName }![:0]u8 {
    if (name.len == 0) return error.EmptyName;
    const lead_digit = name[0] >= '0' and name[0] <= '9';
    const extra: usize = if (lead_digit) 1 else 0;
    const out = try allocator.allocSentinel(u8, name.len + extra, 0);
    var w: usize = 0;
    if (lead_digit) {
        out[w] = '_';
        w += 1;
    }
    for (name) |c| {
        const uc: u8 = if (c >= 'a' and c <= 'z') c - 32 else c;
        const ok = (uc >= 'A' and uc <= 'Z') or (uc >= '0' and uc <= '9') or uc == '_';
        out[w] = if (ok) uc else '_';
        w += 1;
    }
    return out;
}

fn runExec(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var tag_filter = std.ArrayList([]const u8).empty;
    defer tag_filter.deinit(allocator);
    var only_filter = std.ArrayList([]const u8).empty;
    defer only_filter.deinit(allocator);
    var raw_env_names = false;

    var i: usize = 0;
    var dash_dash: ?usize = null;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--")) {
            dash_dash = i;
            break;
        }
        if (std.mem.eql(u8, args[i], "--raw-env-names")) {
            raw_env_names = true;
        } else if (std.mem.eql(u8, args[i], "--tag")) {
            i += 1;
            if (i >= args.len) {
                tty.writeStderr("--tag requires a value\n");
                return 2;
            }
            var it = std.mem.tokenizeScalar(u8, args[i], ',');
            while (it.next()) |t| tag_filter.append(allocator, t) catch return errExit("oom");
        } else if (std.mem.eql(u8, args[i], "--only")) {
            i += 1;
            if (i >= args.len) {
                tty.writeStderr("--only requires a value\n");
                return 2;
            }
            var it = std.mem.tokenizeScalar(u8, args[i], ',');
            while (it.next()) |t| only_filter.append(allocator, t) catch return errExit("oom");
        } else if (std.mem.eql(u8, args[i], "--allow-all")) {
            tty.writeStderr("--allow-all is not supported (intentional)\n");
            return 2;
        } else {
            tty.writeStderr("unknown flag: ");
            tty.writeStderr(args[i]);
            tty.writeStderr("\n");
            return 2;
        }
    }

    if (dash_dash == null or dash_dash.? + 1 >= args.len) {
        tty.writeStderr("usage: secretctl exec [--tag X] [--only N1,N2] -- COMMAND ARGS...\n");
        return 2;
    }
    const child_argv = args[dash_dash.? + 1 ..];
    if (tag_filter.items.len == 0 and only_filter.items.len == 0) {
        tty.writeStderr("no secret selection — pass --tag or --only (no implicit injection)\n");
        return 2;
    }

    var cwd_buf: [1024]u8 = undefined;
    const cwd_ptr = getcwd(&cwd_buf, cwd_buf.len);
    const cwd: []const u8 = if (cwd_ptr) |p| std.mem.span(@as([*:0]const u8, @ptrCast(p))) else "";
    var pol = policy_mod.load(allocator, cwd) catch policy_mod.empty;
    defer if (pol.present) pol.deinit();

    if (!pol.allowsCommand(child_argv[0])) {
        tty.writeStderr("command not in .secretctl.toml allowlist: ");
        tty.writeStderr(child_argv[0]);
        tty.writeStderr("\n");
        return 2;
    }
    for (tag_filter.items) |t| if (!pol.allowsTag(t)) {
        tty.writeStderr("tag not in .secretctl.toml allowlist: ");
        tty.writeStderr(t);
        tty.writeStderr("\n");
        return 2;
    };

    var sess = unlockSession(allocator, .allow) orelse return 1;
    defer sess.deinit();

    // Decide which secrets to inject.
    var selected = std.ArrayList(usize).empty;
    defer selected.deinit(allocator);

    if (only_filter.items.len > 0) {
        for (only_filter.items) |name| {
            const idx = sess.body.findIndex(name) orelse {
                tty.writeStderr("unknown secret: ");
                tty.writeStderr(name);
                tty.writeStderr("\n");
                return 2;
            };
            selected.append(allocator, idx) catch return errExit("oom");
        }
    }
    if (tag_filter.items.len > 0) {
        for (sess.body.secrets.items, 0..) |s, idx| {
            outer: for (tag_filter.items) |needle| {
                for (s.tags) |t| if (std.mem.eql(u8, t, needle)) {
                    selected.append(allocator, idx) catch return errExit("oom");
                    break :outer;
                };
            }
        }
    }
    if (selected.items.len == 0) {
        tty.writeStderr("no secrets matched the selection\n");
        return 2;
    }

    // Policy gate: every selected secret must have at least one tag in the
    // allowlist. This applies to both --tag and --only paths so capability
    // restrictions cannot be bypassed by naming a secret directly.
    if (pol.present) {
        for (selected.items) |idx| {
            const s = sess.body.secrets.items[idx];
            var ok = false;
            for (s.tags) |t| if (pol.allowsTag(t)) {
                ok = true;
                break;
            };
            if (!ok) {
                tty.writeStderr("secret '");
                tty.writeStderr(s.name);
                tty.writeStderr("' has no tag in .secretctl.toml allowlist (");
                tty.writeStderr(pol.source);
                tty.writeStderr(")\n");
                return 2;
            }
        }
    }

    // Decrypt each into env vars.
    var pts = std.ArrayList(mem_util.Plaintext).empty;
    defer {
        for (pts.items) |*pt| pt.deinit();
        pts.deinit(allocator);
    }
    // Track the env var names already injected this run so we can reject two
    // secrets that map to the same name (a real risk once names are
    // normalized, e.g. `foo-bar` and `foo_bar`). Owns the name allocations.
    var env_names = std.ArrayList([:0]u8).empty;
    defer {
        for (env_names.items) |n| allocator.free(n);
        env_names.deinit(allocator);
    }
    for (selected.items) |idx| {
        const rec = sess.body.secrets.items[idx];
        const pt = envelope_mod.decrypt(allocator, &sess.master_key, &sess.master_key_id, &rec.id, &rec.envelope) catch return errExit("decrypt failed");
        pts.append(allocator, pt) catch return errExit("oom");

        // Derive the env var name. By default normalize to UPPER_SNAKE_CASE so
        // injected names are consistent and shell-valid regardless of how the
        // vault key was cased/punctuated; --raw-env-names keeps it verbatim.
        const name_z: [:0]u8 = if (raw_env_names) blk: {
            const z = allocator.allocSentinel(u8, rec.name.len, 0) catch return errExit("oom");
            @memcpy(z, rec.name);
            break :blk z;
        } else envNameFromSecret(allocator, rec.name) catch |e| switch (e) {
            error.OutOfMemory => return errExit("oom"),
            error.EmptyName => {
                tty.writeStderr("secret has an empty name; cannot derive an env var\n");
                return 2;
            },
        };

        for (env_names.items) |existing| {
            if (std.mem.eql(u8, existing, name_z)) {
                tty.writeStderr("two selected secrets map to the same env var '");
                tty.writeStderr(name_z);
                tty.writeStderr("'; rename one or pass --raw-env-names\n");
                allocator.free(name_z);
                return 2;
            }
        }
        env_names.append(allocator, name_z) catch {
            allocator.free(name_z);
            return errExit("oom");
        };

        // Value must be NUL-terminated for libc setenv.
        const value_z = allocator.allocSentinel(u8, pt.bytes.len, 0) catch return errExit("oom");
        @memcpy(value_z, pt.bytes);
        defer allocator.free(value_z);
        if (setenv(name_z.ptr, value_z.ptr, 1) != 0) return errExit("setenv failed");
    }

    // Build child argv (NUL-terminated array).
    var argv_z = allocator.alloc(?[*:0]const u8, child_argv.len + 1) catch return errExit("oom");
    defer allocator.free(argv_z);
    var owned_strings = std.ArrayList([:0]u8).empty;
    defer {
        for (owned_strings.items) |s| allocator.free(s);
        owned_strings.deinit(allocator);
    }
    for (child_argv, 0..) |arg, idx| {
        const z = allocator.allocSentinel(u8, arg.len, 0) catch return errExit("oom");
        @memcpy(z, arg);
        owned_strings.append(allocator, z) catch return errExit("oom");
        argv_z[idx] = z.ptr;
    }
    argv_z[child_argv.len] = null;

    // Build basename (for audit and logging).
    const base = std.fs.path.basename(child_argv[0]);

    // Build tag list summary for audit.
    var tag_list_buf = std.ArrayList(u8).empty;
    defer tag_list_buf.deinit(allocator);
    for (tag_filter.items, 0..) |t, ti| {
        if (ti > 0) tag_list_buf.append(allocator, ',') catch {};
        tag_list_buf.appendSlice(allocator, t) catch {};
    }

    const pid = fork();
    if (pid < 0) return errExit("fork failed");
    if (pid == 0) {
        const argv_terminated: [*:null]const ?[*:0]const u8 = @ptrCast(argv_z.ptr);
        _ = execvp(argv_z[0].?, argv_terminated);
        // execvp only returns on error.
        const errno_val = std.c._errno().*;
        const ENOENT: c_int = 2;
        const EACCES: c_int = 13;
        if (errno_val == ENOENT) _exit(127);
        if (errno_val == EACCES) _exit(126);
        _exit(127);
    }

    // Parent: clear plaintexts before waiting (we already passed them via setenv,
    // and the child process has inherited the env page).
    for (pts.items) |*pt| pt.deinit();
    pts.clearRetainingCapacity();

    var status: c_int = 0;
    if (waitpid(pid, &status, 0) < 0) return errExit("waitpid failed");

    var exit_code: u8 = 0;
    if ((status & 0x7f) == 0) {
        exit_code = @intCast((status >> 8) & 0xff);
    } else {
        exit_code = 128 + @as(u8, @intCast(status & 0x7f));
    }

    audit_mod.log("exec", .cli, &.{
        audit_mod.s("cmd", base),
        audit_mod.arr("tags", tag_filter.items),
        audit_mod.s("cwd", cwd),
        audit_mod.n("exit", @intCast(exit_code)),
    });
    return exit_code;
}

// ------- render -------

fn runRender(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len < 3 or !std.mem.eql(u8, args[1], "--out")) {
        tty.writeStderr("usage: secretctl render TEMPLATE --out PATH\n");
        return 2;
    }
    const template_path = args[0];
    const out_path = args[2];

    var sess = unlockSession(allocator, .allow) orelse return 1;
    defer sess.deinit();

    const template = fsx.readAllAlloc(allocator, template_path, 1 * 1024 * 1024) catch {
        tty.writeStderr("cannot read template: ");
        tty.writeStderr(template_path);
        tty.writeStderr("\n");
        return 2;
    };
    defer allocator.free(template);

    var out: std.ArrayList(u8) = .empty;
    defer {
        mem_util.secureZero(u8, out.items);
        out.deinit(allocator);
    }

    var i: usize = 0;
    while (i < template.len) {
        if (template[i] == '$' and i + 1 < template.len and template[i + 1] == '$') {
            out.append(allocator, '$') catch return errExit("oom");
            i += 2;
            continue;
        }
        if (template[i] == '$' and i + 1 < template.len and template[i + 1] == '{') {
            const close_brace = std.mem.indexOfScalarPos(u8, template, i + 2, '}') orelse {
                tty.writeStderr("unterminated ${...} placeholder in template\n");
                return 2;
            };
            const name = template[i + 2 .. close_brace];
            const idx = sess.body.findIndex(name) orelse {
                tty.writeStderr("template references unknown secret: ");
                tty.writeStderr(name);
                tty.writeStderr("\n");
                return 2;
            };
            const rec = sess.body.secrets.items[idx];
            var pt = envelope_mod.decrypt(allocator, &sess.master_key, &sess.master_key_id, &rec.id, &rec.envelope) catch return errExit("decrypt failed");
            defer pt.deinit();
            out.appendSlice(allocator, pt.bytes) catch return errExit("oom");
            i = close_brace + 1;
            continue;
        }
        out.append(allocator, template[i]) catch return errExit("oom");
        i += 1;
    }

    fsx.writeAllAtomic(out_path, out.items, 0o600) catch {
        tty.writeStderr("cannot write output: ");
        tty.writeStderr(out_path);
        tty.writeStderr("\n");
        return 1;
    };

    audit_mod.log("render", .cli, &.{ audit_mod.s("out", out_path), audit_mod.s("template", template_path) });
    tty.writeStdout("rendered ");
    tty.writeStdout(out_path);
    tty.writeStdout("\n");
    return 0;
}

// ------- tag -------

fn runTag(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len != 2) {
        tty.writeStderr("usage: secretctl tag NAME X,Y[,Z]\n");
        return 2;
    }
    const name = args[0];
    const tags_arg = args[1];

    var tags: std.ArrayList([]const u8) = .empty;
    defer tags.deinit(allocator);
    var it = std.mem.tokenizeScalar(u8, tags_arg, ',');
    while (it.next()) |t| {
        const trimmed = std.mem.trim(u8, t, " \t");
        if (trimmed.len == 0) continue;
        tags.append(allocator, trimmed) catch return errExit("oom");
    }

    var sess = unlockSession(allocator, .allow) orelse return 1;
    defer sess.deinit();

    sess.body.setTags(allocator, name, tags.items) catch |e| switch (e) {
        vault_mod.Error.NotFound => {
            tty.writeStderr("secret not found: ");
            tty.writeStderr(name);
            tty.writeStderr("\n");
            return 2;
        },
        else => return errExit("setTags failed"),
    };
    sess.save() catch return errExit("save failed");

    audit_mod.log("tag", .cli, &.{
        audit_mod.s("name", name),
        audit_mod.arr("tags", tags.items),
    });
    tty.writeStdout("retagged ");
    tty.writeStdout(name);
    tty.writeStdout(" → [");
    for (tags.items, 0..) |t, i| {
        if (i > 0) tty.writeStdout(", ");
        tty.writeStdout(t);
    }
    tty.writeStdout("]\n");
    return 0;
}

// ------- materialize -------

fn runMaterialize(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var name: ?[]const u8 = null;
    var out_path: ?[]const u8 = null;
    var mode: u16 = 0o600;
    var mkdir = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--out")) {
            i += 1;
            if (i >= args.len) {
                tty.writeStderr("--out requires a value\n");
                return 2;
            }
            out_path = args[i];
        } else if (std.mem.eql(u8, a, "--mode")) {
            i += 1;
            if (i >= args.len) {
                tty.writeStderr("--mode requires a value\n");
                return 2;
            }
            mode = std.fmt.parseInt(u16, args[i], 8) catch {
                tty.writeStderr("--mode must be octal (e.g. 0600)\n");
                return 2;
            };
        } else if (std.mem.eql(u8, a, "--mkdir")) {
            mkdir = true;
        } else if (std.mem.startsWith(u8, a, "--")) {
            tty.writeStderr("unknown materialize flag: ");
            tty.writeStderr(a);
            tty.writeStderr("\n");
            return 2;
        } else if (name == null) {
            name = a;
        } else {
            tty.writeStderr("unexpected argument: ");
            tty.writeStderr(a);
            tty.writeStderr("\n");
            return 2;
        }
    }

    if (name == null or out_path == null) {
        tty.writeStderr("usage: secretctl materialize NAME --out PATH [--mode MODE] [--mkdir]\n");
        return 2;
    }

    if (mkdir) {
        if (std.fs.path.dirname(out_path.?)) |parent| {
            fsx.mkdirAll(parent, 0o700) catch return errExit("mkdir parent failed");
        }
    }

    var sess = unlockSession(allocator, .allow) orelse return 1;
    defer sess.deinit();

    var pt = sess.body.revealSecret(allocator, &sess.master_key, &sess.master_key_id, name.?) catch |e| switch (e) {
        vault_mod.Error.NotFound => {
            tty.writeStderr("secret not found: ");
            tty.writeStderr(name.?);
            tty.writeStderr("\n");
            return 2;
        },
        else => return errExit("decrypt failed"),
    };
    defer pt.deinit();

    fsx.writeAllAtomic(out_path.?, pt.bytes, mode) catch {
        tty.writeStderr("cannot write output: ");
        tty.writeStderr(out_path.?);
        tty.writeStderr("\n");
        return 1;
    };

    var mode_buf: [8]u8 = undefined;
    const mode_str = std.fmt.bufPrint(&mode_buf, "0{o}", .{mode}) catch "?";
    audit_mod.log("materialize", .cli, &.{
        audit_mod.s("name", name.?),
        audit_mod.s("out", out_path.?),
        audit_mod.s("mode", mode_str),
    });
    tty.writeStdout("materialized ");
    tty.writeStdout(name.?);
    tty.writeStdout(" → ");
    tty.writeStdout(out_path.?);
    tty.writeStdout("\n");
    return 0;
}

// ------- reveal -------

fn runReveal(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len != 1) {
        tty.writeStderr("usage: secretctl reveal NAME\n");
        return 2;
    }
    if (!tty.isStdoutTty() and c_getenv("SECRETCTL_BATCH") == null) {
        tty.writeStderr("reveal must be run on an interactive terminal (no stdout capture)\n");
        return 2;
    }
    const name = args[0];

    // `reveal` prints plaintext to whoever ran it, so it does not take the
    // cache's word for authorization — every reveal costs a fresh Touch ID at
    // the desk, or phone approval while locked. `exec` deliberately still uses
    // the cache; agent.CachePolicy records why, and what that leaves open.
    var sess = unlockSession(allocator, .bypass_read) orelse return 1;
    defer sess.deinit();

    var pt = sess.body.revealSecret(allocator, &sess.master_key, &sess.master_key_id, name) catch |e| switch (e) {
        vault_mod.Error.NotFound => {
            tty.writeStderr("secret not found: ");
            tty.writeStderr(name);
            tty.writeStderr("\n");
            return 2;
        },
        else => return errExit("reveal failed"),
    };
    defer pt.deinit();

    tty.writeStdout(name);
    tty.writeStdout(" = ");
    tty.writeStdout(pt.bytes);
    tty.writeStdout("\n");

    audit_mod.log("reveal", .cli, &.{audit_mod.s("name", name)});
    return 0;
}

// ------- 2fa (offline TOTP approval) -------

/// True when this vault has a TOTP seed enrolled.
///
/// Presence of the keychain item is the signal. Reading it needs the ACL, so a
/// foreign binary cannot even answer this question (M5) — which is fine: it has
/// no reason to.
/// Whether this vault has a usable TOTP seed.
///
/// Three states, not two. Collapsing them into a bool is what made an earlier
/// version dangerous: any read failure looked like "never enrolled", so the gate
/// advised `2fa enroll` — and following that advice overwrites a seed that was
/// merely unreadable, silently killing the entry already in someone's phone.
/// A transient keychain problem must never be presented as an invitation to
/// destroy the enrolment.
const TotpState = enum {
    enrolled,
    /// No item at all. `2fa enroll` is the right advice.
    not_enrolled,
    /// The item exists but could not be read — a stale trusted-app ACL after an
    /// upgrade is the expected cause. The seed is probably intact; re-enrolling
    /// would replace it.
    unreadable,
};

fn totpState(master_key_id: *const [16]u8) TotpState {
    const seed = keychain_mod.fetchTotpSeed(std.heap.page_allocator, master_key_id) catch |e| {
        return switch (e) {
            keychain_mod.Error.KeychainItemNotFound => .not_enrolled,
            else => .unreadable,
        };
    };
    defer {
        mem_util.secureZero(u8, seed);
        std.heap.page_allocator.free(seed);
    }
    // A short item is corrupt, not absent: overwriting it is still a decision
    // the operator should make explicitly.
    return if (seed.len >= 16) .enrolled else .unreadable;
}

/// What to print when the seed is there but unreadable. Says plainly what not
/// to do, because the obvious next move is the destructive one.
const totp_unreadable_hint =
    "the TOTP seed exists but could not be read from the keychain.\n" ++
    "Do NOT run `secretctl 2fa enroll` — that replaces the seed and the entry\n" ++
    "in your authenticator stops working. A stale trusted-app ACL after a\n" ++
    "`brew upgrade` is the usual cause; run a command that unlocks the vault\n" ++
    "from a terminal first, which re-establishes the keychain protector.\n" ++
    "If the seed is genuinely lost, `secretctl 2fa disable` then re-enroll.\n";

/// Path of the replay ledger. Not secret — it holds one integer — but 0600
/// because everything in the vault directory is.
fn totpStatePath(allocator: std.mem.Allocator, home: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/totp.state", .{home});
}

/// The most recently spent time step, if any.
///
/// A missing or unparseable file reads as "nothing spent" rather than as an
/// error: the ledger is a replay guard, and failing closed on a corrupt one
/// would lock the operator out of their own vault over a file that carries no
/// secret. The cost of failing open is that a code can be reused once within
/// its own 30 s window — bounded, and strictly better than an unopenable vault.
fn totpLastStep(allocator: std.mem.Allocator, home: []const u8) ?u64 {
    const path = totpStatePath(allocator, home) catch return null;
    defer allocator.free(path);
    const raw = fsx.readAllAlloc(allocator, path, 64) catch return null;
    defer allocator.free(raw);
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    return std.fmt.parseInt(u64, trimmed, 10) catch null;
}

fn totpRecordStep(allocator: std.mem.Allocator, home: []const u8, step: u64) void {
    const path = totpStatePath(allocator, home) catch return;
    defer allocator.free(path);
    var buf: [32]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}\n", .{step}) catch return;
    fsx.writeAllAtomic(path, text, 0o600) catch {};
}

/// Ask for a TOTP code and verify it. Returns true only on a fresh, unspent
/// code.
///
/// The code comes from `$SECRETCTL_TOTP_FD` when set, otherwise from the
/// terminal. **Never from argv** — `ps` is world-readable, and this project has
/// already had to move the master passphrase and an enrolment token off it for
/// exactly that reason.
fn requestTotpApproval(
    allocator: std.mem.Allocator,
    home: []const u8,
    master_key_id: *const [16]u8,
    reason: []const u8,
) bool {
    const seed = keychain_mod.fetchTotpSeed(allocator, master_key_id) catch {
        tty.writeStderr("cannot read the TOTP seed from the keychain; run `secretctl 2fa enroll`\n");
        return false;
    };
    defer {
        mem_util.secureZero(u8, seed);
        allocator.free(seed);
    }

    tty.writeStderr("authorization required: ");
    tty.writeStderr(reason);
    tty.writeStderr("\n");

    var code = tty.readFromFdEnv(allocator, "SECRETCTL_TOTP_FD") catch blk: {
        // No dedicated channel. A terminal is the other legitimate source; an
        // unattended run has neither and must fail rather than hang.
        const pw = tty.readPassword(allocator, "6-digit code: ") catch {
            tty.writeStderr("no code supplied. Pass it on a dedicated fd, e.g.\n" ++
                "  SECRETCTL_TOTP_FD=3 secretctl ... 3<<<\"123456\"\n");
            return false;
        };
        break :blk pw;
    };
    defer code.deinit();

    const trimmed = std.mem.trim(u8, code.bytes, " \t\r\n");
    const last = totpLastStep(allocator, home);
    const m = totp.verifyNow(seed, trimmed, last) catch |e| {
        switch (e) {
            totp.Error.Replayed => tty.writeStderr(
                "that code was already used. Wait for the next one (up to 30s).\n"),
            totp.Error.Malformed => tty.writeStderr("expected exactly six digits\n"),
            else => tty.writeStderr("incorrect code\n"),
        }
        audit_mod.log("authz.denied", .cli, &.{audit_mod.s("method", "totp")});
        return false;
    };

    // Spend it before returning. If this write fails the code stays reusable
    // for the rest of its step — logged rather than fatal, for the same reason
    // a corrupt ledger reads as empty.
    totpRecordStep(allocator, home, m.step);
    audit_mod.log("authz.approved", .cli, &.{audit_mod.s("method", "totp")});
    // stderr, not stdout: stdout is the command's own output channel, and
    // `list --json` shares it. Writing progress there made the JSON
    // unparseable for exactly the callers most likely to be driving this path.
    tty.writeStderr("authorized\n");
    return true;
}

fn runTwoFactor(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len == 0) {
        tty.writeStderr("usage: secretctl 2fa [enroll|status|test|disable]\n");
        return 2;
    }
    var p = paths_mod.resolve(allocator) catch return errExit("cannot resolve paths");
    defer p.deinit();
    if (!fsx.fileExists(p.master_key)) {
        tty.writeStderr("no vault found; run `secretctl init` first\n");
        return 1;
    }
    const blob = fsx.readAllAlloc(allocator, p.master_key, 1 * 1024 * 1024) catch
        return errExit("read master.key failed");
    defer allocator.free(blob);
    if (blob.len < 26) return errExit("master.key too short");
    var mk_id: [16]u8 = undefined;
    @memcpy(&mk_id, blob[10..26]);

    if (std.mem.eql(u8, args[0], "enroll")) {
        switch (totpState(&mk_id)) {
            .not_enrolled => {},
            .enrolled => {
                tty.writeStderr("already enrolled. `secretctl 2fa disable` first if you want a new seed —\n" ++
                    "re-enrolling invalidates whatever your authenticator currently holds.\n");
                return 1;
            },
            // The load-bearing case. Overwriting here is exactly the data loss
            // this whole distinction exists to prevent, so refuse and point at
            // the explicit escape hatch rather than deciding for the operator.
            .unreadable => {
                tty.writeStderr(totp_unreadable_hint);
                return 1;
            },
        }
        var seed: [totp.seed_len]u8 = undefined;
        rand.bytes(&seed);
        defer mem_util.secureZero(u8, &seed);

        keychain_mod.storeTotpSeed(&mk_id, &seed) catch {
            tty.writeStderr("could not store the seed in the keychain\n");
            return 1;
        };

        const uri = totp.otpauthUri(allocator, &seed, "vault") catch return errExit("out of memory");
        defer {
            mem_util.secureZero(u8, uri);
            allocator.free(uri);
        }
        tty.writeStdout("Add this to your authenticator app:\n\n  ");
        tty.writeStdout(uri);
        tty.writeStdout("\n\nThen confirm it round-trips before relying on it:\n");
        tty.writeStdout("  SECRETCTL_TOTP_FD=3 secretctl 2fa test 3<<<\"123456\"\n");
        audit_mod.log("2fa.enroll", .cli, &.{audit_mod.s("method", "totp")});
        return 0;
    }

    if (std.mem.eql(u8, args[0], "status")) {
        switch (totpState(&mk_id)) {
            .enrolled => {},
            .not_enrolled => {
                tty.writeStdout("TOTP: not enrolled\n");
                tty.writeStdout(authz.not_configured_hint);
                return 1;
            },
            .unreadable => {
                tty.writeStdout("TOTP: enrolled, but the seed is not readable right now\n");
                tty.writeStderr(totp_unreadable_hint);
                return 1;
            },
        }
        tty.writeStdout("TOTP: enrolled (SHA1, 6 digits, 30s)\n");
        if (totpLastStep(allocator, p.home)) |st| {
            var buf: [64]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "last code spent at step {d}\n", .{st}) catch "\n";
            tty.writeStdout(line);
        } else {
            tty.writeStdout("no code spent yet\n");
        }
        return 0;
    }

    if (std.mem.eql(u8, args[0], "test")) {
        // A full verification that unlocks nothing, so the channel can be
        // checked without putting a real secret behind it.
        switch (totpState(&mk_id)) {
            .enrolled => {},
            .not_enrolled => {
                tty.writeStderr(authz.not_configured_hint);
                return 1;
            },
            .unreadable => {
                tty.writeStderr(totp_unreadable_hint);
                return 1;
            },
        }
        return if (requestTotpApproval(allocator, p.home, &mk_id, "2fa test, no secret involved")) 0 else 1;
    }

    if (std.mem.eql(u8, args[0], "disable")) {
        keychain_mod.deleteTotpSeed(&mk_id) catch {};
        const path = totpStatePath(allocator, p.home) catch return errExit("out of memory");
        defer allocator.free(path);
        fsx.unlinkIfExists(path);
        tty.writeStdout("TOTP disabled. A locked screen will now refuse instead of asking.\n");
        audit_mod.log("2fa.disable", .cli, &.{audit_mod.s("method", "totp")});
        return 0;
    }

    tty.writeStderr("unknown 2fa subcommand: ");
    tty.writeStderr(args[0]);
    tty.writeStderr("\n");
    return 2;
}

// ------- key (sub-dispatcher) -------

fn runKey(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len == 0) {
        tty.writeStderr("usage: secretctl key add-keychain-protector [--touch-id|--no-touch-id]\n");
        return 2;
    }
    const sub = args[0];
    const tail = args[1..];
    if (std.mem.eql(u8, sub, "add-keychain-protector")) return runKeyAddKeychainProtector(allocator, tail);
    tty.writeStderr("unknown key subcommand: ");
    tty.writeStderr(sub);
    tty.writeStderr("\n");
    return 2;
}

fn runKeyAddKeychainProtector(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var touch_id_flag: ?bool = null;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--touch-id")) {
            touch_id_flag = true;
        } else if (std.mem.eql(u8, a, "--no-touch-id")) {
            touch_id_flag = false;
        } else {
            tty.writeStderr("unknown flag: ");
            tty.writeStderr(a);
            tty.writeStderr("\n");
            return 2;
        }
    }
    const batch = c_getenv("SECRETCTL_BATCH") != null;
    const touch_id = blk: {
        if (touch_id_flag) |v| {
            if (v and !local_auth.available()) {
                tty.writeStderr("--touch-id requested but Touch ID/Face ID is not available\n");
                return 2;
            }
            break :blk v;
        }
        if (batch) break :blk false;
        break :blk local_auth.available();
    };

    var p = paths_mod.resolve(allocator) catch return errExit("cannot resolve paths");
    defer p.deinit();
    if (!fsx.fileExists(p.master_key)) {
        tty.writeStderr("no vault found; run `secretctl init` first\n");
        return 1;
    }

    const blob = fsx.readAllAlloc(allocator, p.master_key, 1 * 1024 * 1024) catch return errExit("read master.key failed");
    defer allocator.free(blob);

    var master_key: [aes.key_len]u8 = undefined;
    defer mem_util.secureZero(u8, &master_key);

    // Try silent keychain unwrap first; fall back to password.
    var parsed = master_key_mod.parseAndUnlock(allocator, blob, null, .require_biometric, &master_key, null) catch |e| switch (e) {
        master_key_mod.Error.AuthenticationFailed,
        master_key_mod.Error.NoUsableProtector,
        => null,
        else => return errExit("vault unlock failed"),
    } orelse blk: {
        tty.writeStdout("Master password required to add a new keychain protector.\n");
        var pw = tty.readPassword(allocator, "Master password: ") catch |e| return errExit(switch (e) {
            tty.ReadError.PassphraseChannelRequired => passphrase_channel_hint,
            else => "password input failed",
        });
        defer pw.deinit();
        break :blk master_key_mod.parseAndUnlock(allocator, blob, pw.bytes, .require_biometric, &master_key, null) catch |e| switch (e) {
            master_key_mod.Error.AuthenticationFailed => {
                tty.writeStderr("incorrect password\n");
                return 1;
            },
            else => return errExit("vault unlock failed"),
        };
    };
    defer parsed.deinit(allocator);

    // Build a new keychain protector, append to existing list.
    const flags: keychain_mod.Flags = if (touch_id) .touch_id else .default;
    var new_protector = keychain_mod.wrapWithFlags(allocator, &master_key, &parsed.master_key_id, flags) catch |e| {
        tty.writeStderr("keychain protector creation failed: ");
        tty.writeStderr(@errorName(e));
        tty.writeStderr("\n");
        return 1;
    };
    defer new_protector.deinit(allocator);

    // Append to in-memory protectors slice (resize via temporary ArrayList).
    // Note: combined items reference body pointers owned elsewhere
    // (parsed.protectors via parsed.deinit, new_protector via the defer above).
    var combined: std.ArrayList(protector_mod.Protector) = .empty;
    defer combined.deinit(allocator);
    for (parsed.protectors) |pr| {
        combined.append(allocator, pr) catch return errExit("oom");
    }
    combined.append(allocator, new_protector) catch return errExit("oom");

    const new_file: master_key_mod.MasterFile = .{
        .master_key_id = parsed.master_key_id,
        .master_key_version = parsed.master_key_version,
        .protectors = combined.items,
    };
    const new_blob = master_key_mod.serialize(allocator, &new_file, &master_key) catch return errExit("serialize failed");
    defer allocator.free(new_blob);
    fsx.writeAllAtomic(p.master_key, new_blob, 0o600) catch return errExit("write master.key failed");

    audit_mod.log("key.add-keychain-protector", .cli, &.{
        audit_mod.b("touch_id", touch_id),
    });
    if (touch_id) {
        tty.writeStdout("Added Touch ID keychain protector for this machine.\n");
    } else {
        tty.writeStdout("Added keychain protector for this machine (default ACL).\n");
    }
    tty.writeStdout("Now commit and push ~/.secretctl/master.key so the other machines see the new protector.\n");
    return 0;
}

// ------- sync -------

extern "c" fn chdir(path: [*:0]const u8) c_int;
extern "c" fn gethostname(buf: [*]u8, len: usize) c_int;

fn runGitInDir(allocator: std.mem.Allocator, dir: []const u8, argv: []const []const u8, capture_stdout: bool) struct { exit: u8, stdout: []u8 } {
    var pipe_out: [2]c_int = undefined;
    if (capture_stdout) {
        if (pipe(&pipe_out) != 0) return .{ .exit = 1, .stdout = &.{} };
    }

    const pid = fork();
    if (pid < 0) return .{ .exit = 1, .stdout = &.{} };
    if (pid == 0) {
        var dir_z_buf: [1024]u8 = undefined;
        if (dir.len >= dir_z_buf.len) std.process.exit(1);
        @memcpy(dir_z_buf[0..dir.len], dir);
        dir_z_buf[dir.len] = 0;
        if (chdir(@ptrCast(&dir_z_buf[0])) != 0) std.process.exit(1);

        if (capture_stdout) {
            _ = dup2(pipe_out[1], 1);
            _ = close(pipe_out[0]);
            _ = close(pipe_out[1]);
        }

        // Build NUL-terminated argv (allocSentinel is fine here; child exits or execs).
        var arena_buf: [16][:0]u8 = undefined;
        var argv_ptrs: [16]?[*:0]const u8 = undefined;
        if (argv.len + 1 > arena_buf.len) std.process.exit(1);
        for (argv, 0..) |arg, i| {
            const z = allocator.allocSentinel(u8, arg.len, 0) catch std.process.exit(1);
            @memcpy(z, arg);
            arena_buf[i] = z;
            argv_ptrs[i] = z.ptr;
        }
        argv_ptrs[argv.len] = null;
        const argv_terminated: [*:null]const ?[*:0]const u8 = @ptrCast(&argv_ptrs[0]);
        _ = execvp(argv_ptrs[0].?, argv_terminated);
        std.process.exit(127);
    }

    var captured: []u8 = &.{};
    if (capture_stdout) {
        _ = close(pipe_out[1]);
        var buf: std.ArrayList(u8) = .empty;
        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = read(pipe_out[0], &chunk, chunk.len);
            if (n <= 0) break;
            buf.appendSlice(allocator, chunk[0..@intCast(n)]) catch break;
        }
        _ = close(pipe_out[0]);
        captured = buf.toOwnedSlice(allocator) catch &.{};
    }

    var status: c_int = 0;
    _ = waitpid(pid, &status, 0);
    var ec: u8 = 0;
    if ((status & 0x7f) == 0) ec = @intCast((status >> 8) & 0xff) else ec = 1;
    return .{ .exit = ec, .stdout = captured };
}

extern "c" fn pipe(fds: *[2]c_int) c_int;

fn runSync(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    if (args.len != 0) {
        tty.writeStderr("usage: secretctl sync\n");
        return 2;
    }
    var p = paths_mod.resolve(allocator) catch return errExit("cannot resolve paths");
    defer p.deinit();

    // Verify ~/.secretctl/.git exists.
    var git_dir_buf: [1024]u8 = undefined;
    const git_dir = std.fmt.bufPrint(&git_dir_buf, "{s}/.git", .{p.home}) catch return errExit("path too long");
    if (!fsx.fileExists(git_dir)) {
        tty.writeStderr("not a git repository: ");
        tty.writeStderr(p.home);
        tty.writeStderr("\nrun `git init` in there and push to a remote first (see /secretctl/sync/ docs)\n");
        return 2;
    }

    // 1. Stage everything
    _ = runGitInDir(allocator, p.home, &.{ "git", "add", "-A" }, false);

    // 2. Commit if there's anything staged
    const diff = runGitInDir(allocator, p.home, &.{ "git", "diff", "--cached", "--quiet" }, false);
    var did_commit = false;
    if (diff.exit != 0) {
        var hn: [256]u8 = undefined;
        @memset(&hn, 0);
        _ = gethostname(&hn, hn.len);
        const host = std.mem.sliceTo(&hn, 0);
        var msg_buf: [256]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "vault: {s} {d}", .{ host, clock_mod.unixSeconds() }) catch "vault: sync";
        const cm = runGitInDir(allocator, p.home, &.{ "git", "commit", "-m", msg }, false);
        if (cm.exit != 0) {
            tty.writeStderr("git commit failed\n");
            audit_mod.log("sync", .cli, &.{ audit_mod.s("step", "commit"), audit_mod.s("status", "failed") });
            return 1;
        }
        did_commit = true;
    }

    // 3. Pull with fast-forward only. Diverged history = bail; user resolves.
    {
        const r = runGitInDir(allocator, p.home, &.{ "git", "pull", "--ff-only" }, false);
        if (r.exit != 0) {
            tty.writeStderr("git pull --ff-only failed (history has diverged); resolve manually:\n");
            tty.writeStderr("  cd ");
            tty.writeStderr(p.home);
            tty.writeStderr(" && git pull   # then `git checkout --theirs vault` (or --ours) and commit\n");
            audit_mod.log("sync", .cli, &.{ audit_mod.s("step", "pull"), audit_mod.s("status", "diverged") });
            return 1;
        }
    }

    // 4. Push
    {
        const r = runGitInDir(allocator, p.home, &.{ "git", "push" }, false);
        if (r.exit != 0) {
            tty.writeStderr("git push failed (remote rejected? run `git push` manually for diagnostics)\n");
            audit_mod.log("sync", .cli, &.{ audit_mod.s("step", "push"), audit_mod.s("status", "failed") });
            return 1;
        }
    }

    audit_mod.log("sync", .cli, &.{audit_mod.s("status", if (did_commit) "committed" else "nochange")});
    if (did_commit) {
        tty.writeStdout("synced (committed + pushed local changes)\n");
    } else {
        tty.writeStdout("synced (no local changes; remote up-to-date)\n");
    }
    return 0;
}

// ------- reinstall-keychain -------

fn runReinstallKeychain(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var touch_id_flag: ?bool = null;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--touch-id")) {
            touch_id_flag = true;
        } else if (std.mem.eql(u8, a, "--no-touch-id")) {
            touch_id_flag = false;
        } else {
            tty.writeStderr("usage: secretctl reinstall-keychain [--touch-id|--no-touch-id]\n");
            return 2;
        }
    }
    const batch = c_getenv("SECRETCTL_BATCH") != null;
    const touch_id = blk: {
        if (touch_id_flag) |v| {
            if (v and !local_auth.available()) {
                tty.writeStderr("--touch-id requested but Touch ID/Face ID is not available\n");
                return 2;
            }
            break :blk v;
        }
        if (batch) break :blk false;
        break :blk local_auth.available();
    };
    var p = paths_mod.resolve(allocator) catch return errExit("cannot resolve paths");
    defer p.deinit();
    if (!fsx.fileExists(p.master_key)) {
        tty.writeStderr("no vault found; run `secretctl init` first\n");
        return 1;
    }

    // Read master.key blob.
    const blob = fsx.readAllAlloc(allocator, p.master_key, 1 * 1024 * 1024) catch return errExit("read master.key failed");
    defer allocator.free(blob);

    // Force passphrase unlock (Keychain protector likely broken).
    tty.writeStdout("Master password required to rebuild Keychain protector.\n");
    var pw = tty.readPassword(allocator, "Master password: ") catch |e| return errExit(switch (e) {
        tty.ReadError.PassphraseChannelRequired => passphrase_channel_hint,
        else => "password input failed",
    });
    defer pw.deinit();

    var master_key: [aes.key_len]u8 = undefined;
    var parsed = master_key_mod.parseAndUnlock(allocator, blob, pw.bytes, .require_biometric, &master_key, null) catch |e| switch (e) {
        master_key_mod.Error.AuthenticationFailed => {
            tty.writeStderr("incorrect password\n");
            return 1;
        },
        else => return errExit("vault unlock failed"),
    };
    defer parsed.deinit(allocator);
    defer mem_util.secureZero(u8, &master_key);

    // Delete the existing Keychain item (if any).
    keychain_mod.deleteFor(&parsed.master_key_id) catch {};

    // Drop existing Keychain protector entries from the protector list.
    var kept = std.ArrayList(protector_mod.Protector).empty;
    defer {
        for (kept.items) |*pr| pr.deinit(allocator);
        kept.deinit(allocator);
    }
    for (parsed.protectors) |*pr| {
        if (pr.type_id == @intFromEnum(protector_mod.ProtectorType.macos_keychain)) {
            // dropping; protector body will be freed when parsed.deinit runs
            continue;
        }
        // Move ownership of pr to kept; clear from parsed so deinit doesn't double-free.
        kept.append(allocator, pr.*) catch return errExit("oom");
        pr.* = .{ .id = undefined, .type_id = 0, .created_at = 0, .body = &.{} };
    }

    // Create a fresh Keychain protector. The --touch-id body flag tells
    // unwrap() to gate the fetch on a Touch ID prompt (LocalAuthentication).
    const flags: keychain_mod.Flags = if (touch_id) .touch_id else .default;
    const new_kp = keychain_mod.wrapWithFlags(allocator, &master_key, &parsed.master_key_id, flags) catch |e| switch (e) {
        else => {
            tty.writeStderr("keychain protector creation failed\n");
            tty.writeStderr(@errorName(e));
            tty.writeStderr("\n");
            return 1;
        },
    };
    kept.append(allocator, new_kp) catch return errExit("oom");

    // Re-serialize master.key.
    const new_file: master_key_mod.MasterFile = .{
        .master_key_id = parsed.master_key_id,
        .master_key_version = parsed.master_key_version,
        .protectors = kept.items,
    };
    const new_blob = master_key_mod.serialize(allocator, &new_file, &master_key) catch return errExit("serialize failed");
    defer allocator.free(new_blob);
    fsx.writeAllAtomic(p.master_key, new_blob, 0o600) catch return errExit("write master.key failed");

    audit_mod.log("reinstall-keychain", .cli, &.{audit_mod.b("touch_id", touch_id)});
    if (touch_id) {
        tty.writeStdout("Keychain protector rebuilt with Touch ID. The next vault access will\n");
        tty.writeStdout("trigger a fingerprint prompt; cancel falls back to passphrase.\n");
    } else {
        tty.writeStdout("Keychain protector rebuilt. The next access will prompt once;\n");
        tty.writeStdout("click \"Always Allow\" to suppress future prompts for this binary.\n");
    }
    return 0;
}

// ------- prune-keychain -------

fn runPruneKeychain(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var yes = false;
    for (args) |a| {
        if (std.mem.eql(u8, a, "--yes")) {
            yes = true;
        } else {
            tty.writeStderr("usage: secretctl prune-keychain [--yes]\n");
            return 2;
        }
    }

    var p = paths_mod.resolve(allocator) catch return errExit("cannot resolve paths");
    defer p.deinit();
    if (!fsx.fileExists(p.master_key)) {
        tty.writeStderr("no vault found; run `secretctl init` first\n");
        return 1;
    }
    const blob = fsx.readAllAlloc(allocator, p.master_key, 1 * 1024 * 1024) catch return errExit("read master.key failed");
    defer allocator.free(blob);
    if (blob.len < 26) return errExit("master.key too short");

    // Current vault's keychain account (read from the plaintext header).
    var mk_id: [16]u8 = undefined;
    @memcpy(&mk_id, blob[10..26]);
    var keep_buf: [32]u8 = undefined;
    keychain_mod.accountFor(&mk_id, &keep_buf);
    const keep = keep_buf[0..];
    // The current vault owns a second item: its TOTP seed. Without this, prune
    // would classify it as debris and silently destroy the 2FA enrolment —
    // which is exactly the failure mode `2fa-design.md` §5 item 6 recorded as
    // a guard that had to land before anything else depended on the keychain.
    var keep_totp_buf: [keychain_mod.totp_account_len]u8 = undefined;
    keychain_mod.totpAccountFor(&mk_id, &keep_totp_buf);
    const keep_totp = keep_totp_buf[0..];

    const accounts = keychain_mod.listAccounts(allocator) catch return errExit("keychain enumeration failed");
    defer {
        for (accounts) |a| allocator.free(a);
        allocator.free(accounts);
    }

    var stale: usize = 0;
    for (accounts) |acct| {
        if (std.mem.eql(u8, acct, keep)) continue;
        if (std.mem.eql(u8, acct, keep_totp)) continue;
        stale += 1;
        if (yes) {
            keychain_mod.deleteAccount(acct) catch {
                tty.writeStderr("  failed to delete ");
                tty.writeStderr(acct);
                tty.writeStderr("\n");
                continue;
            };
            tty.writeStdout("deleted ");
            tty.writeStdout(acct);
            tty.writeStdout("\n");
        } else {
            tty.writeStdout("would delete ");
            tty.writeStdout(acct);
            tty.writeStdout("\n");
        }
    }

    if (stale == 0) {
        tty.writeStdout("no stale secretctl keychain items (keeping this vault's wrap key and TOTP seed).\n");
        return 0;
    }
    if (yes) {
        audit_mod.log("prune-keychain", .cli, &.{audit_mod.s("kept", keep)});
        tty.writeStdout("done; kept the current vault's item.\n");
    } else {
        tty.writeStdout("\nthis is a dry run; re-run with --yes to delete the above (current vault is never touched).\n");
    }
    return 0;
}

// ------- helpers -------

fn isValidName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128) return false;
    for (name) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != '.') return false;
    }
    return true;
}

fn errExit(msg: []const u8) u8 {
    tty.writeStderr("secretctl: ");
    tty.writeStderr(msg);
    tty.writeStderr("\n");
    return 1;
}

const testing = std.testing;

test "envNameFromSecret normalizes case and separators" {
    const cases = .{
        .{ "service_token", "SERVICE_TOKEN" },
        .{ "my-api-key", "MY_API_KEY" },
        .{ "ALREADY_UPPER", "ALREADY_UPPER" },
        .{ "cloud_access_key_id", "CLOUD_ACCESS_KEY_ID" },
        .{ "db.host-name", "DB_HOST_NAME" },
    };
    inline for (cases) |c| {
        const got = try envNameFromSecret(testing.allocator, c[0]);
        defer testing.allocator.free(got);
        try testing.expectEqualStrings(c[1], got);
    }
}

test "envNameFromSecret prefixes a leading digit" {
    const got = try envNameFromSecret(testing.allocator, "1service");
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("_1SERVICE", got);
}

test "envNameFromSecret rejects empty name" {
    try testing.expectError(error.EmptyName, envNameFromSecret(testing.allocator, ""));
}
