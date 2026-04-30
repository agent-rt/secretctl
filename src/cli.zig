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
const master_key_mod = @import("master_key.zig");
const vault_mod = @import("vault.zig");
const edit_view = @import("edit_view.zig");
const list_view = @import("list_view.zig");
const policy_mod = @import("policy.zig");
const audit_mod = @import("audit.zig");
const editor_mod = @import("editor.zig");
const envelope_mod = @import("envelope.zig");
const mcp_mod = @import("mcp.zig");
const local_auth = @import("local_auth.zig");

pub const ExitCode = enum(u8) {
    success = 0,
    internal = 1,
    usage = 2,
    not_executable = 126,
    not_found = 127,
    _,
};

pub const usage_text =
    \\secretctl — single-binary local secret manager
    \\
    \\USAGE:
    \\  secretctl init [--no-touch-id]
    \\  secretctl add NAME [--tag X,Y] [--editor]
    \\  secretctl edit NAME
    \\  secretctl rm NAME
    \\  secretctl list [--json] [--tag X]
    \\  secretctl exec [--tag X] [--only N1,N2] -- COMMAND ARGS...
    \\  secretctl render TEMPLATE --out PATH
    \\  secretctl materialize NAME --out PATH [--mode MODE] [--mkdir]
    \\  secretctl reveal NAME
    \\  secretctl mcp [--cwd PATH] [--allow-secret-read]   # MCP server over stdio
    \\  secretctl reinstall-keychain [--no-touch-id]   # rebuild keychain protector
    \\
    \\ENV:
    \\  $VISUAL / $EDITOR control which editor `edit` and `add --editor` launch.
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
        tty.writeStdout("secretctl 0.1.0\n");
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
    if (std.mem.eql(u8, cmd, "mcp")) return runMcp(allocator, tail);
    if (std.mem.eql(u8, cmd, "reinstall-keychain")) return runReinstallKeychain(allocator, tail);

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

    var pw = if (batch) blk: {
        const line = tty.readLine(allocator, 4096) catch return errExit("password input failed");
        break :blk mem_util.Plaintext.fromOwnedSlice(allocator, line);
    } else tty.readNewPassword(allocator, 8) catch return errExit("password input failed");
    defer pw.deinit();

    // Batch mode (testing) keeps Keychain off by default so that test scripts
    // can pass `password\nvalue\n` over stdin reliably. Tests that need
    // Keychain (e.g. MCP smoke tests) set SECRETCTL_BATCH_KEYCHAIN=1.
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

fn unlockSession(allocator: std.mem.Allocator) ?Session {
    var p = paths_mod.resolve(allocator) catch return null;
    var ok = false;
    defer if (!ok) p.deinit();

    if (!fsx.fileExists(p.master_key)) {
        tty.writeStderr("no vault found; run `secretctl init` first\n");
        return null;
    }

    const blob = fsx.readAllAlloc(allocator, p.master_key, 1 * 1024 * 1024) catch return null;
    defer allocator.free(blob);

    var master_key: [aes.key_len]u8 = undefined;
    var attempt: u32 = 0;
    var unlocked = false;

    // First try: keychain only (no password prompt).
    var parsed = master_key_mod.parseAndUnlock(allocator, blob, null, &master_key) catch |e| switch (e) {
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
            var pw = tty.readPassword(allocator, "Master password: ") catch return null;
            defer pw.deinit();
            const result = master_key_mod.parseAndUnlock(allocator, blob, pw.bytes, &master_key) catch |e| switch (e) {
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
    parsed.deinit(allocator);

    const vresult = vault_mod.loadFromFile(allocator, p.vault, &master_key, null) catch |e| switch (e) {
        vault_mod.Error.AuthenticationFailed => {
            tty.writeStderr("vault contents do not match this master key\n");
            mem_util.secureZero(u8, &master_key);
            return null;
        },
        else => {
            tty.writeStderr("vault read failed\n");
            mem_util.secureZero(u8, &master_key);
            return null;
        },
    };

    ok = true;
    return Session{
        .paths = p,
        .master_key = master_key,
        .master_key_id = vresult.master_key_id,
        .master_key_version = vresult.master_key_version,
        .body = vresult.body,
        .allocator = allocator,
    };
}

// ------- add / rm -------

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

    var sess = unlockSession(allocator) orelse return 1;
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

    if (use_editor) {
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
                tty.writeStderr("add must run from a terminal (try --editor)\n");
                return 2;
            },
            error.Cancelled => return 1,
            else => return errExit("input failed"),
        };
        // Move ownership of value out of entry; tags need conversion to const.
        pt = entry.value;
        entry.value = mem_util.Plaintext.fromOwnedSlice(allocator, &.{}); // sentinel so deinit is cheap
        for (entry.tags) |t| tags_storage.append(allocator, t) catch return errExit("oom");
        // Detach tag ownership from entry so it doesn't free them.
        const tag_buf = entry.tags;
        entry.tags = &.{};
        entry.deinit();
        // tag_buf is now leaked structurally; free the outer slice (items already moved as []const u8 view).
        allocator.free(tag_buf);
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

    // tags_storage holds either CLI-arg slices (borrowed from argv) or pointers
    // to bytes owned by entry.tags freed above. The only ones we own and must
    // free are the duplicates from edit_view; those were already freed via the
    // detach trick. CLI tags are slices into argv → no free needed.

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

    var sess = unlockSession(allocator) orelse return 1;
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
    var sess = unlockSession(allocator) orelse return 1;
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

    var sess = unlockSession(allocator) orelse return 1;
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

fn runExec(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var tag_filter = std.ArrayList([]const u8).empty;
    defer tag_filter.deinit(allocator);
    var only_filter = std.ArrayList([]const u8).empty;
    defer only_filter.deinit(allocator);

    var i: usize = 0;
    var dash_dash: ?usize = null;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--")) {
            dash_dash = i;
            break;
        }
        if (std.mem.eql(u8, args[i], "--tag")) {
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

    var sess = unlockSession(allocator) orelse return 1;
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
    for (selected.items) |idx| {
        const rec = sess.body.secrets.items[idx];
        const pt = envelope_mod.decrypt(allocator, &sess.master_key, &sess.master_key_id, &rec.id, &rec.envelope) catch return errExit("decrypt failed");
        pts.append(allocator, pt) catch return errExit("oom");

        // Place into env (must be NUL-terminated for libc setenv).
        const name_z = allocator.allocSentinel(u8, rec.name.len, 0) catch return errExit("oom");
        @memcpy(name_z, rec.name);
        defer allocator.free(name_z);
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

    var sess = unlockSession(allocator) orelse return 1;
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
            const close = std.mem.indexOfScalarPos(u8, template, i + 2, '}') orelse {
                tty.writeStderr("unterminated ${...} placeholder in template\n");
                return 2;
            };
            const name = template[i + 2 .. close];
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
            i = close + 1;
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

    var sess = unlockSession(allocator) orelse return 1;
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

    var sess = unlockSession(allocator) orelse return 1;
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

// ------- mcp -------

fn runMcp(allocator: std.mem.Allocator, args: []const []const u8) u8 {
    var cwd: ?[]const u8 = null;
    var dangerous = false;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--cwd")) {
            i += 1;
            if (i >= args.len) {
                tty.writeStderr("--cwd requires a value\n");
                return 2;
            }
            cwd = args[i];
        } else if (std.mem.eql(u8, a, "--allow-secret-read")) {
            dangerous = true;
        } else {
            tty.writeStderr("unknown mcp flag: ");
            tty.writeStderr(a);
            tty.writeStderr("\n");
            return 2;
        }
    }
    return mcp_mod.serve(allocator, .{ .cwd = cwd, .dangerous = dangerous });
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
    var pw = tty.readPassword(allocator, "Master password: ") catch return errExit("password input failed");
    defer pw.deinit();

    var master_key: [aes.key_len]u8 = undefined;
    var parsed = master_key_mod.parseAndUnlock(allocator, blob, pw.bytes, &master_key) catch |e| switch (e) {
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
