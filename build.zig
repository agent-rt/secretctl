const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // In nix sandboxes there's no Xcode toolchain, so Zig can't auto-detect
    // the macOS SDK. The apple-sdk derivation exports `SDKROOT`; if it's set
    // we hand its framework dir to every module that needs Apple frameworks.
    const sdk_paths: ?struct {
        framework: std.Build.LazyPath,
        include: std.Build.LazyPath,
    } = blk: {
        const sdkroot = b.graph.environ_map.get("SDKROOT") orelse break :blk null;
        break :blk .{
            .framework = .{ .cwd_relative = b.pathJoin(&.{ sdkroot, "System", "Library", "Frameworks" }) },
            .include = .{ .cwd_relative = b.pathJoin(&.{ sdkroot, "usr", "include" }) },
        };
    };

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.os.tag == .macos) {
        if (sdk_paths) |p| {
            exe_mod.addFrameworkPath(p.framework);
            exe_mod.addSystemIncludePath(p.include);
        }
        exe_mod.linkFramework("Security", .{});
        exe_mod.linkFramework("CoreFoundation", .{});
        exe_mod.linkFramework("LocalAuthentication", .{});
        exe_mod.linkFramework("Foundation", .{});
        exe_mod.addCSourceFile(.{
            .file = b.path("src/local_auth.m"),
            .flags = &.{ "-fobjc-arc", "-Wno-everything" },
        });
    }
    exe_mod.link_libc = true;

    const exe = b.addExecutable(.{
        .name = "secretctl",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run secretctl");
    run_step.dependOn(&run_cmd.step);

    // Single test target rooted at lib.zig — refAllDeclsRecursive collects every test.
    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.os.tag == .macos) {
        if (sdk_paths) |p| {
            test_mod.addFrameworkPath(p.framework);
            test_mod.addSystemIncludePath(p.include);
        }
        test_mod.linkFramework("Security", .{});
        test_mod.linkFramework("CoreFoundation", .{});
        test_mod.linkFramework("LocalAuthentication", .{});
        test_mod.linkFramework("Foundation", .{});
        test_mod.addCSourceFile(.{
            .file = b.path("src/local_auth.m"),
            .flags = &.{ "-fobjc-arc", "-Wno-everything" },
        });
    }
    test_mod.link_libc = true;
    const t = b.addTest(.{ .root_module = test_mod });
    const run_t = b.addRunArtifact(t);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_t.step);
}
