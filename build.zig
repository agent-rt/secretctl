const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (target.result.os.tag == .macos) {
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
