const std = @import("std");
const CrossTarget = std.Target.Query;
const builtin = @import("builtin");
const fs = std.fs;

const CryptoLib = enum { openssl, boringssl };

const crypto_lib: CryptoLib = .openssl;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const lib_mod = b.addModule("jwt", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lib_mod.addSystemIncludePath(.{ .cwd_relative = "/usr/local/opt/openssl@3/include" });
    const cricket = b.dependency("cricket", .{
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addLibrary(.{
        .name = "jwt",
        .root_module = lib_mod,
        .linkage = .static,
    });

    b.installArtifact(lib);

    const unit_tests_1_module = b.createModule(.{
        .root_source_file = b.path("test_jwt.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const unit_tests_1 = b.addTest(.{
        .name = "test_jwt",
        .root_module = unit_tests_1_module,
    });

    const unit_tests_2_module = b.createModule(.{
        .root_source_file = b.path("test_payload.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const unit_tests_2 = b.addTest(.{
        .name = "test_payload",
        .root_module = unit_tests_2_module,
    });

    const unit_tests_3_module = b.createModule(.{
        .root_source_file = b.path("test_parse.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const unit_tests_3 = b.addTest(.{
        .name = "test_parse",
        .root_module = unit_tests_3_module,
    });
    unit_tests_1.root_module.addImport("cricket", cricket.module("cricket"));
    lib_mod.addImport("cricket", cricket.module("cricket"));

    const rsa_test_module = b.createModule(.{
        .root_source_file = b.path("rsa.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    rsa_test_module.addSystemIncludePath(.{ .cwd_relative = "/usr/local/opt/openssl@3/include" });
    const rsa_test = b.addTest(.{
        .name = "rsa",
        .root_module = rsa_test_module,
    });
    const jwt_test_module = b.createModule(.{
        .root_source_file = b.path("jwt.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    jwt_test_module.addSystemIncludePath(.{ .cwd_relative = "/usr/local/opt/openssl@3/include" });
    const jwt_test = b.addTest(.{
        .name = "jwt",
        .root_module = jwt_test_module,
    });
    lib_mod.linkSystemLibrary("ssl", .{});
    lib_mod.linkSystemLibrary("crypto", .{});

    lib.linkLibC();
    lib.linkSystemLibrary("ssl");
    lib.linkSystemLibrary("crypto");

    jwt_test.linkSystemLibrary("ssl");
    jwt_test.linkSystemLibrary("crypto");
    jwt_test.linkLibC();
    rsa_test.linkLibC();

    rsa_test.linkSystemLibrary("ssl");
    rsa_test.linkSystemLibrary("crypto");

    unit_tests_3.linkSystemLibrary("ssl");
    unit_tests_3.linkSystemLibrary("crypto");
    unit_tests_3.linkLibC();
    unit_tests_2.linkLibC();
    unit_tests_1.linkSystemLibrary("ssl");
    unit_tests_1.linkSystemLibrary("crypto");
    unit_tests_1.linkLibC();

    // tests running
    // ============
    const run_unit_test_1 = b.addRunArtifact(unit_tests_1);
    const run_unit_test_2 = b.addRunArtifact(unit_tests_2);

    const run_unit_test_3 = b.addRunArtifact(unit_tests_3);
    const run_unit_test4 = b.addRunArtifact(rsa_test);
    const run_unit_test5 = b.addRunArtifact(jwt_test);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_unit_test_1.step);
    test_step.dependOn(&run_unit_test_2.step);
    test_step.dependOn(&run_unit_test_3.step);
    test_step.dependOn(&run_unit_test4.step);

    test_step.dependOn(&run_unit_test5.step);
}
