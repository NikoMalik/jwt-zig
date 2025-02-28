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
    const cricket = b.dependency("cricket", .{
        .target = target,
        .optimize = optimize,
    });

    const lib = b.addStaticLibrary(.{
        .name = "jwt",
        .root_module = lib_mod,
        .link_libc = true,
    });

    b.installArtifact(lib);

    const unit_tests_1 = b.addTest(.{
        .root_source_file = b.path("test_jwt.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const unit_tests_2 = b.addTest(.{
        .root_source_file = b.path("test_payload.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const unit_tests_3 = b.addTest(.{
        .root_source_file = b.path("test_parse.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    unit_tests_1.root_module.addImport("cricket", cricket.module("cricket"));
    lib_mod.addImport("cricket", cricket.module("cricket"));

    const rsa_test = b.addTest(.{
        .root_source_file = b.path("rsa.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    const jwt_test = b.addTest(.{
        .root_source_file = b.path("jwt.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    if (builtin.target.os.tag == .windows) {
        lib_mod.linkSystemLibrary("libssl-3-x64", .{});
        lib_mod.linkSystemLibrary("libcrypto-3-x64", .{});
        lib_mod.addSystemIncludePath(.{ .cwd_relative = "C:\\Program Files\\OpenSSL\\include" });
        lib_mod.addLibraryPath(.{ .cwd_relative = "C:\\Program Files\\OpenSSL\\bin" });
        lib.addLibraryPath(.{ .cwd_relative = "C:\\Program Files\\OpenSSL\\bin" });
        lib.linkSystemLibrary("libssl-3-x64");
        lib.linkSystemLibrary("libcrypto-3-x64");
        lib.linkSystemLibrary("crypt32");
        lib.linkSystemLibrary("ws2_32");
        lib.linkSystemLibrary("advapi32");
        lib_mod.linkSystemLibrary("crypt32", .{});
        lib_mod.linkSystemLibrary("ws2_32", .{});
        lib_mod.linkSystemLibrary("advapi32", .{});
        lib.linkLibC();

        unit_tests_1.linkSystemLibrary("libssl-3-x64");
        unit_tests_1.linkSystemLibrary("libcrypto-3-x64");
        unit_tests_1.addLibraryPath(.{ .cwd_relative = "C:\\Program Files\\OpenSSL\\bin" });
        unit_tests_1.linkSystemLibrary("crypt32");
        unit_tests_1.linkSystemLibrary("ws2_32");
        unit_tests_1.linkSystemLibrary("advapi32");
        unit_tests_1.linkLibC();

        unit_tests_3.linkSystemLibrary("libssl-3-x64");
        unit_tests_3.linkSystemLibrary("libcrypto-3-x64");
        unit_tests_3.addLibraryPath(.{ .cwd_relative = "C:\\Program Files\\OpenSSL\\bin" });
        unit_tests_3.linkSystemLibrary("crypt32");
        unit_tests_3.linkSystemLibrary("ws2_32");
        unit_tests_3.linkSystemLibrary("advapi32");

        unit_tests_3.linkLibC();

        rsa_test.linkSystemLibrary("libssl-3-x64");
        rsa_test.linkSystemLibrary("libcrypto-3-x64");
        rsa_test.addLibraryPath(.{ .cwd_relative = "C:\\Program Files\\OpenSSL\\bin" });
        rsa_test.linkSystemLibrary("crypt32");
        rsa_test.linkSystemLibrary("ws2_32");
        rsa_test.linkSystemLibrary("advapi32");
        rsa_test.linkLibC();

        jwt_test.linkSystemLibrary("libssl-3-x64");
        jwt_test.linkSystemLibrary("libcrypto-3-x64");
        jwt_test.addLibraryPath(.{ .cwd_relative = "C:\\Program Files\\OpenSSL\\bin" });
        jwt_test.linkSystemLibrary("crypt32");
        jwt_test.linkSystemLibrary("ws2_32");
        jwt_test.linkSystemLibrary("advapi32");
        jwt_test.linkLibC();

        unit_tests_2.addLibraryPath(.{ .cwd_relative = "C:\\Program Files\\OpenSSL\\bin" });
        unit_tests_2.linkSystemLibrary("crypt32");
        unit_tests_2.linkSystemLibrary("ws2_32");
        unit_tests_2.linkSystemLibrary("advapi32");
        unit_tests_2.linkLibC();
    } else {
        lib_mod.linkSystemLibrary("ssl", .{});
        lib_mod.linkSystemLibrary("crypto", .{});

        lib.linkLibC();
        lib.linkSystemLibrary("ssl");
        lib.linkSystemLibrary("crypto");

        jwt_test.linkSystemLibrary("ssl");
        jwt_test.linkLibC();
        jwt_test.linkSystemLibrary("crypto");
        rsa_test.linkLibC();
        rsa_test.linkSystemLibrary("ssl");
        rsa_test.linkSystemLibrary("crypto");
        unit_tests_3.linkLibC();
        unit_tests_3.linkSystemLibrary("ssl");
        unit_tests_3.linkSystemLibrary("crypto");
        unit_tests_2.linkLibC();
        unit_tests_1.linkSystemLibrary("ssl");
        unit_tests_1.linkSystemLibrary("crypto");
        unit_tests_1.linkLibC();
    }

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
