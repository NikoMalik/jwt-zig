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
    if (builtin.os.tag == .windows) {
        const openssl_path = std.os.getenv("OPENSSL_ROOT_DIR") orelse "C:/Program Files/OpenSSL";

        lib_mod.addIncludePath(.{ .cwd_relative = openssl_path ++ "/include" });

        lib_mod.addLibraryPath(.{ .cwd_relative = openssl_path ++ "/lib" });
        lib_mod.addLibraryPath(.{ .cwd_relative = openssl_path ++ "/bin" });

        const win_libs = [_][]const u8{ "libssl-3-x64", "libcrypto-3-x64", "crypt32", "ws2_32", "advapi32", "user32" };

        inline for (win_libs) |lib_name| {
            lib_mod.linkSystemLibrary(lib_name, .{});
            jwt_test.linkSystemLibrary(lib_name);
            rsa_test.linkSystemLibrary(lib_name);
            unit_tests_1.linkSystemLibrary(lib_name);
            unit_tests_2.linkSystemLibrary(lib_name);
            lib.linkSystemLibrary(lib_name);
            unit_tests_3.linkSystemLibrary(lib_name);
        }
    } else {
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
