const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const lib_mod = b.addModule("jwt", .{
        .root_source_file = b.path("root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const cricket = b.dependency("cricket", .{
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addImport("cricket", cricket.module("cricket"));

    const lib = b.addStaticLibrary(.{
        .name = "jwt",
        .root_module = lib_mod,
    });

    b.installArtifact(lib);

    const unit_tests_1 = b.addTest(.{
        .root_source_file = b.path("test_jwt.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests_2 = b.addTest(.{
        .root_source_file = b.path("test_payload.zig"),
        .target = target,
        .optimize = optimize,
    });

    const unit_tests_3 = b.addTest(.{
        .root_source_file = b.path("test_parse.zig"),
        .target = target,
        .optimize = optimize,
    });

    //modules import
    unit_tests_1.root_module.addImport("cricket", cricket.module("cricket"));

    // const run_lib_unit_tests_jwt = b.addRunArtifact(lib_unit_tests_jwt);
    const run_unit_test_1 = b.addRunArtifact(unit_tests_1);
    const run_unit_test_2 = b.addRunArtifact(unit_tests_2);
    const run_unit_test_3 = b.addRunArtifact(unit_tests_3);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_unit_test_1.step);
    test_step.dependOn(&run_unit_test_2.step);
    test_step.dependOn(&run_unit_test_3.step);
}
