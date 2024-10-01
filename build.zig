const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod_known_folders = b.dependency("known-folders", .{}).module("known-folders");

    const exe = b.addExecutable(.{
        .name = "zigman",
        .root_source_file = b.path("src/zigman.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    exe.root_module.addImport("known-folders", mod_known_folders);
    b.installArtifact(exe);

    const run_exe = b.addRunArtifact(exe);
    if (b.args) |args| run_exe.addArgs(args);
    b.step("run", "Run zigman").dependOn(&run_exe.step);

    const test_exe = b.addTest(.{
        .root_source_file = b.path("src/zigman.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    test_exe.root_module.addImport("known-folders", mod_known_folders);

    const run_test_exe = b.addRunArtifact(test_exe);
    b.step("test", "Run the tests").dependOn(&run_test_exe.step);
}
