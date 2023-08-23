const std = @import("std");

const builtin = @import("builtin");

const bearssl = @import("zig-bearssl");

pub fn build(b: *std.Build) !void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{
        .default_target = try std.zig.CrossTarget.parse(.{
            .arch_os_abi = if (builtin.os.tag == .windows)
                "native-native-gnu" // on windows, use gnu by default
            else
                "native-linux-musl", // glibc has some problems by-default, use musl instead
        }),
    });

    const gurl = b.addExecutable(.{
        .name = "gurl",
        .root_source_file = .{
            .path = "src/main.zig",
        },
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const gurl_test = b.addTest(.{
        .root_source_file = .{
            .path = "src/main.zig",
        },
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    const zig_network_dep = b.dependency("zig-network", .{});
    const zig_args_dep = b.dependency("zig-args", .{});
    const known_folders_dep = b.dependency("known-folders", .{});
    const bearssl_dep = b.dependency("zig-bearssl", .{});

    const zig_network = zig_network_dep.module("network");
    const zig_args = zig_args_dep.module("args");
    const known_folders = known_folders_dep.module("known-folders");
    const zig_bearssl = bearssl_dep.module("bearssl");

    for ([_]*std.Build.Step.Compile{ gurl, gurl_test }) |module| {
        bearssl.bearssl.linkBearSSL(bearssl_dep.builder.build_root.path orelse ".", module, target);
        module.addModule("zig-network", zig_network);
        module.addModule("zig-args", zig_args);
        module.addModule("known-folders", known_folders);
        module.addModule("zig-bearssl", zig_bearssl);
    }

    if (optimize != .Debug) {
        gurl.strip = true;
    }

    b.installArtifact(gurl);

    const gurl_exec = b.addRunArtifact(gurl);
    gurl_exec.addArgs(&[_][]const u8{
        "gemini://gemini.circumlunar.space/",
    });

    const run_step = b.step("run", "Runs gurl with gemini://gemini.circumlunar.space/");
    run_step.dependOn(&gurl_exec.step);

    const test_step = b.step("test", "Runs the test suite with queries to gemini.circumlunar.space");
    test_step.dependOn(&gurl_test.step);
}
