const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{});

    const gurl = b.addExecutable("gget", "src/main.zig");
    gurl.setBuildMode(mode);
    gurl.setTarget(target);
    gurl.linkLibC();

    gurl.addIncludeDir("./BearSSL/inc");
    gurl.addLibPath("./BearSSL/build");
    gurl.linkSystemLibrary("bearssl");

    gurl.addPackagePath("network", "./zig-network/network.zig");

    gurl.install();

    const gurl_exec = gurl.run();
    gurl_exec.addArgs(&[_][]const u8{
        "gemini://gemini.circumlunar.space/",
    });

    const run_step = b.step("run", "Runs gurl with gemini://gemini.circumlunar.space/");
    run_step.dependOn(&gurl_exec.step);
}
