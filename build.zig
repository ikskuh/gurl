const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{
        .default_target = try std.zig.CrossTarget.parse(.{
            .arch_os_abi = "native-native-gnu.2.25..2.25", // we need at least glibc 2.25 for getentropy
        }),
    });

    const gurl = b.addExecutable("gurl", "src/main.zig");
    const gurl_test = b.addTest("src/main.zig");

    for ([_]*std.build.LibExeObjStep{ gurl, gurl_test }) |module| {
        module.setBuildMode(mode);
        module.setTarget(target);
        module.linkLibC();

        module.addIncludeDir("./BearSSL/inc");
        module.addLibPath("./BearSSL/build");
        module.linkSystemLibrary("bearssl");

        module.addPackagePath("network", "./zig-network/network.zig");
        module.addPackagePath("uri", "./zig-uri/uri.zig");
        module.addPackagePath("args", "./zig-args/args.zig");
    }

    const gurl_exec = gurl.run();
    gurl_exec.addArgs(&[_][]const u8{
        "gemini://gemini.circumlunar.space/",
    });

    gurl.install();

    const run_step = b.step("run", "Runs gurl with gemini://gemini.circumlunar.space/");
    run_step.dependOn(&gurl_exec.step);

    const test_step = b.step("test", "Runs the test suite with queries to gemini.circumlunar.space");
    test_step.dependOn(&gurl_test.step);
}
