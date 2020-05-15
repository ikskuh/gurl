const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{
        .default_target = try std.zig.CrossTarget.parse(.{
            .arch_os_abi = "native-native-gnu.2.25..2.25", // we need at least glibc 2.25 for getentropy
        }),
    });

    const gurl = b.addExecutable("gurl", "src/main.zig");
    gurl.setBuildMode(mode);
    gurl.setTarget(target);
    gurl.linkLibC();

    gurl.addIncludeDir("./BearSSL/inc");
    gurl.addLibPath("./BearSSL/build");
    gurl.linkSystemLibrary("bearssl");

    gurl.addPackagePath("network", "./zig-network/network.zig");
    gurl.addPackagePath("uri", "./zig-uri/uri.zig");

    const gurl_test = b.addTest("src/main.zig");
    gurl_test.setBuildMode(mode);
    gurl_test.setTarget(target);
    gurl_test.linkLibC();

    gurl_test.addIncludeDir("./BearSSL/inc");
    gurl_test.addLibPath("./BearSSL/build");
    gurl_test.linkSystemLibrary("bearssl");

    gurl_test.addPackagePath("network", "./zig-network/network.zig");
    gurl_test.addPackagePath("uri", "./zig-uri/uri.zig");

    gurl.install();

    const gurl_exec = gurl.run();
    gurl_exec.addArgs(&[_][]const u8{
        "gemini://gemini.circumlunar.space/",
    });

    const run_step = b.step("run", "Runs gurl with gemini://gemini.circumlunar.space/");
    run_step.dependOn(&gurl_exec.step);

    const test_step = b.step("test", "Runs the test suite with queries to gemini.circumlunar.space");
    test_step.dependOn(&gurl_test.step);
}
