const std = @import("std");

const packages = @import("lib/packages.zig");
const bearssl = @import("lib/zig-bearssl/src/lib.zig");

pub fn build(b: *std.build.Builder) !void {
    const mode = b.standardReleaseOptions();
    const target = b.standardTargetOptions(.{
        .default_target = try std.zig.CrossTarget.parse(.{
            .arch_os_abi = if (std.builtin.os.tag == .windows)
                "native-native-gnu" // on windows, use gnu by default
            else
                "native-linux-musl", // glibc has some problems by-default, use musl instead
        }),
    });

    const gurl = b.addExecutable("gurl", "src/main.zig");
    const gurl_test = b.addTest("src/main.zig");

    for ([_]*std.build.LibExeObjStep{ gurl, gurl_test }) |module| {
        module.setTarget(target);
        module.setBuildMode(mode);
        module.linkLibC();

        packages.addAllTo(module);
        bearssl.linkBearSSL("lib/zig-bearssl/", module, target);
    }

    if (mode != .Debug) {
        gurl.strip = true;
    }

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
