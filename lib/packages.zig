// zpm package file. do not modify (without knowing what you're doing)!
const std = @import("std");

pub fn get(comptime name: []const u8) std.build.Pkg {
    return @field(packages, name);
}

pub fn addAllTo(exe: *std.build.LibExeObjStep) void {
    inline for (std.meta.declarations(packages)) |decl| {
        exe.addPackage(@field(packages, decl.name));
    }
}

const packages = struct { // begin list
    // begin pkg
    const @"zig-network" = std.build.Pkg{
        .name = "zig-network",
        .path = "lib/zig-network/network.zig",
        .dependencies = null,
    };
    // end pkg
    // begin pkg
    const @"zig-args" = std.build.Pkg{
        .name = "zig-args",
        .path = "lib/zig-args/args.zig",
        .dependencies = null,
    };
    // end pkg
    // begin pkg
    const @"known-folders" = std.build.Pkg{
        .name = "known-folders",
        .path = "lib/known-folders/known-folders.zig",
        .dependencies = null,
    };
    // end pkg
    // begin pkg
    const @"zig-bearssl" = std.build.Pkg{
        .name = "zig-bearssl",
        .path = "lib/zig-bearssl/src/lib.zig",
        .dependencies = null,
    };
    // end pkg
    // begin pkg
    const @"zig-uri" = std.build.Pkg{
        .name = "zig-uri",
        .path = "lib/zig-uri/uri.zig",
        .dependencies = null,
    };
    // end pkg
}; // end list
