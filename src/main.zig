const std = @import("std");
const network = @import("network");
const wolf = @import("wolf.zig");

pub fn main() !u8 {
    try wolf.init();
    defer wolf.deinit();

    var ssl_ctx = try wolf.Context.init();
    defer ssl_ctx.deinit();

    try ssl_ctx.loadVerifyLocations("/etc/ssl/cert.pem");

    // _ = c.wolfSSL_Debugging_ON();

    std.debug.warn("ssl initialized.\n", .{});

    var socket = try network.Socket.create(.ipv4, .tcp);
    defer socket.close();

    var ep = network.EndPoint{
        .address = network.Address{
            .ipv4 = network.Address.IPv4{
                .value = [_]u8{ 168, 235, 111, 58 },
            },
        },
        .port = 1965,
    };
    try socket.connect(ep);

    std.debug.warn("socket connected to {}.\n", .{ep});

    var ssl_con = try wolf.Connection.initFromFd(ssl_ctx, socket.internal);
    defer ssl_con.close();

    try ssl_con.connect();

    std.debug.warn("ssl connection established.\n", .{});

    const in = ssl_con.inStream();
    const out = ssl_con.outStream();

    try out.writeAll("gemini://gemini.circumlunar.space/\r\n");

    const response = try in.readUntilDelimiterAlloc(std.heap.page_allocator, '\n', 1024);

    std.debug.warn("handshake complete: {}\n", .{response});

    const stdout = std.io.getStdOut().outStream();

    while (true) {
        var buffer: [1024]u8 = undefined;

        var len = try in.readAll(&buffer);

        try stdout.writeAll(buffer[0..len]);

        if (len < buffer.len)
            break;
    }

    return 0;
}
