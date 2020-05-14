const std = @import("std");
const network = @import("network");
const ssl = @import("bearssl.zig");

const c = @cImport({
    @cInclude("bearssl.h");
});

// /*
// * Check whether we closed properly or not. If the engine is
// * closed, then its error status allows to distinguish between
// * a normal closure and a SSL error.
// *
// * If the engine is NOT closed, then this means that the
// * underlying network socket was closed or failed in some way.
// * Note that many Web servers out there do not properly close
// * their SSL connections (they don't send a close_notify alert),
// * which will be reported here as "socket closed without proper
// * SSL termination".
// */
//
// if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) {
//   int err;
//   err = br_ssl_engine_last_error(&sc.eng);
//   if (err == 0) {
//     fprintf(stderr, "closed.\n");
//     return EXIT_SUCCESS;
//   } else {
//     fprintf(stderr, "SSL error %d\n", err);
//     return EXIT_FAILURE;
//   }
// } else {
//   fprintf(stderr,
//     "socket closed without proper SSL termination\n");
//   return EXIT_FAILURE;
// }

// Load the system-local trust anchor (certificate authority certificates)
fn loadTrustAnchors(allocator: *std.mem.Allocator) !ssl.TrustAnchorCollection {
    var file = try std.fs.cwd().openFile("/etc/ssl/cert.pem", .{ .read = true, .write = false });
    defer file.close();

    const pem_text = try file.inStream().readAllAlloc(allocator, 1 << 20); // 1 MB

    return try ssl.TrustAnchorCollection.load(allocator, pem_text);
}

pub fn main() !u8 {
    const generic_allocator = std.heap.page_allocator; // THIS IS INEFFICIENT AS FUCK

    const stdout = std.io.getStdOut().outStream();

    var trust_anchors = try loadTrustAnchors(generic_allocator);
    defer trust_anchors.deinit();

    var ssl_context = ssl.Client.init(trust_anchors);
    ssl_context.relocate();
    try ssl_context.reset("gemini.circumlunar.space", false);

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

    var ssl_stream = ssl.Stream.init(ssl_context.getEngine(), socket.internal);
    defer if (ssl_stream.close()) {} else |err| {
        std.debug.warn("error when closing the stream: {}\n", .{err});
    };

    std.debug.warn("ssl connection established.\n", .{});

    const in = ssl_stream.inStream();
    const out = ssl_stream.outStream();

    const request = "gemini://gemini.circumlunar.space/docs/\r\n";

    try out.writeAll(request);
    try ssl_stream.flush();

    const response = try in.readUntilDelimiterAlloc(generic_allocator, '\n', 1024);

    std.debug.warn("handshake complete: {}\n", .{response});

    while (true) {
        var buffer: [1024]u8 = undefined;

        var len = try in.readAll(&buffer);

        try stdout.writeAll(buffer[0..len]);

        if (len < buffer.len)
            break;
    }

    return 0;
}
