const std = @import("std");
const network = @import("network");
const ssl = @import("bearssl.zig");
const uri = @import("uri");

const c = @cImport({
    @cInclude("bearssl.h");
});

// gemini://gemini.circumlunar.space/docs/spec-spec.txt
// gemini://gemini.conman.org/test/torture/0000

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
    defer allocator.free(pem_text);

    return try ssl.TrustAnchorCollection.load(allocator, pem_text);
}

pub const Response = union(enum) {
    const Self = @This();

    input: Input,
    success: Body,
    redirect: Redirect,
    temporaryFailure: Failure,
    permanentFailure: Failure,
    clientCertificateRequired: CertificateAction,

    fn free(self: Self, allocator: *std.mem.Allocator) void {
        switch (self) {
            .input => |input| {
                allocator.free(input.prompt);
            },
            .redirect => |redir| {
                allocator.free(redir.target);
            },
            .success => |body| {
                allocator.free(body.mime);
                allocator.free(body.data);
            },
            .temporaryFailure, .permanentFailure => |fail| {
                allocator.free(fail.message);
            },
            .clientCertificateRequired => |cert| {
                allocator.free(cert.message);
            },
        }
    }

    pub const Input = struct {
        prompt: []const u8,
    };

    pub const Body = struct {
        mime: []const u8,
        data: []const u8,
        isEndOfClientCertificateSession: bool,
    };

    pub const Redirect = struct {
        pub const Type = enum { permanent, temporary };

        target: []const u8,
        type: Type,
    };

    pub const Failure = struct {
        pub const Type = enum {
            unspecified,
            serverUnavailable,
            cgiError,
            proxyError,
            slowDown,
            notFound,
            gone,
            proxyRequestRefused,
            badRequest,
        };

        type: Type,
        message: []const u8,
    };

    pub const CertificateAction = struct {
        pub const Type = enum {
            unspecified,
            transientCertificateRequested,
            authorisedCertificateRequired,
            certificateNotAccepted,
            futureCertificateRejected,
            expiredCertificateRejected,
        };

        type: Type,
        message: []const u8,
    };
};
pub const ResponseType = @TagType(Response);

pub fn requestRaw(allocator: *std.mem.Allocator, trust_anchors: ssl.TrustAnchorCollection, url: []const u8, memoryLimit: usize) !Response {
    if (url.len > 1024)
        return error.InvalidUrl;

    var temp_allocator_buffer: [5000]u8 = undefined;
    var temp_allocator = std.heap.FixedBufferAllocator.init(&temp_allocator_buffer);

    const parsed_url = uri.parse(url) catch return error.InvalidUrl;

    if (parsed_url.scheme == null)
        return error.InvalidUrl;
    if (!std.mem.eql(u8, parsed_url.scheme.?, "gemini"))
        return error.UnsupportedScheme;

    if (parsed_url.host == null)
        return error.InvalidUrl;

    const hostname_z = try std.mem.dupeZ(&temp_allocator.allocator, u8, parsed_url.host.?);

    const address_list = try std.net.getAddressList(&temp_allocator.allocator, hostname_z, parsed_url.port orelse 1965);
    defer address_list.deinit();

    var socket = for (address_list.addrs) |addr| {
        var ep = network.EndPoint.fromSocketAddress(&addr.any, addr.getOsSockLen()) catch |err| switch (err) {
            error.UnsupportedAddressFamily => continue,
            else => return err,
        };

        var sock = try network.Socket.create(ep.address, .tcp);
        errdefer sock.close();

        sock.connect(ep) catch {
            sock.close();
            continue;
        };

        break sock;
    } else return error.CouldNotConnect;

    // std.debug.warn("socket connected to {}.\n", .{ep});

    var ssl_context = ssl.Client.init(trust_anchors);
    ssl_context.relocate();
    try ssl_context.reset(hostname_z, false);
    // std.debug.warn("ssl initialized.\n", .{});

    var ssl_stream = ssl.Stream.init(ssl_context.getEngine(), socket.internal);
    defer if (ssl_stream.close()) {} else |err| {
        std.debug.warn("error when closing the stream: {}\n", .{err});
    };

    const in = ssl_stream.inStream();
    const out = ssl_stream.outStream();

    var work_buf: [1500]u8 = undefined;

    const request = try std.fmt.bufPrint(&work_buf, "{}\r\n", .{url});

    out.writeAll(request) catch |err| switch (err) {
        error.X509_NOT_TRUSTED => return error.UntrustedCertificate,
        error.X509_BAD_SERVER_NAME => return error.BadServerName,
        else => return err,
    };
    try ssl_stream.flush();

    const response = if (try in.readUntilDelimiterOrEof(&work_buf, '\n')) |buf|
        buf
    else
        return error.InvalidResponse;

    if (response.len < 3)
        return error.InvalidResponse;

    if (response[response.len - 1] != '\r') // not delimited by \r\n
        return error.InvalidResponse;

    if (!std.ascii.isDigit(response[0])) // not a number
        return error.InvalidResponse;

    if (!std.ascii.isDigit(response[1])) // not a number
        return error.InvalidResponse;

    const meta = std.mem.trim(u8, response[2..], " \t\r\n");
    if (meta.len > 1024)
        return error.InvalidResponse;

    // std.debug.warn("handshake complete: {}\n", .{response});

    switch (response[0]) { // primary status code
        '1' => { // INPUT
            var prompt = try std.mem.dupe(allocator, u8, meta);
            errdefer allocator.free(prompt);

            return Response{
                .input = Response.Input{
                    .prompt = prompt,
                },
            };
        },
        '2' => { // SUCCESS
            var mime = try std.mem.dupe(allocator, u8, meta);
            errdefer allocator.free(mime);

            var data = try in.readAllAlloc(allocator, memoryLimit);

            return Response{
                .success = Response.Body{
                    .mime = mime,
                    .data = data,
                    .isEndOfClientCertificateSession = (response[1] == '1'), // check for 21
                },
            };
        },
        '3' => { // REDIRECT
            var target = try std.mem.dupe(allocator, u8, meta);
            errdefer allocator.free(target);

            return Response{
                .redirect = Response.Redirect{
                    .target = target,
                    .type = if (response[1] == '1')
                        Response.Redirect.Type.permanent
                    else
                        Response.Redirect.Type.temporary,
                },
            };
        },
        '4' => { // TEMPORARY FAILURE
            var message = try std.mem.dupe(allocator, u8, meta);
            errdefer allocator.free(message);

            return Response{
                .temporaryFailure = Response.Failure{
                    .type = switch (response[1]) {
                        '1' => Response.Failure.Type.serverUnavailable,
                        '2' => Response.Failure.Type.cgiError,
                        '3' => Response.Failure.Type.proxyError,
                        '4' => Response.Failure.Type.slowDown,
                        else => Response.Failure.Type.unspecified,
                    },
                    .message = message,
                },
            };
        },
        '5' => { // PERMANENT FAILURE
            var message = try std.mem.dupe(allocator, u8, meta);
            errdefer allocator.free(message);

            return Response{
                .permanentFailure = Response.Failure{
                    .type = switch (response[1]) {
                        '1' => Response.Failure.Type.notFound,
                        '2' => Response.Failure.Type.gone,
                        '3' => Response.Failure.Type.proxyRequestRefused,
                        '4' => Response.Failure.Type.badRequest,
                        else => Response.Failure.Type.unspecified,
                    },
                    .message = message,
                },
            };
        },
        '6' => { // CLIENT CERTIFICATE REQUIRED
            var message = try std.mem.dupe(allocator, u8, meta);
            errdefer allocator.free(message);

            return Response{
                .clientCertificateRequired = Response.CertificateAction{
                    .type = switch (response[1]) {
                        '1' => Response.CertificateAction.Type.transientCertificateRequested,
                        '2' => Response.CertificateAction.Type.authorisedCertificateRequired,
                        '3' => Response.CertificateAction.Type.certificateNotAccepted,
                        '4' => Response.CertificateAction.Type.futureCertificateRejected,
                        '5' => Response.CertificateAction.Type.expiredCertificateRejected,
                        else => Response.CertificateAction.Type.unspecified,
                    },
                    .message = message,
                },
            };
        },
        else => return error.UnknownStatusCode,
    }

    unreachable;
}

pub fn main() !u8 {
    const generic_allocator = std.heap.page_allocator; // THIS IS INEFFICIENT AS FUCK

    const stdout = std.io.getStdOut().outStream();

    var trust_anchors = try loadTrustAnchors(generic_allocator);
    defer trust_anchors.deinit();

    // TODO:
    // - "gemini://heavysquare.com/" does not send an end-of-stream?!
    // - ""gemini://typed-hole.org/topkek" does not send an end-of-stream?!

    // "gemini://gemini.circumlunar.space/docs/"
    const request_uri = "gemini://mozz.us/tpokek";

    var response = try requestRaw(generic_allocator, trust_anchors, request_uri, 100 * mebi_bytes);

    switch (response) {
        .success => |body| {
            try stdout.print("MIME: {0}\n", .{body.mime});
            try stdout.writeAll(body.data);
        },
        else => try stdout.print("unimplemented response type: {}\n", .{response}),
    }

    return 0;
}

const kibi_bytes = 1024;
const mebi_bytes = 1024 * 1024;
const gibi_bytes = 1024 * 1024 * 1024;

const kilo_bytes = 1000;
const mega_bytes = 1000_000;
const giga_bytes = 1000_000_000;

// tests

test "loading system certs" {
    var file = try std.fs.cwd().openFile("/etc/ssl/cert.pem", .{ .read = true, .write = false });
    defer file.close();

    const pem_text = try file.inStream().readAllAlloc(std.testing.allocator, 1 << 20); // 1 MB
    defer std.testing.allocator.free(pem_text);

    var trust_anchors = try ssl.TrustAnchorCollection.load(std.testing.allocator, pem_text);
    trust_anchors.deinit();
}

const TestExpection = union(enum) {
    response: ResponseType,
    err: anyerror,
};

fn runTestRequest(url: []const u8, expected_response: TestExpection) !void {
    var trust_anchors = try loadTrustAnchors(std.testing.allocator);
    defer trust_anchors.deinit();

    if (requestRaw(std.testing.allocator, trust_anchors, url, 100 * mebi_bytes)) |response| {
        defer response.free(std.testing.allocator);

        if (expected_response != .response) {
            std.debug.warn("Expected error, but got {}\n", .{@as(ResponseType, response)});
            return error.UnexpectedResponse;
        }

        if (response != expected_response.response) {
            std.debug.warn("Expected {}, but got {}\n", .{ expected_response.response, @as(ResponseType, response) });
            return error.UnexpectedResponse;
        }
    } else |err| {
        if (expected_response != .err) {
            std.debug.warn("Expected {}, but got error {}\n", .{ expected_response.response, err });
            return error.UnexpectedResponse;
        }
        if (err != expected_response.err) {
            std.debug.warn("Expected error {}, but got error {}\n", .{ expected_response.err, err });
            return error.UnexpectedResponse;
        }
    }
}

test "10 INPUT: query gus" {
    try runTestRequest("gemini://gus.guru/search", .{ .response = .input });
}

test "51 PERMANENT FAILURE: query mozz.us" {
    try runTestRequest("gemini://mozz.us/topkek", .{ .response = .permanentFailure });
}

// Run test suite against conmans torture suit
//

// Index page
test "torture suite (0000)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0000", .{ .response = .success });
}

// Redirect-continous temporary redirects
test "torture suite (0022)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell/", .{ .response = .redirect });
}

// Redirect-continous permanent redirects
test "torture suite (0023)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell2/", .{ .response = .redirect });
}

// Redirect-continous random temporary or permanent redirects
test "torture suite (0024)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell3/", .{ .response = .redirect });
}

// Redirect-continous temporary redirects to itself
test "torture suite (0025)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell4", .{ .response = .redirect });
}

// Redirect-continous permanent redirects to itself
test "torture suite (0026)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell5", .{ .response = .redirect });
}

// Redirect-to a non-gemini link
test "torture suite (0027)" {
    try runTestRequest("gemini://gemini.conman.org/test/redirhell6", .{ .response = .redirect });
}

// Status-undefined status code
test "torture suite (0034)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0034a", .{ .err = error.UnknownStatusCode });
}

// Status-undefined success status code
test "torture suite (0035)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0035a", .{ .response = .success });
}

// Status-undefined redirect status code
test "torture suite (0036)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0036a", .{ .response = .redirect });
}

// Status-undefined temporary status code
test "torture suite (0037)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0037a", .{ .response = .temporaryFailure });
}

// Status-undefined permanent status code
test "torture suite (0038)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0038a", .{ .response = .permanentFailure });
}

// Status-one digit status code
test "torture suite (0039)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0039a", .{ .err = error.InvalidResponse });
}

// Status-complete blank line
test "torture suite (0040)" {
    try runTestRequest("gemini://gemini.conman.org/test/torture/0040a", .{ .err = error.InvalidResponse });
}
