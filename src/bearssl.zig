const std = @import("std");

const c = @cImport({
    @cInclude("bearssl.h");
});

pub const BearError = error{
    BAD_PARAM,
    BAD_STATE,
    UNSUPPORTED_VERSION,
    BAD_VERSION,
    BAD_LENGTH,
    TOO_LARGE,
    BAD_MAC,
    NO_RANDOM,
    UNKNOWN_TYPE,
    UNEXPECTED,
    BAD_CCS,
    BAD_ALERT,
    BAD_HANDSHAKE,
    OVERSIZED_ID,
    BAD_CIPHER_SUITE,
    BAD_COMPRESSION,
    BAD_FRAGLEN,
    BAD_SECRENEG,
    EXTRA_EXTENSION,
    BAD_SNI,
    BAD_HELLO_DONE,
    LIMIT_EXCEEDED,
    BAD_FINISHED,
    RESUME_MISMATCH,
    INVALID_ALGORITHM,
    BAD_SIGNATURE,
    WRONG_KEY_USAGE,
    NO_CLIENT_AUTH,
    IO,
    X509_INVALID_VALUE,
    X509_TRUNCATED,
    X509_EMPTY_CHAIN,
    X509_INNER_TRUNC,
    X509_BAD_TAG_CLASS,
    X509_BAD_TAG_VALUE,
    X509_INDEFINITE_LENGTH,
    X509_EXTRA_ELEMENT,
    X509_UNEXPECTED,
    X509_NOT_CONSTRUCTED,
    X509_NOT_PRIMITIVE,
    X509_PARTIAL_BYTE,
    X509_BAD_BOOLEAN,
    X509_OVERFLOW,
    X509_BAD_DN,
    X509_BAD_TIME,
    X509_UNSUPPORTED,
    X509_LIMIT_EXCEEDED,
    X509_WRONG_KEY_TYPE,
    X509_BAD_SIGNATURE,
    X509_TIME_UNKNOWN,
    X509_EXPIRED,
    X509_DN_MISMATCH,
    X509_BAD_SERVER_NAME,
    X509_CRITICAL_EXTENSION,
    X509_NOT_CA,
    X509_FORBIDDEN_KEY_USAGE,
    X509_WEAK_PUBLIC_KEY,
    X509_NOT_TRUSTED,
};
fn convertError(err: c_int) BearError {
    return switch (err) {
        c.BR_ERR_BAD_PARAM => error.BAD_PARAM,
        c.BR_ERR_BAD_STATE => error.BAD_STATE,
        c.BR_ERR_UNSUPPORTED_VERSION => error.UNSUPPORTED_VERSION,
        c.BR_ERR_BAD_VERSION => error.BAD_VERSION,
        c.BR_ERR_BAD_LENGTH => error.BAD_LENGTH,
        c.BR_ERR_TOO_LARGE => error.TOO_LARGE,
        c.BR_ERR_BAD_MAC => error.BAD_MAC,
        c.BR_ERR_NO_RANDOM => error.NO_RANDOM,
        c.BR_ERR_UNKNOWN_TYPE => error.UNKNOWN_TYPE,
        c.BR_ERR_UNEXPECTED => error.UNEXPECTED,
        c.BR_ERR_BAD_CCS => error.BAD_CCS,
        c.BR_ERR_BAD_ALERT => error.BAD_ALERT,
        c.BR_ERR_BAD_HANDSHAKE => error.BAD_HANDSHAKE,
        c.BR_ERR_OVERSIZED_ID => error.OVERSIZED_ID,
        c.BR_ERR_BAD_CIPHER_SUITE => error.BAD_CIPHER_SUITE,
        c.BR_ERR_BAD_COMPRESSION => error.BAD_COMPRESSION,
        c.BR_ERR_BAD_FRAGLEN => error.BAD_FRAGLEN,
        c.BR_ERR_BAD_SECRENEG => error.BAD_SECRENEG,
        c.BR_ERR_EXTRA_EXTENSION => error.EXTRA_EXTENSION,
        c.BR_ERR_BAD_SNI => error.BAD_SNI,
        c.BR_ERR_BAD_HELLO_DONE => error.BAD_HELLO_DONE,
        c.BR_ERR_LIMIT_EXCEEDED => error.LIMIT_EXCEEDED,
        c.BR_ERR_BAD_FINISHED => error.BAD_FINISHED,
        c.BR_ERR_RESUME_MISMATCH => error.RESUME_MISMATCH,
        c.BR_ERR_INVALID_ALGORITHM => error.INVALID_ALGORITHM,
        c.BR_ERR_BAD_SIGNATURE => error.BAD_SIGNATURE,
        c.BR_ERR_WRONG_KEY_USAGE => error.WRONG_KEY_USAGE,
        c.BR_ERR_NO_CLIENT_AUTH => error.NO_CLIENT_AUTH,
        c.BR_ERR_IO => error.IO,
        c.BR_ERR_X509_INVALID_VALUE => error.X509_INVALID_VALUE,
        c.BR_ERR_X509_TRUNCATED => error.X509_TRUNCATED,
        c.BR_ERR_X509_EMPTY_CHAIN => error.X509_EMPTY_CHAIN,
        c.BR_ERR_X509_INNER_TRUNC => error.X509_INNER_TRUNC,
        c.BR_ERR_X509_BAD_TAG_CLASS => error.X509_BAD_TAG_CLASS,
        c.BR_ERR_X509_BAD_TAG_VALUE => error.X509_BAD_TAG_VALUE,
        c.BR_ERR_X509_INDEFINITE_LENGTH => error.X509_INDEFINITE_LENGTH,
        c.BR_ERR_X509_EXTRA_ELEMENT => error.X509_EXTRA_ELEMENT,
        c.BR_ERR_X509_UNEXPECTED => error.X509_UNEXPECTED,
        c.BR_ERR_X509_NOT_CONSTRUCTED => error.X509_NOT_CONSTRUCTED,
        c.BR_ERR_X509_NOT_PRIMITIVE => error.X509_NOT_PRIMITIVE,
        c.BR_ERR_X509_PARTIAL_BYTE => error.X509_PARTIAL_BYTE,
        c.BR_ERR_X509_BAD_BOOLEAN => error.X509_BAD_BOOLEAN,
        c.BR_ERR_X509_OVERFLOW => error.X509_OVERFLOW,
        c.BR_ERR_X509_BAD_DN => error.X509_BAD_DN,
        c.BR_ERR_X509_BAD_TIME => error.X509_BAD_TIME,
        c.BR_ERR_X509_UNSUPPORTED => error.X509_UNSUPPORTED,
        c.BR_ERR_X509_LIMIT_EXCEEDED => error.X509_LIMIT_EXCEEDED,
        c.BR_ERR_X509_WRONG_KEY_TYPE => error.X509_WRONG_KEY_TYPE,
        c.BR_ERR_X509_BAD_SIGNATURE => error.X509_BAD_SIGNATURE,
        c.BR_ERR_X509_TIME_UNKNOWN => error.X509_TIME_UNKNOWN,
        c.BR_ERR_X509_EXPIRED => error.X509_EXPIRED,
        c.BR_ERR_X509_DN_MISMATCH => error.X509_DN_MISMATCH,
        c.BR_ERR_X509_BAD_SERVER_NAME => error.X509_BAD_SERVER_NAME,
        c.BR_ERR_X509_CRITICAL_EXTENSION => error.X509_CRITICAL_EXTENSION,
        c.BR_ERR_X509_NOT_CA => error.X509_NOT_CA,
        c.BR_ERR_X509_FORBIDDEN_KEY_USAGE => error.X509_FORBIDDEN_KEY_USAGE,
        c.BR_ERR_X509_WEAK_PUBLIC_KEY => error.X509_WEAK_PUBLIC_KEY,
        c.BR_ERR_X509_NOT_TRUSTED => error.X509_NOT_TRUSTED,

        else => std.debug.panic("missing error code: {}", .{err}),
    };
}

pub const TrustAnchorCollection = struct {
    const Self = @This();

    arena: std.heap.ArenaAllocator,
    items: []c.br_x509_trust_anchor,

    pub fn load(allocator: *std.mem.Allocator, pem_text: []const u8) !Self {
        var objectBuffer = std.ArrayList(u8).init(allocator);
        defer objectBuffer.deinit();

        try objectBuffer.ensureCapacity(8192);

        var x509_decoder: c.br_pem_decoder_context = undefined;
        c.br_pem_decoder_init(&x509_decoder);

        var current_obj_is_certificate = false;

        var arena = std.heap.ArenaAllocator.init(allocator);

        var trust_anchors = std.ArrayList(c.br_x509_trust_anchor).init(&arena.allocator);
        defer trust_anchors.deinit();

        var offset: usize = 0;
        while (offset < pem_text.len) {
            var diff = c.br_pem_decoder_push(&x509_decoder, pem_text.ptr + offset, pem_text.len - offset);
            offset += diff;

            var event = c.br_pem_decoder_event(&x509_decoder);
            switch (event) {
                0 => unreachable, // there must be an event, we always push the full file

                c.BR_PEM_BEGIN_OBJ => {
                    const name = std.mem.spanZ(c.br_pem_decoder_name(&x509_decoder));
                    current_obj_is_certificate = std.mem.eql(u8, name, "CERTIFICATE") or std.mem.eql(u8, name, "X509 CERTIFICATE");
                    if (current_obj_is_certificate) {
                        try objectBuffer.resize(0);
                        c.br_pem_decoder_setdest(&x509_decoder, appendToBuffer, &objectBuffer);
                    } else {
                        std.debug.warn("ignore object of type '{}'\n", .{name});
                        c.br_pem_decoder_setdest(&x509_decoder, null, null);
                    }
                },
                c.BR_PEM_END_OBJ => {
                    if (current_obj_is_certificate) {
                        var certificate = c.br_x509_certificate{
                            .data = objectBuffer.items.ptr,
                            .data_len = objectBuffer.items.len,
                        };

                        var trust_anchor = try convertToTrustAnchor(&arena.allocator, certificate);

                        try trust_anchors.append(trust_anchor);
                        // ignore end of
                    } else {
                        std.debug.warn("end of ignored object.\n", .{});
                    }
                },
                c.BR_PEM_ERROR => {
                    std.debug.warn("pem error:\n", .{});
                },

                else => unreachable, // no other values are specified
            }
        }

        return Self{
            .items = trust_anchors.toOwnedSlice(),
            .arena = arena,
        };
    }

    pub fn deinit(self: Self) void {
        self.arena.deinit();
    }
};

/// Custom x509 engine that uses the minimal engine and ignores missing trust.
/// First step in TOFU direction
const CertificateValidator = extern struct {
    const Self = @This();
    const class = c.br_x509_class{
        .context_size = @sizeOf(Self),
        .start_chain = start_chain,
        .start_cert = start_cert,
        .append = append,
        .end_cert = end_cert,
        .end_chain = end_chain,
        .get_pkey = get_pkey,
    };

    vtable: *const c.br_x509_class = &class,
    x509_minimal: c.br_x509_minimal_context,

    fn start_chain(ctx: [*c][*c]const c.br_x509_class, server_name: [*c]const u8) callconv(.C) void {
        const self = @fieldParentPtr(Self, "vtable", @ptrCast(**const c.br_x509_class, ctx));
        // std.debug.warn("start_chain({0}, {1})\n", .{
        //     ctx,
        //     std.mem.spanZ(server_name),
        // });
        self.x509_minimal.vtable.?.*.start_chain.?(&self.x509_minimal.vtable, server_name);
    }

    fn start_cert(ctx: [*c][*c]const c.br_x509_class, length: u32) callconv(.C) void {
        const self = @fieldParentPtr(Self, "vtable", @ptrCast(**const c.br_x509_class, ctx));
        // std.debug.warn("start_cert({0}, {1})\n", .{
        //     ctx,
        //     length,
        // });
        self.x509_minimal.vtable.?.*.start_cert.?(&self.x509_minimal.vtable, length);
    }

    fn append(ctx: [*c][*c]const c.br_x509_class, buf: [*c]const u8, len: usize) callconv(.C) void {
        const self = @fieldParentPtr(Self, "vtable", @ptrCast(**const c.br_x509_class, ctx));
        // std.debug.warn("append({0}, {1}, {2})\n", .{
        //     ctx,
        //     buf,
        //     len,
        // });
        self.x509_minimal.vtable.?.*.append.?(&self.x509_minimal.vtable, buf, len);
    }

    fn end_cert(ctx: [*c][*c]const c.br_x509_class) callconv(.C) void {
        const self = @fieldParentPtr(Self, "vtable", @ptrCast(**const c.br_x509_class, ctx));
        // std.debug.warn("end_cert({})\n", .{
        //     ctx,
        // });
        self.x509_minimal.vtable.?.*.end_cert.?(&self.x509_minimal.vtable);
    }

    fn end_chain(ctx: [*c][*c]const c.br_x509_class) callconv(.C) c_uint {
        const self = @fieldParentPtr(Self, "vtable", @ptrCast(**const c.br_x509_class, ctx));
        const err = self.x509_minimal.vtable.?.*.end_chain.?(&self.x509_minimal.vtable);
        // std.debug.warn("end_chain({}) → {}\n", .{
        //     ctx,
        //     err,
        // });
        if (err == c.BR_ERR_X509_NOT_TRUSTED) {
            // FUCK THIS!
            // TODO: This should'nt be done actually, but we can override the trust chain with this and just return the
            // pubkey anyways :D
            return 0;
        }

        return err;
    }

    fn get_pkey(ctx: [*c]const [*c]const c.br_x509_class, usages: [*c]c_uint) callconv(.C) [*c]const c.br_x509_pkey {
        const self = @fieldParentPtr(Self, "vtable", @ptrCast(*const *const c.br_x509_class, ctx));

        const pkey = self.x509_minimal.vtable.?.*.get_pkey.?(&self.x509_minimal.vtable, usages);
        // std.debug.warn("get_pkey({}, {}) → {}\n", .{
        //     ctx,
        //     usages,
        //     pkey,
        // });
        return pkey;
    }
};

pub const Client = struct {
    const Self = @This();

    client: c.br_ssl_client_context,
    x509_custom: CertificateValidator,
    iobuf: [c.BR_SSL_BUFSIZE_BIDI]u8,

    pub fn init(tac: TrustAnchorCollection) Self {
        var ctx = Self{
            .client = undefined,
            .x509_custom = .{
                .x509_minimal = undefined,
            },
            .iobuf = undefined,
        };
        c.br_ssl_client_init_full(&ctx.client, &ctx.x509_custom.x509_minimal, tac.items.ptr, tac.items.len);

        return ctx;
    }

    pub fn relocate(self: *Self) void {
        c.br_ssl_engine_set_x509(&self.client.eng, @ptrCast([*c][*c]const c.br_x509_class, &self.x509_custom.vtable));
        c.br_ssl_engine_set_buffer(&self.client.eng, &self.iobuf, self.iobuf.len, 1);
    }

    pub fn reset(self: *Self, host: [:0]const u8, resumeSession: bool) !void {
        const err = c.br_ssl_client_reset(&self.client, host, if (resumeSession) @as(c_int, 1) else 0);
        if (err < 0)
            return convertError(c.br_ssl_engine_last_error(&self.client.eng));
    }

    pub fn getEngine(self: *Self) *c.br_ssl_engine_context {
        return &self.client.eng;
    }
};

pub const Stream = struct {
    const Self = @This();

    engine: *c.br_ssl_engine_context,
    ioc: c.br_sslio_context,

    /// Initializes a new SSLStream backed by the ssl engine and file descriptor.
    pub fn init(engine: *c.br_ssl_engine_context, fd: std.os.fd_t) Self {
        var stream = Self{
            .engine = engine,
            .ioc = undefined,
        };

        const fd_as_ptr = @intToPtr(*c_void, @intCast(usize, fd));

        c.br_sslio_init(&stream.ioc, stream.engine, sockRead, fd_as_ptr, sockWrite, fd_as_ptr);
        return stream;
    }

    /// Closes the connection. Note that this may fail when the remote part does not terminate the SSL stream correctly.
    pub fn close(self: *Self) !void {
        if (c.br_sslio_close(&self.ioc) < 0)
            return convertError(c.br_ssl_engine_last_error(self.engine));
    }

    /// Flushes all pending data into the fd.
    pub fn flush(self: *Self) !void {
        if (c.br_sslio_flush(&self.ioc) < 0)
            return convertError(c.br_ssl_engine_last_error(self.engine));
    }

    /// low level read from fd to ssl library
    fn sockRead(ctx: ?*c_void, buf: [*c]u8, len: usize) callconv(.C) c_int {
        var fd = @intCast(std.os.fd_t, @ptrToInt(ctx));
        return if (std.os.read(fd, buf[0..len])) |num|
            @intCast(c_int, num)
        else |err|
            -1;
    }

    /// low level  write from ssl library to fd
    fn sockWrite(ctx: ?*c_void, buf: [*c]const u8, len: usize) callconv(.C) c_int {
        var fd = @intCast(std.os.fd_t, @ptrToInt(ctx));
        return if (std.os.write(fd, buf[0..len])) |num|
            @intCast(c_int, num)
        else |err|
            -1;
    }

    const ReadError = error{EndOfStream} || BearError;

    /// reads some data from the ssl stream.
    pub fn read(self: *Self, buffer: []u8) ReadError!usize {
        var result = c.br_sslio_read(&self.ioc, buffer.ptr, buffer.len);
        if (result < 0) {
            const errc = c.br_ssl_engine_last_error(self.engine);
            if (errc == c.BR_ERR_OK)
                return 0;
            return convertError(errc);
        }
        return @intCast(usize, result);
    }

    const WriteError = error{EndOfStream} || BearError;

    /// writes some data to the ssl stream.
    pub fn write(self: *Self, bytes: []const u8) WriteError!usize {
        var result = c.br_sslio_write(&self.ioc, bytes.ptr, bytes.len);
        if (result < 0) {
            const errc = c.br_ssl_engine_last_error(self.engine);
            if (errc == c.BR_ERR_OK)
                return 0;
            return convertError(errc);
        }
        return @intCast(usize, result);
    }

    pub const InStream = io.InStream(Self, ReadError, read);
    pub fn inStream(self: *Self) std.io.InStream(*Self, ReadError, read) {
        return .{ .context = self };
    }

    pub const OutStream = std.io.OutStream(*Self, WriteError, write);
    pub fn outStream(self: *Self) OutStream {
        return .{ .context = self };
    }
};

fn appendToBuffer(dest_ctx: ?*c_void, buf: ?*const c_void, len: usize) callconv(.C) void {
    var dest_buffer = @ptrCast(*std.ArrayList(u8), @alignCast(@alignOf(std.ArrayList(u8)), dest_ctx));
    // std.debug.warn("read chunk of {} bytes...\n", .{len});

    dest_buffer.appendSlice(@ptrCast([*]const u8, buf)[0..len]) catch |err| {
        std.debug.warn("failed to read chunk of {} bytes...\n", .{len});
    };
}

fn Vector(comptime T: type) type {
    return extern struct {
        buf: ?[*]T,
        ptr: usize,
        len: usize,
    };
}

fn convertToTrustAnchor(allocator: *std.mem.Allocator, cert: c.br_x509_certificate) !c.br_x509_trust_anchor {
    var dc: c.br_x509_decoder_context = undefined;

    var vdn = std.ArrayList(u8).init(allocator);
    defer vdn.deinit();

    c.br_x509_decoder_init(&dc, appendToBuffer, &vdn);
    c.br_x509_decoder_push(&dc, cert.data, cert.data_len);

    const private_key: *c.br_x509_pkey = if (@ptrCast(?*c.br_x509_pkey, c.br_x509_decoder_get_pkey(&dc))) |pk|
        pk
    else
        return convertError(c.br_x509_decoder_last_error(&dc));

    var ta = c.br_x509_trust_anchor{
        .dn = undefined,
        .flags = 0,
        .pkey = undefined,
    };

    if (c.br_x509_decoder_isCA(&dc) != 0) {
        ta.flags |= c.BR_X509_TA_CA;
    }

    switch (private_key.key_type) {
        c.BR_KEYTYPE_RSA => {
            var n = try std.mem.dupe(allocator, u8, private_key.key.rsa.n[0..private_key.key.rsa.nlen]);
            errdefer allocator.free(n);

            var e = try std.mem.dupe(allocator, u8, private_key.key.rsa.e[0..private_key.key.rsa.elen]);
            errdefer allocator.free(e);

            ta.pkey = .{
                .key_type = c.BR_KEYTYPE_RSA,
                .key = .{
                    .rsa = .{
                        .n = n.ptr,
                        .nlen = n.len,
                        .e = e.ptr,
                        .elen = e.len,
                    },
                },
            };
        },
        c.BR_KEYTYPE_EC => {
            var q = try std.mem.dupe(allocator, u8, private_key.key.ec.q[0..private_key.key.ec.qlen]);
            errdefer allocator.free(q);

            ta.pkey = .{
                .key_type = c.BR_KEYTYPE_EC,
                .key = .{
                    .ec = .{
                        .curve = private_key.key.ec.curve,
                        .q = q.ptr,
                        .qlen = q.len,
                    },
                },
            };
        },
        else => return error.UnsupportedKeyType,
    }

    errdefer switch (private_key.key_type) {
        c.BR_KEYTYPE_RSA => {
            allocator.free(ta.pkey.key.rsa.n[0..ta.pkey.key.rsa.nlen]);
            allocator.free(ta.pkey.key.rsa.e[0..ta.pkey.key.rsa.elen]);
        },
        c.BR_KEYTYPE_EC => allocator.free(ta.pkey.key.ec.q[0..ta.pkey.key.ec.qlen]),
        else => unreachable,
    };

    const dn = vdn.toOwnedSlice();
    ta.dn = .{
        .data = dn.ptr,
        .len = dn.len,
    };

    return ta;
}
