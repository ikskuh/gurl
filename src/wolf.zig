const std = @import("std");

const c = @cImport({
    @cInclude("wolfssl/options.h");
    @cInclude("wolfssl/ssl.h");
});

fn printWolfError(ssl: *c.WOLFSSL) void {
    var buffer: [80]u8 = undefined;

    const err = @bitCast(c_uint, c.wolfSSL_get_error(ssl, 0));

    // std.debug.warn("{}\n", .{err});

    std.debug.assert(c.wolfSSL_ERR_error_string(err, &buffer) != null);
    std.debug.warn("ERROR: {}\n", .{
        std.mem.spanZ(&buffer),
    });
}

pub fn init() !void {
    if (c.wolfSSL_Init() != c.WOLFSSL_SUCCESS) {
        std.debug.warn("ERROR: Failed to initialize the wolf library\n", .{});
        return error.WolfError;
    }
}

pub fn deinit() void {
    _ = c.wolfSSL_Cleanup();
}

pub const Context = struct {
    const Self = @This();

    ctx: *c.WOLFSSL_CTX,

    pub fn init() !Self {
        var ctx: *c.WOLFSSL_CTX = if (c.wolfSSL_CTX_new(c.wolfTLSv1_2_client_method())) |_ctx|
            _ctx
        else {
            std.debug.warn("ERROR: failed to create WOLFSSL_CTX\n", .{});
            return error.WolfError;
        };
        return Self{
            .ctx = ctx,
        };
    }

    pub fn deinit(self: Self) void {
        _ = c.wolfSSL_CTX_free(self.ctx);
    }

    pub fn loadVerifyLocations(self: Self, pem_file: [:0]const u8) !void {
        if (c.wolfSSL_CTX_load_verify_locations(self.ctx, pem_file, null) != c.SSL_SUCCESS) {
            std.debug.warn("ERROR: failed to load {}, please check the file!\n", .{pem_file});
            return error.WolfError;
        }
    }
};

pub const Connection = struct {
    const Self = @This();

    ssl: *c.WOLFSSL,

    pub fn initFromFd(ctx: Context, fd: std.os.fd_t) !Self {
        const ssl: *c.WOLFSSL = if (c.wolfSSL_new(ctx.ctx)) |_ssl|
            _ssl
        else {
            std.debug.warn("ERROR: failed to create WOLFSSL object\n", .{});
            return error.WolfError;
        };
        errdefer c.wolfSSL_free(ssl);

        if (c.wolfSSL_set_fd(ssl, fd) != c.WOLFSSL_SUCCESS) {
            std.debug.warn("ERROR: Failed to set the file descriptor\n", .{});
            printWolfError(ssl);
            return error.WolfError;
        }

        return Self{
            .ssl = ssl,
        };
    }

    pub fn close(self: Self) void {
        c.wolfSSL_free(self.ssl);
    }

    pub fn connect(self: Self) !void {
        var err = c.wolfSSL_connect(self.ssl);
        if (err != c.SSL_SUCCESS) {
            std.debug.warn("ERROR: failed to connect to wolfSSL: {}\n", .{err});
            printWolfError(self.ssl);
            return error.WolfError;
        }
    }

    const ReadError = error{WolfError};
    pub fn read(self: Self, buffer: []u8) ReadError!usize {
        var result = c.wolfSSL_read(self.ssl, buffer.ptr, @intCast(c_int, buffer.len));
        if (result <= 0) {
            std.debug.warn("ERROR: failed to read from wolfSSL: {}\n", .{result});
            printWolfError(self.ssl);
            return error.WolfError;
        }
        return @intCast(usize, result);
    }

    const WriteError = error{WolfError};
    pub fn write(self: Self, bytes: []const u8) WriteError!usize {
        var result = c.wolfSSL_write(self.ssl, bytes.ptr, @intCast(c_int, bytes.len));
        if (result <= 0) {
            std.debug.warn("ERROR: failed to write to wolfSSL: {}\n", .{result});
            printWolfError(self.ssl);
            return error.WolfError;
        }
        return @intCast(usize, result);
    }

    pub const InStream = io.InStream(Self, ReadError, read);
    pub fn inStream(self: Self) std.io.InStream(Self, ReadError, read) {
        return .{ .context = self };
    }

    pub const OutStream = std.io.OutStream(Self, WriteError, write);
    pub fn outStream(self: Self) OutStream {
        return .{ .context = self };
    }
};
