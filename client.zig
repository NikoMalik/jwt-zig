const std = @import("std");

pub const base64 = std.base64.url_safe_no_pad.Encoder;
pub const base64url = std.base64.url_safe_no_pad;

// Reusable client functions for JWKS workflows
pub const JwksClient = struct {
    pub fn extractKid(token: []const u8, allocator: std.mem.Allocator) !?[]const u8 {
        // Extract the header from JWT
        var iter = std.mem.splitSequence(u8, token, ".");
        const header_b64 = iter.first();

        // Decode header
        const header_decoded_size = base64url.Decoder.calcSizeForSlice(header_b64) catch 0;
        if (header_decoded_size == 0) return null;

        var header_buffer: [512]u8 = undefined;
        _ = try base64url.Decoder.decode(header_buffer[0..header_decoded_size], header_b64);

        // Parse JSON to get kid
        const header_json = try std.json.parseFromSlice(
            struct { kid: ?[]const u8 },
            allocator,
            header_buffer[0..header_decoded_size],
            .{ .ignore_unknown_fields = true },
        );
        defer header_json.deinit();

        // Duplicate the kid string since we're returning it
        if (header_json.value.kid) |kid| {
            return try allocator.dupe(u8, kid);
        }
        return null;
    }

    pub fn parseJwks(allocator: std.mem.Allocator, jwks_json: []const u8) !JWKS {
        const parsed = try std.json.parseFromSlice(JWKS, allocator, jwks_json, .{
            .ignore_unknown_fields = true,
        });
        defer parsed.deinit();

        // Return the JWKS structure
        var jwk_list = try allocator.alloc(JWK, parsed.value.keys.len);
        for (parsed.value.keys, 0..) |key, i| {
            jwk_list[i] = JWK{
                .kty = try allocator.dupe(u8, key.kty),
                .kid = try allocator.dupe(u8, key.kid),
                .use = try allocator.dupe(u8, key.use),
                .alg = try allocator.dupe(u8, key.alg),
                .n = try allocator.dupe(u8, key.n),
                .e = try allocator.dupe(u8, key.e),
            };
        }

        return JWKS{ .keys = jwk_list };
    }

    pub fn findKeyByKid(jwks: JWKS, kid: []const u8) ?JWK {
        for (jwks.keys) |jwk| {
            if (std.mem.eql(u8, jwk.kid, kid)) {
                return jwk;
            }
        }
        return null;
    }

    pub fn deinit(jwks: JWKS, allocator: std.mem.Allocator) void {
        for (jwks.keys) |jwk| {
            allocator.free(jwk.kty);
            allocator.free(jwk.kid);
            allocator.free(jwk.use);
            allocator.free(jwk.alg);
            allocator.free(jwk.n);
            allocator.free(jwk.e);
        }
        allocator.free(jwks.keys);
    }

    pub const JWK = struct {
        kty: []const u8,
        kid: []const u8,
        use: []const u8,
        alg: []const u8,
        n: []const u8,
        e: []const u8,
    };

    pub const JWKS = struct {
        keys: []JWK,
    };
};

// Helper functions
pub fn hexToBytes(allocator: std.mem.Allocator, hex_str: []const u8) ![]u8 {
    var bytes = try allocator.alloc(u8, hex_str.len / 2);
    errdefer allocator.free(bytes);

    var i: usize = 0;
    while (i < hex_str.len) : (i += 2) {
        const byte_hex = hex_str[i .. i + 2];
        bytes[i / 2] = try std.fmt.parseInt(u8, byte_hex, 16);
    }
    return bytes;
}

pub fn bytesToHex(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var hex = try allocator.alloc(u8, bytes.len * 2);
    errdefer allocator.free(hex);

    for (bytes, 0..) |byte, i| {
        _ = try std.fmt.bufPrint(hex[i * 2 .. i * 2 + 2], "{x:0>2}", .{byte});
    }
    return hex;
}

pub fn allocBase64Url(data: []const u8, allocator: std.mem.Allocator, encoded_len: usize) ![]u8 {
    const b64 = try allocator.alloc(u8, encoded_len);
    errdefer allocator.free(b64);
    _ = base64url.Encoder.encode(b64, data);
    return b64;
}

// Create JWKS JSON from RSA key parameters (n, e in hex format)
pub fn createJwksJson(n_hex: []const u8, e_hex: []const u8, kid: []const u8, alg: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    // Convert hex to bytes for base64 encoding
    const n_bytes = try hexToBytes(allocator, n_hex);
    defer allocator.free(n_bytes);
    const e_bytes = try hexToBytes(allocator, e_hex);
    defer allocator.free(e_bytes);

    // Create JWKS JSON structure
    const n_b64_len = base64url.Encoder.calcSize(n_bytes.len);
    const e_b64_len = base64url.Encoder.calcSize(e_bytes.len);

    const n_b64 = try allocBase64Url(n_bytes, allocator, n_b64_len);
    defer allocator.free(n_b64);
    const e_b64 = try allocBase64Url(e_bytes, allocator, e_b64_len);
    defer allocator.free(e_b64);

    // Build JWKS JSON
    var jwks_buf: [4096]u8 = undefined;
    var jwks_fbs = std.io.fixedBufferStream(&jwks_buf);
    const jwks_writer = jwks_fbs.writer();

    try jwks_writer.writeAll("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"");
    try jwks_writer.writeAll(kid);
    try jwks_writer.writeAll("\",\"use\":\"sig\",\"alg\":\"");
    try jwks_writer.writeAll(alg);
    try jwks_writer.writeAll("\",\"n\":\"");
    try jwks_writer.writeAll(n_b64);
    try jwks_writer.writeAll("\",\"e\":\"");
    try jwks_writer.writeAll(e_b64);
    try jwks_writer.writeAll("\"}]}");

    const jwks_json = jwks_fbs.getWritten();
    return try allocator.dupe(u8, jwks_json);
}
