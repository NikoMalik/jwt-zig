const std = @import("std");
const pl = @import("payload.zig");
const head = @import("header.zig");
const eddsa = @import("eddsa.zig");
const date = @import("time.zig");
const jwt = @import("jwt.zig");
const parse = @import("parse.zig");
const typ = @import("algorithm.zig");
const SecretKey = std.crypto.sign.Ed25519.SecretKey;
const PublicKey = std.crypto.sign.Ed25519.PublicKey;

test "parse test" {
    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.EDDSA, .{});
    const iat = date.NumericDate.init(alloc, @as(u64, @intCast(std.time.timestamp())));
    const payload = pl.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);

    _ = try jwtToken.signToken(SecretKey, null);
    const verify = try jwtToken.verifyToken(PublicKey, null);
    std.debug.print("{any}\n", .{verify});

    const raw = jwtToken.raw.?;

    var token = try parse.parseToken(alloc, raw, jwtToken.signature.?);
    std.debug.print("Token: raw = {s}, sep1 = {d}, sep2 = {d}\n", .{ token.raw.?, token.sep1, token.sep2 });
    // _ = try token.signToken(SecretKey, null);
    const verify_2 = try token.verifyToken(PublicKey, null);
    std.debug.print("Verify: {any}\n", .{verify_2});
    // std.debug.print("{any}\n", .{token});

    // std.debug.print("{s}\n", res);
}
