const std = @import("std");
const head = @import("header.zig");
const typ = @import("algorithm.zig");
const p = @import("payload.zig");
const date = @import("time.zig");
const jwt = @import("jwt.zig");
const PublicKey = std.crypto.sign.Ed25519.PublicKey;

test "JWT EDDSA test " {
    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.EDDSA, .{});
    const iat = date.NumericDate.init(alloc, @as(u64, @intCast(std.time.timestamp())));
    const payload = p.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);

    const sigmaToken = try jwtToken.signToken(std.crypto.sign.Ed25519.SecretKey, null);
    const verify = try jwtToken.verifyToken(PublicKey, null);
    std.debug.print("{any}\n", .{verify});
    // alloc.free(sigmaToken);

    std.debug.print("{s}\n", .{sigmaToken});

    const key = try jwtToken.generateKeyPair();

    const sigmaToken2 = try jwtToken.signToken(std.crypto.sign.Ed25519.SecretKey, key.secret_key);
    const verify_not_null = try jwtToken.verifyToken(PublicKey, key.public_key);
    std.debug.print("{any}\n", .{verify_not_null});
    std.debug.print("{s}\n", .{sigmaToken2});
}
