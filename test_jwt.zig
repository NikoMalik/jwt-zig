const std = @import("std");
const head = @import("header.zig");
const typ = @import("algorithm.zig");
const p = @import("payload.zig");
const date = @import("time.zig");
const jwt = @import("jwt.zig");
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const assert = std.debug.assert;

test "JWT EDDSA test " {
    std.debug.print("eddsa\n", .{});
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
    defer jwtToken.deinit(false, false);

    const sigmaToken = try jwtToken.signToken(null);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{any}\n", .{verify});
    // alloc.free(sigmaToken);

    std.debug.print("{s}\n", .{sigmaToken});

    const key = try jwtToken.generateKeyPairEddsa();
    var keybyte = key.secret_key.toBytes();

    const sigmaToken2 = try jwtToken.signToken(&keybyte);
    var publikkey = key.public_key.toBytes();
    const verify_not_null = try jwtToken.verifyToken(&publikkey);
    std.debug.print("{any}\n", .{verify_not_null});
    std.debug.print("{s}\n", .{sigmaToken2});
    assert(verify);
}

test "jwt hs256 test" {
    std.debug.print("hs256\n", .{});
    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.HS256, .{});
    const iat = date.NumericDate.init(alloc, @as(u64, @intCast(std.time.timestamp())));
    const payload = p.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);
    defer jwtToken.deinit(false, false);

    const sigmaToken = try jwtToken.signToken(null);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt hs256 no null test" {
    std.debug.print("hs256|not null\n", .{});

    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.HS256, .{});
    const iat = date.NumericDate.init(alloc, @as(u64, @intCast(std.time.timestamp())));
    const payload = p.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);
    defer jwtToken.deinit(false, false);

    var hmacKey = try jwtToken.generateKeyPairHS256();

    const sigmaToken = try jwtToken.signToken(hmacKey[0..]);

    const verify = try jwtToken.verifyToken(hmacKey[0..]);

    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt hs384 not null test" {
    std.debug.print("hs384|not null\n", .{});

    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.HS384, .{});
    const iat = date.NumericDate.init(alloc, @as(u64, @intCast(std.time.timestamp())));
    const payload = p.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);
    defer jwtToken.deinit(false, false);

    var hmacKey = try jwtToken.generateKeyPairHS384();

    const sigmaToken = try jwtToken.signToken(hmacKey[0..]);
    const verify = try jwtToken.verifyToken(hmacKey[0..]);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt hs384 null test" {
    std.debug.print("hs384|null\n", .{});

    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.HS384, .{});

    const payload = p.Payload{
        .allocator = alloc,
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };
    var jwtToken = jwt.Token.init(alloc, &header, &payload);
    defer jwtToken.deinit(false, false);

    const sigmaToken = try jwtToken.signToken(null);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}
