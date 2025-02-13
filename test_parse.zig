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
const assert = std.debug.assert;

test "parse test" {
    std.debug.print("test parse eddsa", .{});
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

    _ = try jwtToken.signToken(null);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{any}\n", .{verify});

    const raw = jwtToken.raw.?;

    const signature = jwtToken.signature.?;

    var token = try parse.parseToken(alloc, raw, signature);
    defer token.deinit(true, true);

    std.debug.assert(token.raw != null);
    std.debug.assert(token.signature != null);

    // std.debug.print("Token: {any}\n", .{token});
    // defer token.deinit();

    std.debug.print("Token: raw = {s}, sep1 = {d}, sep2 = {d}\n", .{ token.raw.?, token.sep1, token.sep2 });
    // _ = try token.signToken(SecretKey, null);
    const verify_2 = try token.verifyToken(null);
    assert(verify_2);
    std.debug.print("Verify: {any}\n", .{verify_2});
    // std.debug.print("{any}\n", .{token});

    // std.debug.print("{s}\n", res);
}
//
test "parse hs256 test" {
    std.debug.print("test parse hs256", .{});
    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.HS256, .{});
    const iat = date.NumericDate.init(alloc, @as(u64, @intCast(std.time.timestamp())));
    const payload = pl.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);

    _ = try jwtToken.signToken(null);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{any}\n", .{verify});

    const raw = jwtToken.raw.?;

    const signature = jwtToken.signature.?;

    var token = try parse.parseToken(alloc, raw, signature);
    defer token.deinit(true, true);

    std.debug.print("TokenAlg: {s}\n", .{token.header.alg.string()});
    // token.deinit();

    std.debug.print("Token: raw = {s}, sep1 = {d}, sep2 = {d}\n", .{ token.raw.?, token.sep1, token.sep2 });
    // _ = try token.signToken(SecretKey, null);

    const verify_2 = try token.verifyToken(null);
    assert(verify_2);

    std.debug.print("Verify: {any}\n", .{verify_2});
    // std.debug.print("{any}\n", .{token});
}

test "parse hs256 test null" {
    std.debug.print("test parse hs256 null", .{});
    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.HS256, .{});
    const iat = date.NumericDate.init(alloc, @as(u64, @intCast(std.time.timestamp())));
    const payload = pl.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);

    _ = try jwtToken.signToken(null);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{any}\n", .{verify});

    const raw = jwtToken.raw.?;

    var token = try parse.parseToken(alloc, raw, null);
    defer token.deinit(true, true);
}

test "parse hs384 test null" {
    std.debug.print("test parse hs384 null", .{});
    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.HS384, .{});
    const iat = date.NumericDate.init(alloc, @as(u64, @intCast(std.time.timestamp())));
    const payload = pl.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);

    _ = try jwtToken.signToken(null);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{any}\n", .{verify});

    const raw = jwtToken.raw.?;

    var token = try parse.parseToken(alloc, raw, null);
    defer token.deinit(true, true);
}

test "parse hs384 not null " {
    std.debug.print("test parse h384 not null", .{});

    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.HS384, .{});
    const iat = date.NumericDate.init(alloc, @as(u64, @intCast(std.time.timestamp())));
    const payload = pl.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);

    _ = try jwtToken.signToken(null);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{any}\n", .{verify});

    const raw = jwtToken.raw.?;

    const signature = jwtToken.signature.?;

    var token = try parse.parseToken(alloc, raw, signature);
    defer token.deinit(true, true);

    std.debug.print("TokenAlg: {s}\n", .{token.header.alg.string()});

    const verify_2 = try token.verifyToken(null);

    std.debug.print("Verify: {any}\n", .{verify_2});
    assert(verify_2);
    assert(verify);
}
//
test "parse hs512 null " {
    std.debug.print("test parse hs512 not null", .{});

    const alloc = std.heap.page_allocator;
    const header = head.Header.init(alloc, typ.Type.JWT, typ.Algorithm.HS512, .{});

    const payload = pl.Payload{
        .allocator = alloc,
        .jti = "test_id",
        .sub = "subject",
    };

    var jwtToken = jwt.Token.init(alloc, &header, &payload);

    _ = try jwtToken.signToken(null);
    const raw = jwtToken.raw.?;

    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{any}\n", .{verify});

    var token = try parse.parseToken(alloc, raw, null);

    defer token.deinit(true, true);

    assert(verify);
}
