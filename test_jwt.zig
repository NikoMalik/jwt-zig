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
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.EDDSA, .{});
    const iat = date.NumericDate.init(alloc.allocator(), @as(u64, @intCast(std.time.timestamp())));
    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    const sigmaToken = try jwtToken.signToken(null);
    defer alloc.allocator().free(sigmaToken);

    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{any}\n", .{verify});
    // alloc.free(sigmaToken);

    std.debug.print("{s}\n", .{sigmaToken});

    const key = try jwtToken.generateKeyPairEddsa();
    var keybyte = key.secret_key.toBytes();

    const sigmaToken2 = try jwtToken.signToken(keybyte[0..]);
    defer alloc.allocator().free(sigmaToken2);
    var publikkey = key.public_key.toBytes();
    const verify_not_null = try jwtToken.verifyToken(&publikkey);
    std.debug.print("{any}\n", .{verify_not_null});
    std.debug.print("{s}\n", .{sigmaToken2});
    assert(verify);
}

test "jwt hs256 test" {
    std.debug.print("hs256\n", .{});
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.HS256, .{});
    const iat = date.NumericDate.init(alloc.allocator(), @as(u64, @intCast(std.time.timestamp())));
    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    const sigmaToken = try jwtToken.signToken(null);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt hs256 no null test" {
    std.debug.print("hs256|not null\n", .{});

    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.HS256, .{});
    const iat = date.NumericDate.init(alloc.allocator(), @as(u64, @intCast(std.time.timestamp())));
    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    var hmacKey = try jwtToken.generateKeyPairHS256();

    const sigmaToken = try jwtToken.signToken(hmacKey[0..]);
    defer alloc.allocator().free(sigmaToken);

    const verify = try jwtToken.verifyToken(hmacKey[0..]);

    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt hs384 not null test" {
    std.debug.print("hs384|not null\n", .{});

    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.HS384, .{});
    const iat = date.NumericDate.init(alloc.allocator(), @as(u64, @intCast(std.time.timestamp())));
    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .iat = iat,
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    var hmacKey = try jwtToken.generateKeyPairHS384();

    const sigmaToken = try jwtToken.signToken(hmacKey[0..]);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(hmacKey[0..]);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt hs384 null test" {
    std.debug.print("hs384|null\n", .{});

    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.HS384, .{});

    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };
    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    const sigmaToken = try jwtToken.signToken(null);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt hs512 null test" {
    std.debug.print("hs512|null\n", .{});
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.HS512, .{});

    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    const sigmaToken = try jwtToken.signToken(null);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt hs512 not null test" {
    std.debug.print("hs512|not null\n", .{});
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.HS512, .{});

    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    var key = try jwtToken.generateKeyPairHS512();

    const sigmaToken = try jwtToken.signToken(key[0..]);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(key[0..]);

    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt es256 not null test" {
    std.debug.print("es256|not null\n", .{});

    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.ES256, .{});

    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    const key = try jwtToken.generateKeyPairEs256();
    var keyPrivate = key.secret_key.toBytes();
    var keyPublic = key.public_key.toUncompressedSec1();

    // const pem = try jwt.pemEncode(alloc, &keyPublic, "PUBLIC KEY");
    // defer alloc.free(pem);
    // const pem2 = try jwt.pemEncode(alloc, &keyPrivate, "PRIVATE KEY");
    // defer alloc.free(pem2);
    std.debug.print("privatekey={any}\n", .{keyPrivate});
    std.debug.print("publickey={any}\n", .{keyPublic});

    // std.debug.print("{s}\n", .{pem});
    // std.debug.print("{s}\n", .{pem2});

    const sigmaToken = try jwtToken.signToken(keyPrivate[0..]);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(keyPublic[0..]);

    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt es256 null test" {
    std.debug.print("es256|null\n", .{});
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.ES256, .{});

    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    const sigmaToken = try jwtToken.signToken(null);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt es384 null test" {
    std.debug.print("es384|null\n", .{});
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.ES384, .{});

    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    const sigmaToken = try jwtToken.signToken(null);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

// //
test "jwt es256 with pem test" {
    std.debug.print("es256|pem\n", .{});
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.ES256, .{});

    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    var privPem = try jwt.keyFromFile(alloc.allocator(), "private_key.pem");
    defer privPem.deinit();
    var publicPem = try jwt.keyFromFile(alloc.allocator(), "public_key.pem");
    defer publicPem.deinit();
    std.debug.print("privatelen={d}\n", .{privPem.value.bytes.len});
    std.debug.print("publiclen{d}\n", .{publicPem.value.bytes.len});

    var privateBytes: [32]u8 = undefined;
    @memcpy(&privateBytes, privPem.value.bytes);
    var publicBytes: [65]u8 = undefined;
    @memcpy(&publicBytes, publicPem.value.bytes);

    const sigmaToken = try jwtToken.signToken(privateBytes[0..]);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(publicBytes[0..]);

    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}
//
test "jwt es256 pem and sign" {
    std.debug.print("es256|pem\n", .{});
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.ES256, .{
        .kid = "kid",
    });

    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    var privPem = try jwt.keyFromFile(alloc.allocator(), "private_key.pem");
    defer privPem.deinit();
    var publicPem = try jwt.keyFromFile(alloc.allocator(), "public_key.pem");
    defer publicPem.deinit();
    std.debug.print("privatelen={d}\n", .{privPem.value.bytes.len});
    std.debug.print("publiclen{d}\n", .{publicPem.value.bytes.len});

    var privateBytes: [32]u8 = undefined;
    @memcpy(&privateBytes, privPem.value.bytes);
    var publicBytes: [65]u8 = undefined;
    @memcpy(&publicBytes, publicPem.value.bytes);

    try jwtToken.sign(privateBytes[0..]);
    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("{any}\n", .{verify});
    std.debug.print("{s}\n", .{jwtToken.raw.?});
    assert(verify);
}

const exm = struct {
    exp: u64,
};
test "jwt es256 pem and sign with custom payload" {
    std.debug.print("es256|pem\n", .{});
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.ES256, .{
        .kid = "kid",
    });

    const payload = p.CustomPayload(exm).init(alloc.allocator(), .{
        .exp = 1,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(alloc.allocator(), header, payload);
    defer jwtToken.deinit();

    var privPem = try jwt.keyFromFile(alloc.allocator(), "private_key.pem");
    defer privPem.deinit();
    var publicPem = try jwt.keyFromFile(alloc.allocator(), "public_key.pem");
    defer publicPem.deinit();
    std.debug.print("privatelen={d}\n", .{privPem.value.bytes.len});
    std.debug.print("publiclen{d}\n", .{publicPem.value.bytes.len});

    var privateBytes: [32]u8 = undefined;
    @memcpy(&privateBytes, privPem.value.bytes);
    var publicBytes: [65]u8 = undefined;
    @memcpy(&publicBytes, publicPem.value.bytes);

    try jwtToken.sign(privateBytes[0..]);
    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("{any}\n", .{verify});
    std.debug.print("{s}\n", .{jwtToken.raw.?});
    assert(verify);
}

test "jwt none test" {
    std.debug.print("none|null\n", .{});
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const leaks = alloc.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});
    const header = head.Header.init(alloc.allocator(), typ.Type.JWT, typ.Algorithm.none, .{});

    const payload = p.Payload{
        .allocator = alloc.allocator(),
        .jti = "sigma boy",
        .iss = "iss",
        .sub = "trump",
    };

    var jwtToken = jwt.Token(p.Payload).init(alloc.allocator(), header, payload);

    defer jwtToken.deinit();

    const sigmaToken = try jwtToken.signToken(null);
    defer alloc.allocator().free(sigmaToken);
    const verify = try jwtToken.verifyToken(null);
    std.debug.print("{s}\n", .{sigmaToken});
    std.debug.print("{any}\n", .{verify});
    // assert(verify);
}

test "jwt custom es384 test" {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.ES384, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 2,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    var privPem = try jwt.keyFromFile(allocator, "private_key_es384.pem"); //$ openssl ecparam -name secp384r1 -genkey -noout -out private_key_es384.pem

    defer privPem.deinit();
    var publicPem = try jwt.keyFromFile(allocator, "public_key_es384.pem"); //$ openssl ec -in private_key_es384.pem -pubout -out public_key_es384.pem

    defer publicPem.deinit();
    std.debug.print("privatelen={d}\n", .{privPem.value.bytes.len});
    std.debug.print("publiclen{d}\n", .{publicPem.value.bytes.len});

    var privateBytes: [48]u8 = undefined; // for es384 key private key is 48
    @memcpy(&privateBytes, privPem.value.bytes);
    var publicBytes: [97]u8 = undefined; // for es384 key public key is 97

    @memcpy(&publicBytes, publicPem.value.bytes);

    try jwtToken.sign(privateBytes[0..]);
    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("{any}\n", .{verify});
    std.debug.print("{s}\n", .{jwtToken.raw.?});
    assert(verify);
}
