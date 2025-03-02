const std = @import("std");
const head = @import("header.zig");
const typ = @import("algorithm.zig");
const p = @import("payload.zig");
const date = @import("time.zig");
const jwt = @import("jwt.zig");
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const assert = std.debug.assert;
const rr = @import("rsa.zig");

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
    std.log.debug("CUSTOM ES384 TESTING", .{});
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

test "jwt generate ps256" {
    std.log.debug("VALID GENERATE PS256 MUST BE OK", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.PS256, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 2,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    const ps256KeyPair = try jwtToken.generateKeyPairPS256();
    defer ps256KeyPair.deinit();
    ps256KeyPair.private.printKeyInfo();
    var buf: [2500]u8 = undefined;
    const signBytes = try ps256KeyPair.private.toBytes(&buf);
    // defer allocator.free(signBytes);
    // //
    const result = try jwtToken.signToken(signBytes[0..]);
    defer allocator.free(result);
    std.debug.print("{s}\n", .{result});
    const resPayload = try jwtToken.payload.marshalJSON_PAYLOAD();
    defer allocator.free(resPayload);
    std.debug.print("payload : {s}\n", .{resPayload});
    const public = try ps256KeyPair.private.publicKey();

    const publicBytes = try public.toBytes(&buf);

    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt generate invalid ps256" {
    std.log.debug("INVALID PS256 MUST BE FALSE", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.PS256, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 2,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    const ps256KeyPair = try jwtToken.generateKeyPairPS256();
    defer ps256KeyPair.deinit();
    ps256KeyPair.private.printKeyInfo();
    var buf: [2500]u8 = undefined;
    const signBytes = try ps256KeyPair.private.toBytes(&buf);
    // defer allocator.free(signBytes);
    // //
    const result = try jwtToken.signToken(signBytes[0..]);
    defer allocator.free(result);
    std.debug.print("{s}\n", .{result});
    const resPayload = try jwtToken.payload.marshalJSON_PAYLOAD();
    defer allocator.free(resPayload);
    std.debug.print("payload : {s}\n", .{resPayload});

    //and now create FAKE PUBLIC KEY
    //==============================
    var buf_fake: [2500]u8 = undefined;
    const fake_key_pair = try jwtToken.generateKeyPairPS256();
    defer fake_key_pair.deinit();
    const public_fake = try fake_key_pair.private.publicKey();
    const fake_bytes = try public_fake.toBytes(&buf_fake);

    const verify = try jwtToken.verifyToken(fake_bytes[0..]);
    std.debug.print("{any}\n", .{verify});
    assert(!verify);
}

test "jwt generate ps384" {
    std.debug.print("JWT GENERATE PS384 INVALID KEYS HASH\n", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.PS384, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 34,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    const ps256KeyPair = try jwtToken.generateKeyPairPS256();
    defer ps256KeyPair.deinit();
    ps256KeyPair.private.printKeyInfo();
    var buf: [2500]u8 = undefined;
    const signBytes = try ps256KeyPair.private.toBytes(&buf);
    try std.testing.expectError(error.BitsIncorrect, jwtToken.signToken(signBytes[0..]));
    const resPayload = try jwtToken.payload.marshalJSON_PAYLOAD();
    defer allocator.free(resPayload);
    std.debug.print("payload : {s}\n", .{resPayload});
}

test "jwt generate ps384 ok" {
    std.log.debug("VALID GENERATE PS384 MUST BE OK", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.PS384, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 384,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    const ps384KeyPair = try jwtToken.generateKeyPairPS384();
    defer ps384KeyPair.deinit();
    ps384KeyPair.private.printKeyInfo();
    var buf: [2500]u8 = undefined;
    const signBytes = try ps384KeyPair.private.toBytes(&buf);
    // defer allocator.free(signBytes);
    // //
    const result = try jwtToken.signToken(signBytes[0..]);
    defer allocator.free(result);
    std.debug.print("{s}\n", .{result});
    const resPayload = try jwtToken.payload.marshalJSON_PAYLOAD();
    defer allocator.free(resPayload);
    std.debug.print("payload : {s}\n", .{resPayload});
    const public = try ps384KeyPair.private.publicKey();

    const publicBytes = try public.toBytes(&buf);

    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt generate ps512 ok" {
    std.log.debug("VALID GENERATE PS512 MUST BE OK", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.PS512, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 512,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    const ps512KeyPair = try jwtToken.generateKeyPairPS512();
    defer ps512KeyPair.deinit();
    ps512KeyPair.private.printKeyInfo();
    var buf: [2500]u8 = undefined;
    const signBytes = try ps512KeyPair.private.toBytes(&buf);
    // defer allocator.free(signBytes);
    // //
    const result = try jwtToken.signToken(signBytes[0..]);
    defer allocator.free(result);
    std.debug.print("{s}\n", .{result});
    const resPayload = try jwtToken.payload.marshalJSON_PAYLOAD();
    defer allocator.free(resPayload);
    std.debug.print("payload : {s}\n", .{resPayload});
    const public = try ps512KeyPair.private.publicKey();

    const publicBytes = try public.toBytes(&buf);

    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt generate ps512 ok with pem" {
    std.log.debug("VALID GENERATE PS512 MUST BE OK with pem", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.PS512, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 512512521521,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    const pem = @embedFile("private_rsa.pem");
    const privKey = try rr.PS512.PrivateKey.fromPem_Der(pem);
    const ps256KeyPair = try rr.PS512.KeyPair.initFromSecret(privKey);
    defer ps256KeyPair.deinit();
    ps256KeyPair.private.printKeyInfo();
    var buf: [2500]u8 = undefined;
    const signBytes = try ps256KeyPair.private.toBytes(&buf);
    try jwtToken.sign(signBytes[0..]);
    const resPayload = try jwtToken.payload.marshalJSON_PAYLOAD();
    defer allocator.free(resPayload);
    std.debug.print("payload: {s}\n", .{resPayload});
    const public = try ps256KeyPair.private.publicKey();
    const publicBytes = try public.toBytes(&buf);
    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt generate rs512 ok with pem" {
    std.log.debug("VALID GENERATE rs512 MUST BE OK with pem", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.RS512, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 111111,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    const pem = @embedFile("private_rsa.pem");
    const privKey = try rr.RS512.PrivateKey.fromPem_Der(pem);
    const ps256KeyPair = try rr.RS512.KeyPair.initFromSecret(privKey);
    defer ps256KeyPair.deinit();
    ps256KeyPair.private.printKeyInfo();
    var buf: [2500]u8 = undefined;
    const signBytes = try ps256KeyPair.private.toBytes(&buf);
    try jwtToken.sign(signBytes[0..]);
    const resPayload = try jwtToken.payload.marshalJSON_PAYLOAD();
    defer allocator.free(resPayload);
    std.debug.print("payload: {s}\n", .{resPayload});
    const public = try ps256KeyPair.private.publicKey();
    const publicBytes = try public.toBytes(&buf);
    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt generate rs256" {
    std.log.debug("VALID GENERATE rs256 MUST BE OK", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.RS256, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 222222,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    const rs256KeyPair = try jwtToken.generateKeyPairRS256();
    defer rs256KeyPair.deinit();
    rs256KeyPair.private.printKeyInfo();
    var buf: [2500]u8 = undefined;
    const signBytes = try rs256KeyPair.private.toBytes(&buf);
    // defer allocator.free(signBytes);
    // //
    const result = try jwtToken.signToken(signBytes[0..]);
    defer allocator.free(result);
    std.debug.print("{s}\n", .{result});
    const resPayload = try jwtToken.payload.marshalJSON_PAYLOAD();
    defer allocator.free(resPayload);
    std.debug.print("payload : {s}\n", .{resPayload});
    const public = try rs256KeyPair.private.publicKey();

    const publicBytes = try public.toBytes(&buf);

    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("{any}\n", .{verify});
    assert(verify);
}

test "jwt generate invalid rs256" {
    std.log.debug("INVALID rs256 MUST BE FALSE", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const leaks = gpa.detectLeaks();
    std.debug.print("leaks={any}\n", .{leaks});

    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.RS256, .{ .cty = "jj" });

    const payload = p.CustomPayload(exm).init(allocator, .{
        .exp = 2,
    });

    var jwtToken = jwt.Token(p.CustomPayload(exm)).init(allocator, header, payload);
    defer jwtToken.deinit();

    const ps256KeyPair = try jwtToken.generateKeyPairRS256();
    defer ps256KeyPair.deinit();
    ps256KeyPair.private.printKeyInfo();
    var buf: [2500]u8 = undefined;
    const signBytes = try ps256KeyPair.private.toBytes(&buf);
    // defer allocator.free(signBytes);
    // //
    const result = try jwtToken.signToken(signBytes[0..]);
    defer allocator.free(result);
    std.debug.print("{s}\n", .{result});
    const resPayload = try jwtToken.payload.marshalJSON_PAYLOAD();
    defer allocator.free(resPayload);
    std.debug.print("payload : {s}\n", .{resPayload});

    //and now create FAKE PUBLIC KEY
    //==============================
    var buf_fake: [2500]u8 = undefined;
    const fake_key_pair = try jwtToken.generateKeyPairRS256();
    defer fake_key_pair.deinit();
    const public_fake = try fake_key_pair.private.publicKey();
    const fake_bytes = try public_fake.toBytes(&buf_fake);

    const verify = try jwtToken.verifyToken(fake_bytes[0..]);
    std.debug.print("{any}\n", .{verify});
    assert(!verify);
}
