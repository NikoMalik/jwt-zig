const std = @import("std");
const Allocator = std.mem.Allocator;
const pl = @import("payload.zig");
const head = @import("header.zig");
const eddsa = @import("eddsa.zig");
const base64url = std.base64.url_safe_no_pad;
const base64 = std.base64.standard;
const SecretKey = std.crypto.sign.Ed25519.SecretKey;
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Signature = std.crypto.sign.Ed25519.Signature;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const HS256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HS384 = std.crypto.auth.hmac.sha2.HmacSha384;
const HS512 = std.crypto.auth.hmac.sha2.HmacSha512;
const PS256 = std.crypto.Certificate.Algorithm.sha256WithRSAEncryption;
const PSS = std.crypto.Certificate.rsa;
const ES256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const ES384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const cricket = @import("cricket");

const Key_cipr = struct {
    var ed: KeyPair = undefined;
    var hs256: [HS256.key_length]u8 = undefined;
    var hs384: [HS384.key_length]u8 = undefined;
    var hs512: [HS512.key_length]u8 = undefined;
    var es256: ES256.KeyPair = undefined;
    var es384: ES384.KeyPair = undefined;
    // var es512: ES512.KeyPair = undefined;
};

//You can add only payload.CustomPayload or payload.Payload
pub fn Token(comptime Payload: type) type {
    return struct {
        allocator: Allocator,
        payload: Payload,
        header: head.Header,
        raw: ?[]u8,
        signature: ?[]u8,
        sep1: usize,
        sep2: usize,
        header_json: ?std.json.Parsed(head.Header),
        payload_json: ?std.json.Parsed(Payload),

        const Self = @This();

        pub fn init(allocator: Allocator, header: head.Header, payload: Payload) Self {
            return Self{
                .allocator = allocator,
                .header = header,
                .payload = payload,
                .raw = null,
                .signature = null,
                .sep1 = 0,
                .sep2 = 0,
                .header_json = null,
                .payload_json = null,
            };
        }

        pub fn allocParsed(allocator: Allocator, header: std.json.Parsed(head.Header), payload: std.json.Parsed(Payload)) Self {
            return Self{
                .allocator = allocator,
                .header = header.value,
                .payload = payload.value,
                .header_json = header,
                .payload_json = payload,
                .raw = null,
                .signature = null,
                .sep1 = 0,
                .sep2 = 0,
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.raw) |ptr| {
                self.allocator.free(ptr);
                self.raw = null;
            }
            if (self.signature) |ptr| {
                self.allocator.free(ptr);
                self.signature = null;
            }

            if (self.header_json) |ptr| {
                ptr.deinit();

                self.header_json = null;
            }
            if (self.payload_json != null) {
                self.payload_json.?.deinit();
                if (@hasDecl(@TypeOf(self.payload), "deinit")) {
                    self.payload.deinit();
                }
                self.payload_json = null;
            }
        }

        pub fn bytes(t: *Self) []const u8 {
            return t.raw.?;
        }

        pub fn setToken(t: *Self, token: []u8, sep1: usize, sep2: usize) void {
            t.raw = token;
            t.sep1 = sep1;
            t.sep2 = sep1 + 1 + sep2;
        }

        pub fn setSignature(t: *Self, signature: []u8) void {
            if (t.raw) |old_raw| {
                t.allocator.free(old_raw);
            }

            t.signature = signature;
        }

        pub fn generateKeyPairEddsa(t: *Self) !KeyPair {
            _ = t;
            const kp = KeyPair.generate();
            return kp;
        }
        pub fn generateKeyPairEs256(t: *Self) !ES256.KeyPair {
            _ = t;
            const kp = ES256.KeyPair.generate();
            return kp;
        }
        pub fn generateKeyPairEs384(t: *Self) !ES384.KeyPair {
            _ = t;
            const kp = ES384.KeyPair.generate();
            return kp;
        }
        pub fn generateKeyPairHS256(t: *Self) ![HS256.key_length]u8 {
            _ = t;
            var hmac: [HS256.key_length]u8 = undefined;
            std.crypto.random.bytes(&hmac);
            return hmac;
        }

        pub fn generateKeyPairHS512(t: *Self) ![HS512.key_length]u8 {
            _ = t;
            var hmac: [HS512.key_length]u8 = undefined;
            std.crypto.random.bytes(&hmac);
            return hmac;
        }

        pub fn generateKeyPairHS384(t: *Self) ![HS384.key_length]u8 {
            _ = t;
            var hmac: [HS384.key_length]u8 = undefined;
            std.crypto.random.bytes(&hmac);
            return hmac;
        }

        pub fn beforeSignature(t: *Self) []const u8 {
            return t.raw.?[0..t.sep2];
        }

        pub fn headerPart(t: *Self) []const u8 {
            return t.raw.?[0..t.sep1];
        }

        pub fn payloadPart(t: *Self) []const u8 {
            return t.raw[t.sep1 + 1 .. t.sep2];
        }

        pub fn signaturePart(t: *Self) []const u8 {
            return t.raw[t.sep2 + 1 ..];
        }

        inline fn signingString(t: *Self, js: *std.ArrayList(u8)) !void {
            var writer = js.writer();
            const header = try t.header.unmarshalHeader();
            defer t.header.free_Base64URL(header);
            try writer.writeAll(header);
            t.sep1 = writer.context.items.len;
            try writer.writeAll(".");
            const payload = try pl.unmarshalPaylod_custom((t.payload));

            defer t.allocator.free(payload);
            try writer.writeAll(payload);
            t.sep2 = writer.context.items.len;
        }

        //for EDDSA KEY IS PRIVATE KEY
        //FOR HMAC KEY IS KEY
        //Sign token gives you signed token which not free after deinit token
        pub fn signToken(t: *Self, key: ?[]u8) ![]const u8 {
            var js = std.ArrayList(u8).init(t.allocator);
            defer js.deinit();
            try t.signingString(&js);
            const sst = js.items;
            // js.clearRetainingCapacity();
            switch (t.header.alg) {
                .EDDSA => {
                    const writer = js.writer();
                    var edd: eddsa.Eddsa = undefined;
                    if (key) |k| {
                        if (k.len != std.crypto.sign.Ed25519.SecretKey.encoded_length) {
                            return error.InvalidKeySize;
                        }

                        edd = try eddsa.Eddsa.initFromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes(@as(*const [std.crypto.sign.Ed25519.SecretKey.encoded_length]u8, @ptrCast(k.ptr)).*));
                    } else {
                        edd = try eddsa.Eddsa.generateKeys();
                        Key_cipr.ed = edd.keyPaid;
                    }

                    const sig = try edd.sign(sst);
                    var sigBytes = sig.toBytes();
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &sigBytes);

                    const encodedLen = base64url.Encoder.calcSize(sigBytes.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &sigBytes);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);

                    return tokenRaw;
                },
                .HS256 => {
                    const writer = js.writer();
                    var hmac: [HS256.mac_length]u8 = undefined;

                    if (key) |k| {
                        if (k.len != std.crypto.auth.hmac.sha2.HmacSha256.key_length) {
                            return error.InvalidKeySize;
                        }
                        HS256.create(&hmac, sst, k);
                    } else {
                        var key_temp: [std.crypto.auth.hmac.sha2.HmacSha256.key_length]u8 = undefined;
                        std.crypto.random.bytes(&key_temp);
                        Key_cipr.hs256 = key_temp;
                        HS256.create(&hmac, sst, key_temp[0..]);
                    }
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &hmac);
                    // std.debug.print("hmac sign{any}\n", .{hmac});
                    // std.debug.print("signature{any}\n ", .{t.signature.?});
                    const encodedLen = base64url.Encoder.calcSize(hmac.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &hmac);

                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    return tokenRaw;
                },
                .HS384 => {
                    const writer = js.writer();
                    var hmac: [HS384.mac_length]u8 = undefined;
                    if (key) |k| {
                        if (k.len != HS384.key_length) {
                            return error.InvalidKeySize;
                        }
                        HS384.create(&hmac, sst, k);
                    } else {
                        var key_temp: [HS384.key_length]u8 = undefined;
                        std.crypto.random.bytes(&key_temp);
                        Key_cipr.hs384 = key_temp;
                        HS384.create(&hmac, sst, key_temp[0..]);
                    }
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &hmac);

                    const encodedLen = base64url.Encoder.calcSize(hmac.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &hmac);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    return tokenRaw;
                },
                .HS512 => {
                    const writer = js.writer();
                    var hmac: [HS512.mac_length]u8 = undefined;
                    if (key) |k| {
                        if (k.len != HS512.key_length) {
                            return error.InvalidKeySize;
                        }
                        HS512.create(&hmac, sst, k);
                    } else {
                        var key_temp: [HS512.key_length]u8 = undefined;
                        std.crypto.random.bytes(&key_temp);
                        Key_cipr.hs512 = key_temp;
                        HS512.create(&hmac, sst, key_temp[0..]);
                    }
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &hmac);
                    const encodedLen = base64url.Encoder.calcSize(hmac.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &hmac);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    return tokenRaw;
                },
                .ES256 => {
                    const writer = js.writer();
                    var es: ES256.KeyPair = undefined;
                    if (key) |k| {
                        if (k.len != ES256.SecretKey.encoded_length) {
                            return error.InvalidKeySize;
                        }
                        // var ktemp: [ES256.SecretKey.encoded_length]u8 = undefined;
                        // @memcpy(&ktemp, k);
                        es = try ES256.KeyPair.fromSecretKey(try ES256.SecretKey.fromBytes(@as(*const [ES256.SecretKey.encoded_length]u8, @ptrCast(k.ptr)).*));
                    } else {
                        es = try t.generateKeyPairEs256();
                        Key_cipr.es256 = es;
                    }
                    const sig = try es.sign(sst, null);
                    const sigBytes = sig.toBytes();
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &sigBytes);
                    const encodedLen = base64url.Encoder.calcSize(sigBytes.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &sigBytes);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    return tokenRaw;
                },
                .ES384 => {
                    const writer = js.writer();
                    var es: ES384.KeyPair = undefined;
                    if (key) |k| {
                        if (k.len != ES384.SecretKey.encoded_length) {
                            return error.InvalidKeySize;
                        }
                        es = try ES384.KeyPair.fromSecretKey(try ES384.SecretKey.fromBytes(@as(*const [ES384.SecretKey.encoded_length]u8, @ptrCast(k.ptr)).*));
                    } else {
                        es = try t.generateKeyPairEs384();
                        Key_cipr.es384 = es;
                    }
                    const sig = try es.sign(sst, null);
                    const sigBytes = sig.toBytes();
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &sigBytes);
                    const encodedLen = base64url.Encoder.calcSize(sigBytes.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &sigBytes);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }

                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    return tokenRaw;
                },
                .none => {
                    const writer = js.writer();
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = null;

                    try writer.writeByte('.');

                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    return tokenRaw;
                },

                else => unreachable,
            }
        }
        pub fn sign(t: *Self, key: ?[]u8) !void {
            var js = std.ArrayList(u8).init(t.allocator);
            defer js.deinit();
            try t.signingString(&js);
            const sst = js.items;
            // js.clearRetainingCapacity();
            switch (t.header.alg) {
                .EDDSA => {
                    const writer = js.writer();
                    var edd: eddsa.Eddsa = undefined;
                    if (key) |k| {
                        if (k.len != std.crypto.sign.Ed25519.SecretKey.encoded_length) {
                            return error.InvalidKeySize;
                        }
                        // const ktemp: [64]u8 = @ptrCast(@alignCast(k.ptr));
                        // @memcpy(&ktemp, k);
                        edd = try eddsa.Eddsa.initFromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes(@as(*const [std.crypto.sign.Ed25519.SecretKey.encoded_length]u8, @ptrCast(k.ptr)).*));
                    } else {
                        edd = try eddsa.Eddsa.generateKeys();
                        Key_cipr.ed = edd.keyPaid;
                    }

                    const sig = try edd.sign(sst);
                    var sigBytes = sig.toBytes();
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &sigBytes);

                    const encodedLen = base64url.Encoder.calcSize(sigBytes.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &sigBytes);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    defer t.allocator.free(tokenRaw);
                },
                .HS256 => {
                    const writer = js.writer();
                    var hmac: [HS256.mac_length]u8 = undefined;

                    if (key) |k| {
                        if (k.len != std.crypto.auth.hmac.sha2.HmacSha256.key_length) {
                            return error.InvalidKeySize;
                        }
                        HS256.create(&hmac, sst, k);
                    } else {
                        var key_temp: [std.crypto.auth.hmac.sha2.HmacSha256.key_length]u8 = undefined;
                        std.crypto.random.bytes(&key_temp);
                        Key_cipr.hs256 = key_temp;
                        HS256.create(&hmac, sst, key_temp[0..]);
                    }
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &hmac);
                    // std.debug.print("hmac sign{any}\n", .{hmac});
                    // std.debug.print("signature{any}\n ", .{t.signature.?});
                    const encodedLen = base64url.Encoder.calcSize(hmac.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &hmac);

                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    defer t.allocator.free(tokenRaw);
                },
                .HS384 => {
                    const writer = js.writer();
                    var hmac: [HS384.mac_length]u8 = undefined;
                    if (key) |k| {
                        if (k.len != HS384.key_length) {
                            return error.InvalidKeySize;
                        }
                        HS384.create(&hmac, sst, k);
                    } else {
                        var key_temp: [HS384.key_length]u8 = undefined;
                        std.crypto.random.bytes(&key_temp);
                        Key_cipr.hs384 = key_temp;
                        HS384.create(&hmac, sst, key_temp[0..]);
                    }
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &hmac);

                    const encodedLen = base64url.Encoder.calcSize(hmac.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &hmac);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    defer t.allocator.free(tokenRaw);
                },
                .HS512 => {
                    const writer = js.writer();
                    var hmac: [HS512.mac_length]u8 = undefined;
                    if (key) |k| {
                        if (k.len != HS512.key_length) {
                            return error.InvalidKeySize;
                        }
                        HS512.create(&hmac, sst, k);
                    } else {
                        var key_temp: [HS512.key_length]u8 = undefined;
                        std.crypto.random.bytes(&key_temp);
                        Key_cipr.hs512 = key_temp;
                        HS512.create(&hmac, sst, key_temp[0..]);
                    }
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &hmac);
                    const encodedLen = base64url.Encoder.calcSize(hmac.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &hmac);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    defer t.allocator.free(tokenRaw);
                },
                .ES256 => {
                    const writer = js.writer();
                    var es: ES256.KeyPair = undefined;
                    if (key) |k| {
                        if (k.len != ES256.SecretKey.encoded_length) {
                            return error.InvalidKeySize;
                        }
                        es = try ES256.KeyPair.fromSecretKey(try ES256.SecretKey.fromBytes(@as(*const [ES256.SecretKey.encoded_length]u8, @ptrCast(k.ptr)).*));
                    } else {
                        es = try t.generateKeyPairEs256();
                        Key_cipr.es256 = es;
                    }
                    const sig = try es.sign(sst, null);
                    const sigBytes = sig.toBytes();
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &sigBytes);
                    const encodedLen = base64url.Encoder.calcSize(sigBytes.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &sigBytes);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    defer t.allocator.free(tokenRaw);
                },
                .ES384 => {
                    const writer = js.writer();
                    var es: ES384.KeyPair = undefined;
                    if (key) |k| {
                        if (k.len != ES384.SecretKey.encoded_length) {
                            std.debug.print("triggered private len {d}\n", .{k.len});
                            std.debug.print("want this len: {d}\n", .{ES384.SecretKey.encoded_length});
                            return error.InvalidKeySize;
                        }
                        es = try ES384.KeyPair.fromSecretKey(try ES384.SecretKey.fromBytes(@as(*const [ES384.SecretKey.encoded_length]u8, @ptrCast(k.ptr)).*));
                    } else {
                        es = try t.generateKeyPairEs384();
                        Key_cipr.es384 = es;
                    }
                    const sig = try es.sign(sst, null);
                    const sigBytes = sig.toBytes();
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = try t.allocator.dupe(u8, &sigBytes);
                    const encodedLen = base64url.Encoder.calcSize(sigBytes.len);
                    const sigDest = try t.allocator.alloc(u8, encodedLen);
                    defer t.allocator.free(sigDest);
                    const encodedSig = base64url.Encoder.encode(sigDest, &sigBytes);
                    // try writer.writeAll(sst);
                    try writer.writeByte('.');
                    try writer.writeAll(encodedSig);
                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }

                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    defer t.allocator.free(tokenRaw);
                },
                .none => {
                    const writer = js.writer();
                    if (t.signature) |s| {
                        t.allocator.free(s);
                    }
                    t.signature = null;
                    try writer.writeByte('.');

                    const tokenRaw = try js.toOwnedSlice();
                    if (t.raw) |old_raw| {
                        t.allocator.free(old_raw);
                    }
                    t.raw = try t.allocator.dupe(u8, tokenRaw);
                    defer t.allocator.free(tokenRaw);
                },

                else => unreachable,
            }
        }

        pub fn verifyToken(t: *Self, key: ?[]u8) !bool {
            switch (t.header.alg) {
                .EDDSA => {
                    if (t.signature.?.len != std.crypto.sign.Ed25519.Signature.encoded_length) {
                        std.debug.print("triggered {d}\n", .{t.signature.?.len});
                        return error.InvalidSignatureLength;
                    }
                    const sst = t.beforeSignature();
                    const _signature_: *[std.crypto.sign.Ed25519.Signature.encoded_length]u8 = t.signature.?[0..std.crypto.sign.Ed25519.Signature.encoded_length];

                    const signature = Signature.fromBytes(_signature_.*);

                    var sig: bool = undefined;
                    if (key) |k| {
                        if (k.len != std.crypto.sign.Ed25519.PublicKey.encoded_length) {
                            return error.InvalidKeySize;
                        }
                        const pk = try std.crypto.sign.Ed25519.PublicKey.fromBytes(@as(*const [std.crypto.sign.Ed25519.PublicKey.encoded_length]u8, @ptrCast(k.ptr)).*);
                        sig = eddsa.Eddsa.verify(signature, sst, pk);
                    } else {
                        // std.debug.print("triggered null\n", .{});
                        sig = eddsa.Eddsa.verify(signature, sst, Key_cipr.ed.public_key);
                    }
                    return sig;
                },
                .HS256 => {
                    if (t.signature.?.len != HS256.mac_length) {
                        std.debug.print("signature len triggered {d}\n", .{t.signature.?.len});
                        return error.InvalidSignatureLength;
                    }
                    const sst = t.beforeSignature();
                    const signature: *[HS256.mac_length]u8 = t.signature.?[0..HS256.mac_length];
                    // defer t.allocator.free(t.signature.?);
                    var hmac: [HS256.mac_length]u8 = undefined;

                    if (key) |k| {
                        if (k.len != HS256.key_length) {
                            return error.InvalidKeySize;
                        }
                        HS256.create(&hmac, sst, k);
                    } else {
                        HS256.create(&hmac, sst, &Key_cipr.hs256);
                    }

                    return pl.constTimeEqual(signature, &hmac);
                },
                .HS384 => {
                    if (t.signature.?.len != HS384.mac_length) {
                        std.debug.print("triggered {d}\n", .{t.signature.?.len});
                        return error.InvalidSignatureLength;
                    }
                    const sst = t.beforeSignature();
                    const signature: *[HS384.mac_length]u8 = t.signature.?[0..HS384.mac_length];
                    var hmac: [HS384.mac_length]u8 = undefined;
                    if (key) |k| {
                        if (k.len != HS384.key_length) {
                            return error.InvalidKeySize;
                        }
                        HS384.create(&hmac, sst, k);
                    } else {
                        HS384.create(&hmac, sst, &Key_cipr.hs384);
                    }
                    return pl.constTimeEqual(signature, &hmac);
                },
                .HS512 => {
                    if (t.signature.?.len != HS512.mac_length) {
                        std.debug.print("triggered {d}\n", .{t.signature.?.len});
                        return error.InvalidSignatureLength;
                    }

                    const sst = t.beforeSignature();
                    const signature: *[HS512.mac_length]u8 = t.signature.?[0..HS512.mac_length];
                    var hmac: [HS512.mac_length]u8 = undefined;
                    if (key) |k| {
                        if (k.len != HS512.key_length) {
                            return error.InvalidKeySize;
                        }
                        HS512.create(&hmac, sst, k);
                    } else {
                        HS512.create(&hmac, sst, &Key_cipr.hs512);
                    }
                    return pl.constTimeEqual(signature, &hmac);
                },
                .ES256 => {
                    if (t.signature.?.len != ES256.Signature.encoded_length) {
                        std.debug.print("triggered {d}\n", .{t.signature.?.len});
                        return error.InvalidSignatureLength;
                    }
                    const sst = t.beforeSignature();
                    const _signature_: *[ES256.Signature.encoded_length]u8 = t.signature.?[0..ES256.Signature.encoded_length];
                    const signature = ES256.Signature.fromBytes(_signature_.*);
                    var sig: bool = undefined;

                    if (key) |k| {
                        switch (k.len) {
                            ES256.PublicKey.compressed_sec1_encoded_length => {
                                // var unsompressed: [32]u8 = undefined;
                                // @memcpy(&unsompressed, k);
                                const pk = try ES256.PublicKey.fromSec1(@as(*const [32]u8, @ptrCast(k.ptr)));
                                sig = verify(ES256.Signature, signature, sst, pk);
                            },
                            ES256.PublicKey.uncompressed_sec1_encoded_length => {
                                const pk = try ES256.PublicKey.fromSec1(@as(*const [65]u8, @ptrCast(k.ptr)));
                                sig = verify(ES256.Signature, signature, sst, pk);
                            },
                            else => return error.InvalidKeyLength,
                        }
                    } else {
                        sig = verify(ES256.Signature, signature, sst, Key_cipr.es256.public_key);
                    }
                    return sig;
                },
                .ES384 => {
                    if (t.signature.?.len != ES384.Signature.encoded_length) {
                        std.debug.print("triggered {d}\n", .{t.signature.?.len});
                        return error.InvalidSignatureLength;
                    }
                    const sst = t.beforeSignature();
                    const _signature_: *[ES384.Signature.encoded_length]u8 = t.signature.?[0..ES384.Signature.encoded_length];
                    const signature = ES384.Signature.fromBytes(_signature_.*);
                    var sig: bool = undefined;
                    if (key) |k| {
                        switch (k.len) {
                            ES384.PublicKey.compressed_sec1_encoded_length => {
                                const pk = try ES384.PublicKey.fromSec1(@as(*const [48]u8, @ptrCast(k.ptr)));
                                sig = verify(ES384.Signature, signature, sst, pk);
                            },
                            ES384.PublicKey.uncompressed_sec1_encoded_length => {
                                // var unsompressed: [65]u8 = undefined;
                                // @memcpy(&unsompressed, k);
                                const pk = try ES384.PublicKey.fromSec1(@as(*const [97]u8, @ptrCast(k.ptr)));
                                sig = verify(ES384.Signature, signature, sst, pk);
                            },
                            else => return error.InvalidKeyLength,
                        }
                    } else {
                        sig = verify(ES384.Signature, signature, sst, Key_cipr.es384.public_key);
                    }
                    return sig;
                },
                .none => {
                    if (t.signature != null and t.signature.?.len != 0) {
                        return error.InvalidSignature;
                    }

                    const raw = t.raw.?;
                    var iter = std.mem.splitScalar(u8, raw, '.');
                    _ = iter.first();
                    _ = iter.next() orelse return error.InvalidTokenFormat;

                    if (iter.next()) |sig_part| {
                        if (sig_part.len != 0) {
                            return error.InvalidSignature;
                        }
                    }

                    if (key != null) {
                        return error.UnexpectedKeyForNoneAlgorithm;
                    }

                    return true;
                },

                else => unreachable,
            }
        }
    };
}

inline fn verify(comptime SigType: type, sig: SigType, sst: []const u8, pk: anytype) bool {
    sig.verify(sst, pk) catch return false;
    return true;
}

pub fn keyFromFile(allocator: std.mem.Allocator, path: []const u8) !cricket.decode.Decoded {
    const f = try std.fs.cwd().openFile(path, .{});
    defer f.close();

    const key_contents = try f.readToEndAlloc(allocator, 10 * 1024 << 1);
    defer allocator.free(key_contents);

    return try cricket.decode.fromPem(allocator, key_contents);
}
