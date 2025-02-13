const std = @import("std");
const Allocator = std.mem.Allocator;
const pl = @import("payload.zig");
const head = @import("header.zig");
const eddsa = @import("eddsa.zig");
const base64url = std.base64.url_safe_no_pad;
const SecretKey = std.crypto.sign.Ed25519.SecretKey;
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Signature = std.crypto.sign.Ed25519.Signature;
const KeyPair = std.crypto.sign.Ed25519.KeyPair;
const HS256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HS384 = std.crypto.auth.hmac.sha2.HmacSha384;

const Key_cipr = struct {
    var ed: KeyPair = undefined;
    var hs256: [HS256.key_length]u8 = undefined;
    var hs384: [HS384.key_length]u8 = undefined;
    // var hmac: KeyPair = undefined;

};

pub const Token = struct {
    allocator: Allocator,
    payload: *const pl.Payload,
    header: *const head.Header,
    raw: ?[]u8,
    signature: ?[]u8,
    sep1: usize,
    sep2: usize,

    pub fn init(allocator: Allocator, header: *const head.Header, payload: *const pl.Payload) Token {
        return Token{
            .allocator = allocator,
            .header = header,
            .payload = payload,
            .raw = null,
            .signature = null,
            .sep1 = 0,
            .sep2 = 0,
        };
    }

    //HEADER BOOL IS HEAP ALLOCATED TRUE OR FALSE?
    // PAYLOAD BOOL IS HEAP ALLOCATED TRUE OR FALSE?
    pub fn deinit(self: *Token, header: bool, payload: bool) void {
        if (self.raw) |ptr| {
            self.allocator.free(ptr);
            self.raw = null;
        }
        if (self.signature) |ptr| {
            self.allocator.free(ptr);
            self.signature = null;
        }
        if (header) {
            self.allocator.destroy(self.header);
        }
        if (payload) {
            self.allocator.destroy(self.payload);
        }
    }

    pub fn bytes(t: *Token) []const u8 {
        return t.raw.?;
    }

    pub fn setToken(t: *Token, token: []u8, sep1: usize, sep2: usize) void {
        t.raw = token;
        t.sep1 = sep1;
        t.sep2 = sep1 + 1 + sep2;
    }

    pub fn setSignature(t: *Token, signature: []u8) void {
        if (t.raw) |old_raw| {
            t.allocator.free(old_raw);
        }
        t.signature = signature;
    }

    pub fn generateKeyPairEddsa(t: *Token) !KeyPair {
        _ = t;
        const kp = KeyPair.generate();
        return kp;
    }
    pub fn generateKeyPairHS256(t: *Token) ![HS256.key_length]u8 {
        _ = t;
        var hmac: [HS256.key_length]u8 = undefined;
        std.crypto.random.bytes(&hmac);
        return hmac;
    }

    pub fn generateKeyPairHS384(t: *Token) ![HS384.key_length]u8 {
        _ = t;
        var hmac: [HS384.key_length]u8 = undefined;
        std.crypto.random.bytes(&hmac);
        return hmac;
    }

    pub fn beforeSignature(t: *Token) []const u8 {
        return t.raw.?[0..t.sep2];
    }

    pub fn headerPart(t: *Token) []const u8 {
        return t.raw.?[0..t.sep1];
    }

    pub fn payloadPart(t: *Token) []const u8 {
        return t.raw[t.sep1 + 1 .. t.sep2];
    }

    pub fn signaturePart(t: *Token) []const u8 {
        return t.raw[t.sep2 + 1 ..];
    }

    pub fn signingString(t: *Token) ![]const u8 {
        var js = std.ArrayList(u8).init(t.allocator);
        defer js.deinit();
        var writer = js.writer();
        const header = t.header.unmarshalHeader() catch "";
        defer t.header.free_Base64URL(header);
        try writer.writeAll(header);
        t.sep1 = writer.context.items.len;
        try writer.writeAll(".");
        const payload = t.payload.unmsarshalPayload() catch "";
        defer t.payload.free_base64url(payload);
        try writer.writeAll(payload);
        t.sep2 = writer.context.items.len;
        return js.toOwnedSlice();
    }

    //for EDDSA KEY IS PRIVATE KEY
    //FOR HMAC KEY IS KEY
    pub fn signToken(t: *Token, key: ?[]u8) ![]const u8 {
        const sst = try t.signingString();
        var js = std.ArrayList(u8).init(t.allocator);
        defer js.deinit();

        switch (t.header.alg) {
            .EDDSA => {
                const writer = js.writer();
                var edd: eddsa.Eddsa = undefined;
                if (key) |k| {
                    if (k.len != std.crypto.sign.Ed25519.SecretKey.encoded_length) {
                        return error.InvalidKeySize;
                    }
                    var ktemp: [64]u8 = undefined;
                    @memcpy(&ktemp, k);
                    edd = try eddsa.Eddsa.initFromSecretKey(try std.crypto.sign.Ed25519.SecretKey.fromBytes(ktemp));
                } else {
                    edd = try eddsa.Eddsa.generateKeys();
                    Key_cipr.ed = edd.keyPaid;
                }

                const sig = try edd.sign(sst);
                var sigBytes = sig.toBytes();
                t.signature = try t.allocator.dupe(u8, &sigBytes);

                const encodedLen = base64url.Encoder.calcSize(sigBytes.len);
                const sigDest = try t.allocator.alloc(u8, encodedLen);
                defer t.allocator.free(sigDest);
                const encodedSig = base64url.Encoder.encode(sigDest, &sigBytes);
                try writer.writeAll(sst);
                try writer.writeByte('.');
                try writer.writeAll(encodedSig);
                const tokenRaw = try js.toOwnedSlice();
                t.raw = try t.allocator.dupe(u8, tokenRaw);

                return tokenRaw;
            },
            .HS256 => {
                const writer = js.writer();
                var hmac: [HS256.mac_length]u8 = undefined;

                if (key) |k| {
                    HS256.create(&hmac, sst, k);
                } else {
                    var key_temp: [std.crypto.auth.hmac.sha2.HmacSha256.key_length]u8 = undefined;
                    std.crypto.random.bytes(&key_temp);
                    Key_cipr.hs256 = key_temp;
                    HS256.create(&hmac, sst, key_temp[0..]);
                }
                t.signature = try t.allocator.dupe(u8, &hmac);
                // std.debug.print("hmac sign{any}\n", .{hmac});
                // std.debug.print("signature{any}\n ", .{t.signature.?});
                const encodedLen = base64url.Encoder.calcSize(hmac.len);
                const sigDest = try t.allocator.alloc(u8, encodedLen);
                defer t.allocator.free(sigDest);
                const encodedSig = base64url.Encoder.encode(sigDest, &hmac);

                try writer.writeAll(sst);
                try writer.writeByte('.');
                try writer.writeAll(encodedSig);
                const tokenRaw = try js.toOwnedSlice();
                t.raw = try t.allocator.dupe(u8, tokenRaw);
                return tokenRaw;
            },
            .HS384 => {
                const writer = js.writer();
                var hmac: [HS384.mac_length]u8 = undefined;
                if (key) |k| {
                    HS384.create(&hmac, sst, k);
                } else {
                    var key_temp: [HS384.key_length]u8 = undefined;
                    std.crypto.random.bytes(&key_temp);
                    Key_cipr.hs384 = key_temp;
                    HS384.create(&hmac, sst, key_temp[0..]);
                }
                t.signature = try t.allocator.dupe(u8, &hmac);

                const encodedLen = base64url.Encoder.calcSize(hmac.len);
                const sigDest = try t.allocator.alloc(u8, encodedLen);
                defer t.allocator.free(sigDest);
                const encodedSig = base64url.Encoder.encode(sigDest, &hmac);
                try writer.writeAll(sst);
                try writer.writeByte('.');
                try writer.writeAll(encodedSig);
                const tokenRaw = try js.toOwnedSlice();
                t.raw = try t.allocator.dupe(u8, tokenRaw);
                return tokenRaw;
            },
            else => unreachable,
        }
    }
    //public key for eddsa

    pub fn verifyToken(t: *Token, key: ?[]u8) !bool {
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
                    // std.debug.print("triggered not null\n", .{});
                    var keytemp: [std.crypto.sign.Ed25519.PublicKey.encoded_length]u8 = undefined;
                    @memcpy(&keytemp, k);
                    const pk = try std.crypto.sign.Ed25519.PublicKey.fromBytes(keytemp);
                    sig = eddsa.Eddsa.verify(signature, sst, pk);
                } else {
                    // std.debug.print("triggered null\n", .{});
                    sig = eddsa.Eddsa.verify(signature, sst, Key_cipr.ed.public_key);
                }
                return sig;
            },
            .HS256 => {
                if (t.signature.?.len != HS256.mac_length) {
                    std.debug.print("triggered {d}\n", .{t.signature.?.len});
                    return error.InvalidSignatureLength;
                }
                const sst = t.beforeSignature();
                const signature: *[HS256.mac_length]u8 = t.signature.?[0..HS256.mac_length];
                // defer t.allocator.free(t.signature.?);
                var hmac: [HS256.mac_length]u8 = undefined;

                if (key) |k| {
                    HS256.create(&hmac, sst, k);
                } else {
                    HS256.create(&hmac, sst, &Key_cipr.hs256);
                }
                // std.debug.print("Computed HMAC: {any}\n", .{hmac});
                // std.debug.print("Signature from token: {any}\n", .{signature});

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
                    HS384.create(&hmac, sst, k);
                } else {
                    HS384.create(&hmac, sst, &Key_cipr.hs384);
                }
                return pl.constTimeEqual(signature, &hmac);
            },
            else => unreachable,
        }
    }
};
