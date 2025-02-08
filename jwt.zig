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

const Key_cipr = struct {
    var ed: KeyPair = undefined;
    // var hmac: KeyPair = undefined;

};

pub const Token = struct {
    allocator: Allocator,
    payload: *const pl.Payload,
    header: *const head.Header,
    raw: ?[]const u8,
    signature: ?[64]u8,
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

    pub fn bytes(t: *Token) []const u8 {
        return t.raw.?;
    }

    pub fn setToken(t: *Token, token: []u8, sep1: usize, sep2: usize) void {
        t.raw = token;
        t.sep1 = sep1;
        t.sep2 = sep1 + 1 + sep2;
    }

    pub fn generateKeyPair(t: *Token) !KeyPair {
        _ = t;
        const kp = KeyPair.generate();
        return kp;
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
    pub fn signToken(t: *Token, comptime KeyType: type, key: ?KeyType) ![]const u8 {
        const sst = try t.signingString();
        var js = std.ArrayList(u8).init(t.allocator);
        defer js.deinit();

        switch (t.header.alg) {
            .EDDSA => {
                const writer = js.writer();
                var edd: eddsa.Eddsa = undefined;
                if (key) |k| {
                    comptime {
                        if (KeyType != std.crypto.sign.Ed25519.SecretKey) {
                            @compileError("KeyType must be eddsa.Eddsa.SecretKey");
                        }
                    }
                    edd = try eddsa.Eddsa.initFromSecretKey(k);
                } else {
                    edd = try eddsa.Eddsa.generateKeys();
                    Key_cipr.ed = edd.keyPaid;
                }

                const sig = try edd.sign(sst);
                const sigBytes = sig.toBytes();
                t.signature = sigBytes;

                const encodedLen = base64url.Encoder.calcSize(sigBytes.len);
                const sigDest = try t.allocator.alloc(u8, encodedLen);
                const encodedSig = base64url.Encoder.encode(sigDest, &sigBytes);
                try writer.writeAll(sst);
                try writer.writeByte('.');
                try writer.writeAll(encodedSig);
                const tokenRaw = try js.toOwnedSlice();
                t.raw = tokenRaw;
                return tokenRaw;
            },
            else => unreachable,
        }
    }
    //public key for eddsa

    pub fn verifyToken(t: *Token, comptime KeyType: type, key: ?KeyType) !bool {
        switch (t.header.alg) {
            .EDDSA => {
                const sst = t.beforeSignature();
                const signature = Signature.fromBytes(t.signature.?);

                var sig: bool = undefined;
                if (key) |k| {
                    // std.debug.print("triggered not null\n", .{});
                    sig = eddsa.Eddsa.verify(signature, sst, k);
                } else {
                    // std.debug.print("triggered null\n", .{});
                    sig = eddsa.Eddsa.verify(signature, sst, Key_cipr.ed.public_key);
                }
                return sig;
            },
            else => unreachable,
        }
    }
};
