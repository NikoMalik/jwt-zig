const std = @import("std");
const assert = std.debug.assert;
const crypto = std.crypto;
const fmt = std.fmt;
const testing = std.testing;
const pl = @import("payload.zig");

const cwd = std.fs.cwd();

const ssl = @cImport({
    @cDefine("__FILE__", "\"rsa.zig\"");
    @cDefine("__LINE__", "0");

    @cDefine("OPENSSL_API_COMPAT", "10100");
    @cInclude("openssl/sha.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/crypto.h");
    @cInclude("openssl/err.h");
    @cInclude("openssl/bio.h");
});

pub const PS256 = RSAAlgorithm(2048, .RSA_PSS, .sha256);
pub const PS384 = RSAAlgorithm(3072, .RSA_PSS, .sha384);
pub const PS512 = RSAAlgorithm(4096, .RSA_PSS, .sha512);

pub const RS256 = RSAAlgorithm(2048, .RSASSA_PKCS1_v1_5, .sha256);
pub const RS384 = RSAAlgorithm(3072, .RSASSA_PKCS1_v1_5, .sha384);
pub const RS512 = RSAAlgorithm(4096, .RSASSA_PKCS1_v1_5, .sha512);

const BN_CTX = ssl.BN_CTX;
const BN_MONT_CTX = ssl.BN_MONT_CTX;

//hash fn
//=======
const EVP_MD = ssl.EVP_MD;

//ctx-algo
//===
const EVP_MD_CTX = ssl.EVP_MD_CTX;

//rsa struct
//=========
const RSA = ssl.RSA;

//bignum
//======
const BIGNUM = ssl.BIGNUM;

//openssl key
//==========
const EVP_PKEY = ssl.EVP_PKEY;

//help tools all inspired by one genius  (jedisct1)
//====================================
fn sslTry(ret: c_int) !void {
    if (ret != 1) return error.InternalError;
}

fn sslNegTry(ret: c_int) !void {
    if (ret < 0) return error.InternalError;
}

fn sslNTry(comptime T: type, ret: ?*T) !void {
    if (ret == null) return error.InternalError;
}

fn sslAlloc(comptime T: type, ret: ?*T) !*T {
    return ret orelse error.OutOfMemory;
}

// Convert BIGNUM to padded binary format
//=======================================
fn bn2binPadded_deprecated(out: [*c]u8, out_len: usize, in: *const BIGNUM) c_int {
    if (ssl.BN_bn2binpad(in, out, @as(c_int, @intCast(out_len))) == out_len) {
        return 1;
    }
    return 0;
}

fn bn2binPadded(in: *const BIGNUM, out: [*c]u8, out_len: usize) c_int {
    if (ssl.BN_bn2binpad(in, out, @as(c_int, @intCast(out_len))) == out_len) {
        return 1;
    }
    return 0;
}

// Extract RSA key reference from EVP_PKEY
//=======================================
fn rsaRef(evp_pkey: *const EVP_PKEY) *RSA {
    return @constCast(ssl.EVP_PKEY_get0_RSA(evp_pkey).?);
}

// Get RSA key bit size
//=====================
fn rsaBits(evp_pkey: *const EVP_PKEY) c_int {
    return @intCast(ssl.RSA_bits(rsaRef(evp_pkey)));
}

// Get RSA key size in bytes
//==========================
fn rsaSize(evp_pkey: *const EVP_PKEY) usize {
    return @as(usize, @intCast(ssl.RSA_size(rsaRef(evp_pkey))));
}

// Convert signed integer to usize
//================================
inline fn rsaSint_to(c: c_long) usize {
    return @as(usize, @intCast(c));
}

fn rsaParam(param: enum { n, e, p, q, d }, evp_pkey: *const EVP_PKEY) *const BIGNUM {
    switch (param) {
        .n => return ssl.RSA_get0_n(rsaRef(evp_pkey)).?,
        .e => return ssl.RSA_get0_e(rsaRef(evp_pkey)).?,
        .p => return ssl.RSA_get0_p(rsaRef(evp_pkey)).?,
        .q => return ssl.RSA_get0_q(rsaRef(evp_pkey)).?,
        .d => return ssl.RSA_get0_d(rsaRef(evp_pkey)).?,
    }
}

// Duplicate an RSA key
//=====================
fn rsaDup(evp_pkey: *const EVP_PKEY) !*EVP_PKEY {
    const evp_pkey_: ?*EVP_PKEY = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    try sslTry(ssl.EVP_PKEY_copy_parameters(evp_pkey_, evp_pkey));
    return evp_pkey_.?;
}

pub const Padding = union(enum) {
    RSASSA_PKCS1_v1_5: void,
    RSA_PSS: void,
};

const Error = error{
    ContextCreationFailed,
    SignInitFailed,
    VerifyInitFailed,
    SetPaddingFailed,
    SetSaltLenFailed,
    SignSizeFailed,
    BufferTooSmall,
    SignFailed,
    VerifyFailed,
    BitsIncorrect,
    InputTooLarge,
    @"256",
    @"384",
    @"512",
};

// Hash function parameters
//=========================
const HashParams = struct {
    const sha256 = .{
        .evp_fn = ssl.EVP_sha256,
        .salt_length = 32,
    };
    const sha384 = .{
        .evp_fn = ssl.EVP_sha384,
        .salt_length = 48,
    };
    const sha512 = .{
        .evp_fn = ssl.EVP_sha512,
        .salt_length = 64,
    };
};

// Load private key from file
//===========================
pub fn loadPrivateKey(path: []const u8) !*EVP_PKEY {
    const file = try cwd.openFile(path, .{});
    defer file.close();

    const bio = ssl.BIO_new_fp(file.handle, ssl.BIO_NOCLOSE);
    if (bio == null) return error.BioCreationFailed;

    const pkey = ssl.PEM_read_bio_PrivateKey(bio, null, null, null);
    if (pkey == null) return error.KeyLoadFailed;

    return pkey;
}

// // CREATE NEW CONTEXT FOR MN WITH BN_CTX
// // ====================================
fn newMont_ctx(n: *const BIGNUM) !*BN_MONT_CTX {
    const mont_ctx = try sslAlloc(BN_MONT_CTX, ssl.BN_MONT_CTX_new());
    errdefer ssl.BN_MONT_CTX_free(mont_ctx);
    const bn_ctx: *BN_CTX = try sslAlloc(BN_CTX, ssl.BN_CTX_new());
    ssl.BN_CTX_start(bn_ctx);
    defer {
        ssl.BN_CTX_end(bn_ctx);
        ssl.BN_CTX_free(bn_ctx);
    }
    try sslTry(ssl.BN_MONT_CTX_set(mont_ctx, n, bn_ctx));
    return mont_ctx;
}

// Export private key to memory
//=============================
fn exportPrivateKey(pkey: *ssl.EVP_PKEY, allocator: std.mem.Allocator) ![]u8 {
    const bio = ssl.BIO_new(ssl.BIO_s_mem()) orelse return error.BioCreationFailed;
    defer _ = ssl.BIO_free(bio);

    if (ssl.PEM_write_bio_PrivateKey(bio, pkey, null, null, 0, null, null) != 1)
        return error.WriteFailed;

    var data_ptr: [*c]u8 = undefined;
    const len = ssl.BIO_get_mem_data(bio, &data_ptr);
    const size = rsaSint_to(len);
    const result = try allocator.alloc(u8, size);
    @memcpy(result, data_ptr[0..size]);
    return result;
}

fn printOpensslError() void {
    const err = ssl.ERR_get_error();
    if (err != 0) {
        std.debug.print("OpenSSL error: {s}\n", .{ssl.ERR_error_string(err, null)});
    }
}

fn sha256Digest(msg: []const u8) [32]u8 {
    var hasher = crypto.hash.sha2.Sha256.init(.{});
    hasher.update(msg);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn deleteFile(path: []const u8) !void {
    try cwd.deleteFile(path);
}

fn bnConstantTimeEqual(a: *const BIGNUM, b: *const BIGNUM) bool {
    const max_size = 512;
    var buf_a: [max_size]u8 = undefined;
    var buf_b: [max_size]u8 = undefined;

    const bits_a = ssl.BN_num_bits(a);
    const bits_b = ssl.BN_num_bits(b);
    if (constantTimeU32Eq(@as(u32, @intCast(bits_a)), @as(u32, @intCast(bits_b))) != 1) {
        return false;
    }

    if (ssl.BN_bn2binpad(a, &buf_a, max_size) != max_size) return false;
    if (ssl.BN_bn2binpad(b, &buf_b, max_size) != max_size) return false;

    return pl.constTimeEqual(&buf_a, &buf_b);
}

fn constantTimeU32Eq(a: u32, b: u32) u32 {
    var c = ~(a ^ b);
    c &= c >> 16;
    c &= c >> 8;
    c &= c >> 4;
    c &= c >> 2;
    c &= c >> 1;
    return @as(u32, @intFromBool((c & 1) != 0));
}

fn constructPublicKey(n: *BIGNUM, e: *BIGNUM) !RSAAlgorithm(2048, .RSA_PSS, .sha256).PublicKey {
    const rsa_pub = ssl.RSA_new() orelse return error.MemoryAllocation;
    if (ssl.RSA_set0_key(rsa_pub, n, e, null) != 1) {
        ssl.RSA_free(rsa_pub);

        return error.KeySetupFailed;
    }

    const pubkey = ssl.EVP_PKEY_new() orelse {
        ssl.RSA_free(rsa_pub);
        return error.MemoryAllocation;
    };

    if (ssl.EVP_PKEY_assign(pubkey, ssl.EVP_PKEY_RSA, rsa_pub) != 1) {
        ssl.RSA_free(rsa_pub);

        ssl.EVP_PKEY_free(pubkey);

        return error.KeyAssignmentFailed;
    }

    const mont_ctx = try newMont_ctx(n);
    return .{ .key = pubkey, .mont_ctx = mont_ctx };
}

fn hexToBignum(hex: []const u8) !*BIGNUM {
    var bn: ?*BIGNUM = null;
    _ = ssl.BN_hex2bn(&bn, hex.ptr);
    return bn orelse error.BNConversionFailed;
}

fn intToHex(num: i32) ![]const u8 {
    return switch (num) {
        65537 => "010001",
        else => return error.UnsupportedExponent,
    };
}

fn loadKnownBIGNUM(path: []const u8) !*BIGNUM {
    const data = try cwd.readFileAlloc(std.testing.allocator, path, 4096);
    defer std.testing.allocator.free(data);

    const bn = ssl.BN_bin2bn(data.ptr, @intCast(data.len), null);
    return bn orelse error.InvalidData;
}

//=======================================================================

pub fn RSAAlgorithm(comptime modulus_bits: u16, comptime padding: Padding, comptime hash_fn: enum { sha256, sha384, sha512 }) type {
    assert(modulus_bits >= 2048 and modulus_bits <= 4096);
    const Hash = switch (hash_fn) {
        .sha256 => HashParams.sha256,

        .sha384 => HashParams.sha384,
        .sha512 => HashParams.sha512,
    };

    return struct {
        const Self = @This();
        pub const modulus_bytes = (modulus_bits + 7) / 8;
        pub const bits = modulus_bits;

        pub const Secret = [modulus_bytes]u8;
        pub const Signature = [modulus_bytes]u8;
        pub const Noise = [32]u8;

        pub fn generateKeyPair() !KeyPair {
            const private = try generateKey();
            const public = try private.publicKey();
            return .{
                .private = private,
                .public = public,
            };
        }

        pub fn printSaltLenght() void {
            std.log.info("salt_len : {d}", .{Hash.salt_length});
        }

        inline fn actualSize() !void {
            const actual_hash_len = @as(usize, @intCast(ssl.EVP_MD_size(Hash.evp_fn())));
            // std.debug.print("Hash size : {d}", .{actual_hash_len});
            if (actual_hash_len != Hash.salt_length) {
                std.log.err("Invalid hash size: expected {d}, got {d}", .{ Hash.salt_length, actual_hash_len });
                return error.InvalidHashSize;
            }
        }

        pub const KeyPair = struct {
            private: PrivateKey,
            public: PublicKey,

            pub fn deinit(self: KeyPair) void {
                self.private.deinit();
                self.public.deinit();
            }

            pub fn initFromSecret(private_key: PrivateKey) !KeyPair {
                return .{
                    .private = private_key,
                    .public = try private_key.publicKey(),
                };
            }
        };

        pub const PublicKey = struct {
            key: *ssl.EVP_PKEY,
            mont_ctx: *ssl.BN_MONT_CTX,

            pub fn deinit(self: PublicKey) void {
                ssl.EVP_PKEY_free(self.key);
                ssl.BN_MONT_CTX_free(self.mont_ctx);
            }

            pub fn toBytes(self: PublicKey, out: []u8) ![]u8 {
                var buf: [*c]u8 = null;
                const len = ssl.i2d_PublicKey(self.key, &buf);
                if (len <= 0 or len >= out.len) return error.SerializationFailed;
                try sslNTry(u8, buf);

                @memcpy(out[0..@intCast(len)], @as([*]const u8, @ptrCast(buf.?))[0..@intCast(len)]);

                return out[0..@as(usize, @intCast(len))];
            }

            pub fn fromBytes(raw: []u8) !PublicKey {
                const max_len = 1000;
                if (raw.len >= max_len) {
                    return error.InputTooLarge;
                }

                var key: ?*EVP_PKEY = null;
                var der_ptr: [*c]const u8 = raw.ptr;
                try sslNTry(EVP_PKEY, ssl.d2i_PublicKey(ssl.EVP_PKEY_RSA, &key, &der_ptr, @as(c_long, @intCast(raw.len))));
                const evp_key = key.?;
                errdefer ssl.EVP_PKEY_free(evp_key);
                if (rsaBits(evp_key) != modulus_bits) {
                    return error.BitsIncorrect;
                }

                const e3: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(e3);
                try sslTry(ssl.BN_set_word(e3, ssl.RSA_3));
                const ef4: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
                defer ssl.BN_free(ef4);
                try sslTry(ssl.BN_set_word(ef4, ssl.RSA_F4));
                if (!bnConstantTimeEqual(e3, rsaParam(.e, evp_key)) and !bnConstantTimeEqual(ef4, rsaParam(.e, evp_key))) {
                    return error.UnexpectedCheck;
                }
                const mont_ctx = try newMont_ctx(rsaParam(.n, evp_key));
                return .{
                    .key = evp_key,
                    .mont_ctx = mont_ctx,
                };
            }
        };

        pub const PrivateKey = struct {
            key: *ssl.EVP_PKEY,

            pub fn deinit(self: PrivateKey) void {
                ssl.EVP_PKEY_free(self.key);
            }

            pub fn toBytes(self: PrivateKey, out: []u8) ![]u8 {
                var buf: [*c]u8 = null;
                defer ssl.OPENSSL_free(buf);

                const len = ssl.i2d_PrivateKey(self.key, &buf);
                if (len <= 0) {
                    return error.SerializationFailed;
                }
                try actualSize();
                try sslNTry(u8, buf);

                @memcpy(out[0..@intCast(len)], @as([*]const u8, @ptrCast(buf.?))[0..@intCast(len)]);

                return out[0..@as(usize, @intCast(len))];
            }

            pub fn fromBytes(raw: []const u8) !PrivateKey {
                try actualSize();
                var key: ?*EVP_PKEY = null;
                var der_ptr: [*c]const u8 = raw.ptr;
                try sslNTry(EVP_PKEY, ssl.d2i_PrivateKey(ssl.EVP_PKEY_RSA, &key, &der_ptr, @as(c_long, @intCast(raw.len))));
                errdefer ssl.EVP_PKEY_free(key);
                if (rsaBits(key.?) != modulus_bits) {
                    return error.BitsIncorrect;
                }
                return .{
                    .key = key.?,
                };
            }

            pub fn fromPem_Der(data: []const u8) !PrivateKey {
                try actualSize();
                const bio = ssl.BIO_new_mem_buf(data.ptr, @intCast(data.len)) orelse return error.BioCreationFailed;
                defer _ = ssl.BIO_free(bio);

                const is_pem = blk: {
                    const pem_header = "-----BEGIN";
                    if (data.len < pem_header.len) break :blk false;
                    break :blk std.mem.startsWith(u8, data, pem_header);
                };

                var pkey: ?*ssl.EVP_PKEY = null;

                if (is_pem) {

                    // parse as pem
                    pkey = ssl.PEM_read_bio_PrivateKey(bio, null, null, null);
                } else {
                    //  parse as der
                    pkey = ssl.d2i_PrivateKey_bio(bio, null);
                }

                if (pkey == null) {
                    printOpensslError();
                    return error.KeyParseFailed;
                }

                return PrivateKey{ .key = pkey.? };
            }

            pub fn fromKey(key: *EVP_PKEY) PrivateKey {
                return .{ .key = key };
            }

            pub fn printKeyInfo(pkey: PrivateKey) void {
                const rsa_key = rsaRef(pkey.key);
                const n = ssl.RSA_get0_n(rsa_key);
                const e = ssl.RSA_get0_e(rsa_key);

                const n_hex = ssl.BN_bn2hex(n);
                const e_hex = ssl.BN_bn2hex(e);

                defer {
                    ssl.OPENSSL_free(n_hex);
                    ssl.OPENSSL_free(e_hex);
                }

                std.debug.print("Public Key Info:\n", .{});
                std.debug.print("  Modulus (n): {s}\n", .{n_hex});
                std.debug.print("  Exponent (e): {s}\n", .{e_hex});
            }

            pub fn createPrivateKey(n: *BIGNUM, e: *BIGNUM, d: *BIGNUM) !PrivateKey {
                const rsa_key = try sslAlloc(RSA, ssl.RSA_new());
                errdefer ssl.RSA_free(rsa_key);

                try sslTry(ssl.RSA_set0_key(rsa_key, n, e, d));

                const pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
                try sslTry(ssl.EVP_PKEY_assign(pkey, ssl.EVP_PKEY_RSA, rsa_key));

                return PrivateKey.fromKey(pkey);
            }

            pub fn sign(self: PrivateKey, msg: []const u8, sig: []u8) !usize {
                switch (padding) {
                    .RSASSA_PKCS1_v1_5 => return try signPKCS1v15(self.key, msg, sig),
                    .RSA_PSS => return try signPSS(self.key, msg, sig),
                }
            }

            pub fn publicKey(self: PrivateKey) !PublicKey {

                // GET RSA FROM PRIVATE KEY WITHOUT MEMORY COUNT
                // =============================================
                const rsa_priv = rsaRef(self.key);

                // INVOKE N AND E FROM PRIVATE KEY
                //================================
                const n = ssl.RSA_get0_n(rsa_priv) orelse return error.NullPointer;
                const e = ssl.RSA_get0_e(rsa_priv) orelse return error.NullPointer;

                // CREATE NEW RSA FOR PUBLIC KEY
                // =============================
                const rsa_pub = ssl.RSA_new() orelse return error.MemoryAllocation;

                // COPY N AND E TO RSA_PUB
                // =======================
                if (ssl.RSA_set0_key(rsa_pub, ssl.BN_dup(n), ssl.BN_dup(e), null) != 1) {
                    std.log.err("cannot copy n and e in new rsa", .{});
                    ssl.RSA_free(rsa_pub);
                    return error.KeySetupFailed;
                }

                // CREATE NEW CONTEXT AND SETUP
                // ============================
                const mont_ctx = newMont_ctx(n) catch |err| {
                    std.log.err("something going wrong with mont_ctx creation", .{});
                    ssl.RSA_free(rsa_pub);
                    return err;
                };

                // CREATE EVP_KEY FOR PUBLIC
                // ========================
                const pubkey = ssl.EVP_PKEY_new() orelse {
                    ssl.RSA_free(rsa_pub);
                    ssl.BN_MONT_CTX_free(mont_ctx);
                    return error.MemoryAllocation;
                };
                if (ssl.EVP_PKEY_assign(pubkey, ssl.EVP_PKEY_RSA, rsa_pub) != 1) {
                    ssl.RSA_free(rsa_pub);
                    ssl.EVP_PKEY_free(pubkey);
                    ssl.BN_MONT_CTX_free(mont_ctx);
                    return error.KeyAssignmentFailed;
                }

                return PublicKey{
                    .key = pubkey,
                    .mont_ctx = mont_ctx,
                };
            }
        };

        fn signPKCS1v15(pkey: *ssl.EVP_PKEY, msg: []const u8, sig: []u8) !usize {
            const md = Hash.evp_fn().?;
            try actualSize();

            const md_ctx = ssl.EVP_MD_CTX_new() orelse return error.ContextCreationFailed;
            defer ssl.EVP_MD_CTX_free(md_ctx);
            var sig_len: usize = sig.len;
            if (ssl.EVP_DigestSignInit(md_ctx, null, md, null, pkey) != 1) {
                if (sig_len < modulus_bits) {
                    return error.SignSizeFailed;
                }
                printOpensslError();
                return error.SignInitFailed;
            }
            try actualSize();

            //PKCS1 v1.5 requires the message to be hashed, then padded (e.g. 0x00 0x01 0xFF...0xFF 0x00 || hash)
            //and encrypted with a private key. OpenSSL automatically handles this inside EVP_DigestSign.
            if (ssl.EVP_DigestSign(md_ctx, sig.ptr, &sig_len, msg.ptr, msg.len) != 1) {
                if (sig_len < modulus_bytes) {
                    return error.SignSizeFailed;
                } else {
                    return error.SignFailed;
                }
                printOpensslError();

                return error.SignFailed;
            }

            return sig_len;
        }

        fn signPSS(pkey: *ssl.EVP_PKEY, msg: []const u8, sig: []u8) !usize {
            const md = Hash.evp_fn().?;
            try actualSize();

            const md_ctx = ssl.EVP_MD_CTX_new() orelse return error.ContextCreationFailed;

            defer ssl.EVP_MD_CTX_free(md_ctx);

            var sig_len: usize = sig.len;
            if (ssl.EVP_DigestSignInit(md_ctx, null, md, null, pkey) != 1) {
                if (sig_len < modulus_bits) {
                    return error.SignSizeFailed;
                }
                printOpensslError();

                return error.SignInitFailed;
            }

            const pkey_ctx = ssl.EVP_MD_CTX_pkey_ctx(md_ctx);
            if (ssl.EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, ssl.RSA_PKCS1_PSS_PADDING) != 1) {
                printOpensslError();

                return error.SetPaddingFailed;
            }

            if (ssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, ssl.RSA_PSS_SALTLEN_DIGEST) != 1) {
                printOpensslError();

                return error.SetSaltLenFailed;
            }

            //RSA-PSS adds a random salt to the message hash, applies a mask (MGF1), and encrypts the result
            //OpenSSL implements this according to the PKCS#1 v2.2 standard.
            if (ssl.EVP_DigestSign(md_ctx, sig.ptr, &sig_len, msg.ptr, msg.len) != 1)
                if (sig_len < modulus_bytes) {
                    return error.SignSizeFailed;
                } else {
                    return error.SignFailed;
                };

            return sig_len;
        }

        pub fn verify(public_key: PublicKey, msg: []const u8, sig: []const u8) !void {
            switch (padding) {
                .RSASSA_PKCS1_v1_5 => return try verifyPKCS1v15(public_key.key, msg, sig),
                .RSA_PSS => return try verifyPSS(public_key.key, msg, sig),
            }
        }

        fn verifyPKCS1v15(pkey: *ssl.EVP_PKEY, msg: []const u8, sig: []const u8) !void {
            const md_ctx = ssl.EVP_MD_CTX_new() orelse return error.ContextCreationFailed;
            const md = Hash.evp_fn().?;
            try actualSize();

            defer ssl.EVP_MD_CTX_free(md_ctx);

            if (ssl.EVP_DigestVerifyInit(md_ctx, null, md, null, pkey) != 1) {
                printOpensslError();
                return error.VerifyInitFailed;
            }

            if (ssl.EVP_DigestVerify(md_ctx, sig.ptr, sig.len, msg.ptr, msg.len) != 1) {
                printOpensslError();
                return error.VerifyFailed;
            }
        }

        fn verifyPSS(pkey: *ssl.EVP_PKEY, msg: []const u8, sig: []const u8) !void {
            const md = Hash.evp_fn().?;

            const md_ctx = ssl.EVP_MD_CTX_new() orelse return error.ContextCreationFailed;
            defer ssl.EVP_MD_CTX_free(md_ctx);

            if (ssl.EVP_DigestVerifyInit(md_ctx, null, md, null, pkey) != 1) {
                printOpensslError();
                return error.VerifyInitFailed;
            }
            const pkey_ctx = ssl.EVP_MD_CTX_pkey_ctx(md_ctx);
            if (ssl.EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, ssl.RSA_PKCS1_PSS_PADDING) != 1) {
                printOpensslError();
                return error.SetPaddingFailed;
            }
            try actualSize();

            if (ssl.EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, ssl.RSA_PSS_SALTLEN_DIGEST) != 1) {
                printOpensslError();

                return error.SetSaltLenFailed;
            }

            if (ssl.EVP_DigestVerify(md_ctx, sig.ptr, sig.len, msg.ptr, msg.len) != 1) {
                printOpensslError();

                return error.VerifyFailed;
            }
        }
        pub fn generateKey() !PrivateKey {
            const sk = try sslAlloc(RSA, ssl.RSA_new());
            errdefer ssl.RSA_free(sk);
            const e: *BIGNUM = try sslAlloc(BIGNUM, ssl.BN_new());
            defer ssl.BN_free(e);

            try sslTry(ssl.BN_set_word(e, ssl.RSA_F4));
            try sslTry(ssl.RSA_generate_key_ex(sk, modulus_bits, e, null));
            const evp_pkey: *EVP_PKEY = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
            defer ssl.EVP_PKEY_free(evp_pkey);
            _ = ssl.EVP_PKEY_up_ref(evp_pkey);
            _ = ssl.EVP_PKEY_assign(evp_pkey, ssl.EVP_PKEY_RSA, sk);
            const sk_ = PrivateKey{ .key = evp_pkey };
            return sk_;
        }
    };
}

// TEST CASES
// ==================================

test "RSA-PSS Sign/Verify" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    // GENERATE KEYS
    // ============
    var priv_key = try rsa.generateKey();
    defer priv_key.deinit();
    // ===========================
    const pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    // GET SIGNATURE LETS SIGN THIS
    // ============================
    const msg = "Test message";
    var sig: rsa.Signature = undefined;
    const sig_len = try priv_key.sign(msg, &sig);

    // CHECK WHAT IS GOIING ON
    // =======================
    try rsa.verify(pub_key, msg, sig[0..sig_len]);
}

test "RSA-PKCS1v1.5 Sign/Verify" {
    const rsa = RSAAlgorithm(2048, .RSASSA_PKCS1_v1_5, .sha256);

    const priv_key = try rsa.generateKey();
    defer priv_key.deinit();

    const pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    const msg = "Test message";
    var sig: rsa.Signature = undefined;
    const sig_len = try priv_key.sign(msg, &sig);

    try rsa.verify(pub_key, msg, sig[0..sig_len]);
}

test "RSA-PSS detect message tampering" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    var priv_key = try rsa.generateKey();
    defer priv_key.deinit();
    const pub_key = try priv_key.publicKey();

    defer pub_key.deinit();

    // SIGNATURE GHIT
    //===============
    const original_msg = "Test message";
    var sig: rsa.Signature = undefined;

    const sig_len = try priv_key.sign(original_msg, &sig);

    // TRY TO VERIFY WITH ANOTHER MESSAGE
    // =================================
    const tampered_msg = "Tampered!";

    const verify_result = rsa.verify(pub_key, tampered_msg, sig[0..sig_len]);
    try std.testing.expectError(error.VerifyFailed, verify_result);
}

test "RSA-PSS wrong public key detection" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    // GENERATE ONE KEY
    // ================
    var priv_key1 = try rsa.generateKey();

    defer priv_key1.deinit();
    const pub_key1 = try priv_key1.publicKey();
    defer pub_key1.deinit();
    // GENERATE TWO KEY
    // ===============
    var priv_key2 = try rsa.generateKey();
    defer priv_key2.deinit();
    const pub_key2 = try priv_key2.publicKey();
    defer pub_key2.deinit();

    // SIGN WITH THIRST KEY
    // ===================

    const msg = "Secret message";
    var sig: rsa.Signature = undefined;
    const sig_len = try priv_key1.sign(msg, &sig);

    // TRY TO VERIFY WITH ANOTHER KEY
    // =============================
    const verify_result = rsa.verify(pub_key2, msg, sig[0..sig_len]);

    try std.testing.expectError(error.VerifyFailed, verify_result);
}

test "rsa PKCS1-v1_5 signature" {
    const rsa = RSAAlgorithm(2048, .RSASSA_PKCS1_v1_5, .sha256);

    var pkey = try rsa.generateKey();
    defer pkey.deinit();

    const pub_key = try pkey.publicKey();

    const msg = "rsa PKCS1-v1_5 signature";
    var out: rsa.Signature = undefined;

    const sign = try pkey.sign(msg, &out);
    try rsa.verify(pub_key, msg, out[0..sign]);
}

test "RSA-PSS OpenSSL compatibility" {
    const allocator = std.testing.allocator;
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    // GENERATE KEY
    // ===========
    var priv_key = try rsa.generateKey();

    defer priv_key.deinit();
    const pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    // EXPORT TO PEM
    // =============
    const priv_key_pem = try exportPrivateKey(priv_key.key, allocator);
    defer allocator.free(priv_key_pem);
    var test_priv_pem = try cwd.createFile("test_priv.pem", .{});
    defer test_priv_pem.close();
    try test_priv_pem.writeAll(priv_key_pem);

    // HASH MESSAGE
    const msg = "OpenSSL compatibility test";
    // ===========
    const digest = sha256Digest(msg);

    var test_msg = try cwd.createFile("test_msg.txt", .{});
    defer test_msg.close();
    // WRITE HASH TO file
    // ==================
    try test_msg.writeAll(digest[0..]);

    // SIGN WITH OPENSSL CLI
    // ====================
    const sign_result = try std.process.Child.run(.{
        .allocator = allocator,

        .argv = &[_][]const u8{
            "openssl",       "pkeyutl",      "-sign",    "-inkey",               "test_priv.pem", "-in",                "test_msg.txt",
            "-out",          "test_sig.bin", "-pkeyopt", "rsa_padding_mode:pss", "-pkeyopt",      "rsa_pss_saltlen:32", "-pkeyopt",
            "digest:sha256",
        },
    });

    defer {
        if (sign_result.stdout.len > 0) allocator.free(sign_result.stdout);
        if (sign_result.stderr.len > 0) allocator.free(sign_result.stderr);
    }
    std.debug.print("OpenSSL stderr: {s}\n", .{sign_result.stderr});
    try std.testing.expect(sign_result.term.Exited == 0);

    const sig_file = try cwd.openFile("test_sig.bin", .{});
    defer sig_file.close();
    const sig_size = try sig_file.getEndPos();
    try std.testing.expectEqual(rsa.modulus_bytes, sig_size);

    const sig = try cwd.readFileAlloc(allocator, "test_sig.bin", 4096);

    defer allocator.free(sig);

    try rsa.verify(pub_key, msg, sig);

    try deleteFile("test_priv.pem");
    try deleteFile("test_msg.txt");
    try deleteFile("test_sig.bin");
}

test "RSA-PSS OpenSSL compatibility without prehash" {
    const allocator = std.testing.allocator;
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    var priv_key = try rsa.generateKey();
    defer priv_key.deinit();
    const pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    const priv_key_pem = try exportPrivateKey(priv_key.key, allocator);
    defer allocator.free(priv_key_pem);
    var test_priv_pem = try cwd.createFile("test_priv.pem", .{});
    defer test_priv_pem.close();
    try test_priv_pem.writeAll(priv_key_pem);

    const msg = "OpenSSL compatibility test";
    var test_msg = try cwd.createFile("test_msg.txt", .{});
    defer test_msg.close();
    try test_msg.writeAll(msg);

    const sign_result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "openssl",
            "pkeyutl",
            "-sign",
            "-inkey",
            "test_priv.pem",
            "-in",
            "test_msg.txt",
            "-out",
            "test_sig.bin",
            "-pkeyopt",
            "rsa_padding_mode:pss",
            "-pkeyopt",
            "rsa_pss_saltlen:32",
            "-pkeyopt",
            "rsa_mgf1_md:sha256",
            "-rawin",
        },
    });

    defer {
        if (sign_result.stdout.len > 0) allocator.free(sign_result.stdout);
        if (sign_result.stderr.len > 0) allocator.free(sign_result.stderr);
    }
    std.debug.print("OpenSSL stderr: {s}\n", .{sign_result.stderr});
    try std.testing.expect(sign_result.term.Exited == 0);

    const sig_file = try cwd.openFile("test_sig.bin", .{});
    defer sig_file.close();
    const sig_size = try sig_file.getEndPos();
    try std.testing.expectEqual(rsa.modulus_bytes, sig_size);

    const sig = try cwd.readFileAlloc(allocator, "test_sig.bin", 4096);
    defer allocator.free(sig);

    try rsa.verify(pub_key, msg, sig);

    try deleteFile("test_priv.pem");
    try deleteFile("test_msg.txt");
    try deleteFile("test_sig.bin");
}

test "RSA key serialization integrity" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    const priv_key = try rsa.generateKey();
    defer priv_key.deinit();
    const pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    var buf: [1000]u8 = undefined;

    const serialized = try pub_key.toBytes(&buf);

    try std.testing.expect(serialized.len >= 270 and serialized.len <= 350);
    try std.testing.expect(serialized[0] == 0x30); // ASN.1 SEQUENCE
}

test "RSA key validation" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    const priv_key = try rsa.generateKey();
    defer priv_key.deinit();
    const pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    const n = rsaParam(.n, pub_key.key);
    const e = rsaParam(.e, pub_key.key);

    const bits = ssl.BN_num_bits(n);
    try std.testing.expectEqual(@as(c_int, 2048), bits);

    const expected_e = ssl.BN_new();
    defer ssl.BN_free(expected_e);
    _ = ssl.BN_set_word(expected_e, 65537);
    try std.testing.expectEqual(ssl.BN_cmp(e, expected_e), 0);
}

test "RSA sign with insufficient signature buffer" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);
    var priv_key = try rsa.generateKey();
    defer priv_key.deinit();

    const msg = "Test message";

    var small_sig: [256 / 2]u8 = undefined;
    try std.testing.expectError(error.SignSizeFailed, priv_key.sign(msg, &small_sig));
}

test "RSA invalid input handling" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);
    const allocator = std.testing.allocator;

    const priv_key = try rsa.generateKey();
    defer priv_key.deinit();
    const pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    const long_msg = try allocator.alloc(u8, 4096);
    defer allocator.free(long_msg);
    @memset(long_msg, 0xAA);

    var long_sig: rsa.Signature = undefined;

    const sig_len = try priv_key.sign(long_msg, &long_sig);
    try rsa.verify(pub_key, long_msg, long_sig[0..sig_len]);

    const zero_sig = [_]u8{0} ** 256;
    try std.testing.expectError(error.VerifyFailed, rsa.verify(pub_key, "test", &zero_sig));
}

test "RSA signature malleability resistance" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    const priv_key = try rsa.generateKey();
    defer priv_key.deinit();
    const pub_key = try priv_key.publicKey();

    defer pub_key.deinit();

    const msg = "Critical transaction";
    var sig: rsa.Signature = undefined;

    const sig_len = try priv_key.sign(msg, &sig);

    var tampered_sig = sig;

    tampered_sig[0] +%= 1;

    try std.testing.expectError(error.VerifyFailed, rsa.verify(pub_key, msg, tampered_sig[0..sig_len]));
}

test "RSA memory safety" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    // STRESS TEST MEMORY LEAKS
    // =========================
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const priv_key = try rsa.generateKey();
        defer priv_key.deinit();

        const pub_key = try priv_key.publicKey();
        defer pub_key.deinit();

        const msg = "Memory safety test";
        var sig: rsa.Signature = undefined;
        const sig_len = try priv_key.sign(msg, &sig);
        try rsa.verify(pub_key, msg, sig[0..sig_len]);
    }
}

test "Test vector" {
    const tv = .{
        .p = "e1f4d7a34802e27c7392a3cea32a262a34dc3691bd87f3f310dc75673488930559c120fd0410194fb8a0da55bd0b81227e843fdca6692ae80e5a5d414116d4803fca7d8c30eaaae57e44a1816ebb5c5b0606c536246c7f11985d731684150b63c9a3ad9e41b04c0b5b27cb188a692c84696b742a80d3cd00ab891f2457443dadfeba6d6daf108602be26d7071803c67105a5426838e6889d77e8474b29244cefaf418e381b312048b457d73419213063c60ee7b0d81820165864fef93523c9635c22210956e53a8d96322493ffc58d845368e2416e078e5bcb5d2fd68ae6acfa54f9627c42e84a9d3f2774017e32ebca06308a12ecc290c7cd1156dcccfb2311",
        .q = "c601a9caea66dc3835827b539db9df6f6f5ae77244692780cd334a006ab353c806426b60718c05245650821d39445d3ab591ed10a7339f15d83fe13f6a3dfb20b9452c6a9b42eaa62a68c970df3cadb2139f804ad8223d56108dfde30ba7d367e9b0a7a80c4fdba2fd9dde6661fc73fc2947569d2029f2870fc02d8325acf28c9afa19ecf962daa7916e21afad09eb62fe9f1cf91b77dc879b7974b490d3ebd2e95426057f35d0a3c9f45f79ac727ab81a519a8b9285932d9b2e5ccd347e59f3f32ad9ca359115e7da008ab7406707bd0e8e185a5ed8758b5ba266e8828f8d863ae133846304a2936ad7bc7c9803879d2fc4a28e69291d73dbd799f8bc238385",
        .n = "aec4d69addc70b990ea66a5e70603b6fee27aafebd08f2d94cbe1250c556e047a928d635c3f45ee9b66d1bc628a03bac9b7c3f416fe20dabea8f3d7b4bbf7f963be335d2328d67e6c13ee4a8f955e05a3283720d3e1f139c38e43e0338ad058a9495c53377fc35be64d208f89b4aa721bf7f7d3fef837be2a80e0f8adf0bcd1eec5bb040443a2b2792fdca522a7472aed74f31a1ebe1eebc1f408660a0543dfe2a850f106a617ec6685573702eaaa21a5640a5dcaf9b74e397fa3af18a2f1b7c03ba91a6336158de420d63188ee143866ee415735d155b7c2d854d795b7bc236cffd71542df34234221a0413e142d8c61355cc44d45bda94204974557ac2704cd8b593f035a5724b1adf442e78c542cd4414fce6f1298182fb6d8e53cef1adfd2e90e1e4deec52999bdc6c29144e8d52a125232c8c6d75c706ea3cc06841c7bda33568c63a6c03817f722b50fcf898237d788a4400869e44d90a3020923dc646388abcc914315215fcd1bae11b1c751fd52443aac8f601087d8d42737c18a3fa11ecd4131ecae017ae0a14acfc4ef85b83c19fed33cfd1cd629da2c4c09e222b398e18d822f77bb378dea3cb360b605e5aa58b20edc29d000a66bd177c682a17e7eb12a63ef7c2e4183e0d898f3d6bf567ba8ae84f84f1d23bf8b8e261c3729e2fa6d07b832e07cddd1d14f55325c6f924267957121902dc19b3b32948bdead5",

        .e = "010001",
        .d = "0d43242aefe1fb2c13fbc66e20b678c4336d20b1808c558b6e62ad16a287077180b177e1f01b12f9c6cd6c52630257ccef26a45135a990928773f3bd2fc01a313f1dac97a51cec71cb1fd7efc7adffdeb05f1fb04812c924ed7f4a8269925dad88bd7dcfbc4ef01020ebfc60cb3e04c54f981fdbd273e69a8a58b8ceb7c2d83fbcbd6f784d052201b88a9848186f2a45c0d2826870733e6fd9aa46983e0a6e82e35ca20a439c5ee7b502a9062e1066493bdadf8b49eb30d9558ed85abc7afb29b3c9bc644199654a4676681af4babcea4e6f71fe4565c9c1b85d9985b84ec1abf1a820a9bbebee0df1398aae2c85ab580a9f13e7743afd3108eb32100b870648fa6bc17e8abac4d3c99246b1f0ea9f7f93a5dd5458c56d9f3f81ff2216b3c3680a13591673c43194d8e6fc93fc1e37ce2986bd628ac48088bc723d8fbe293861ca7a9f4a73e9fa63b1b6d0074f5dea2a624c5249ff3ad811b6255b299d6bc5451ba7477f19c5a0db690c3e6476398b1483d10314afd38bbaf6e2fbdbcd62c3ca9797a420ca6034ec0a83360a3ee2adf4b9d4ba29731d131b099a38d6a23cc463db754603211260e99d19affc902c915d7854554aabf608e3ac52c19b8aa26ae042249b17b2d29669b5c859103ee53ef9bdc73ba3c6b537d5c34b6d8f034671d7f3a8a6966cc4543df223565343154140fd7391c7e7be03e241f4ecfeb877a051",

        .msg = "8f3dc6fb8c4a02f4d6352edf0907822c1210a9b32f9bdda4c45a698c80023aa6b59f8cfec5fdbb36331372ebefedae7d",
        .sig = "6fef8bf9bc182cd8cf7ce45c7dcf0e6f3e518ae48f06f3c670c649ac737a8b8119a34d51641785be151a697ed7825fdfece82865123445eab03eb4bb91cecf4d6951738495f8481151b62de869658573df4e50a95c17c31b52e154ae26a04067d5ecdc1592c287550bb982a5bb9c30fd53a768cee6baabb3d483e9f1e2da954c7f4cf492fe3944d2fe456c1ecaf0840369e33fb4010e6b44bb1d721840513524d8e9a3519f40d1b81ae34fb7a31ee6b7ed641cb16c2ac999004c2191de0201457523f5a4700dd649267d9286f5c1d193f1454c9f868a57816bf5ff76c838a2eeb616a3fc9976f65d4371deecfbab29362caebdff69c635fe5a2113da4d4d8c24f0b16a0584fa05e80e607c5d9a2f765f1f069f8d4da21f27c2a3b5c984b4ab24899bef46c6d9323df4862fe51ce300fca40fb539c3bb7fe2dcc9409e425f2d3b95e70e9c49c5feb6ecc9d43442c33d50003ee936845892fb8be475647da9a080f5bc7f8a716590b3745c2209fe05b17992830ce15f32c7b22cde755c8a2fe50bd814a0434130b807dc1b7218d4e85342d70695a5d7f29306f25623ad1e8aa08ef71b54b8ee447b5f64e73d09bdd6c3b7ca224058d7c67cc7551e9241688ada12d859cb7646fbd3ed8b34312f3b49d69802f0eaa11bc4211c2f7a29cd5c01ed01a39001c5856fab36228f5ee2f2e1110811872fe7c865c42ed59029c706195d52",
        .secret = "80682c48982407b489d53d1261b19ec8627d02b8cda5336750b8cee332ae260de57b02d72609c1e0e9f28e2040fc65b6f02d56dbd6aa9af8fde656f70495dfb723ba01173d4707a12fddac628ca29f3e32340bd8f7ddb557cf819f6b01e445ad96f874ba235584ee71f6581f62d4f43bf03f910f6510deb85e8ef06c7f09d9794a008be7ff2529f0ebb69decef646387dc767b74939265fec0223aa6d84d2a8a1cc912d5ca25b4e144ab8f6ba054b54910176d5737a2cff011da431bd5f2a0d2d66b9e70b39f4b050e45c0d9c16f02deda9ddf2d00f3e4b01037d7029cd49c2d46a8e1fc2c0c17520af1f4b5e25ba396afc4cd60c494a4c426448b35b49635b337cfb08e7c22a39b256dd032c00adddafb51a627f99a0e1704170ac1f1912e49d9db10ec04c19c58f420212973e0cb329524223a6aa56c7937c5dffdb5d966b6cd4cbc26f3201dd25c80960a1a111b32947bb78973d269fac7f5186530930ed19f68507540eed9e1bab8b00f00d8ca09b3f099aae46180e04e3584bd7ca054df18a1504b89d1d1675d0966c4ae1407be325cdf623cf13ff13e4a28b594d59e3eadbadf6136eee7a59d6a444c9eb4e2198e8a974f27a39eb63af2c9af3870488b8adaad444674f512133ad80b9220e09158521614f1faadfe8505ef57b7df6813048603f0dd04f4280177a11380fbfc861dbcbd7418d62155248dad5fdec0991f",
    };

    const rsa = RSAAlgorithm(4096, .RSA_PSS, .sha256);

    var n: ?*BIGNUM = null;
    var e: ?*BIGNUM = null;
    var d: ?*BIGNUM = null;

    try sslNegTry(ssl.BN_hex2bn(&n, tv.n));

    errdefer ssl.BN_free(n);
    try sslNegTry(ssl.BN_hex2bn(&e, tv.e));
    errdefer ssl.BN_free(e);

    try sslNegTry(ssl.BN_hex2bn(&d, tv.d));

    errdefer ssl.BN_free(d);
    const sk_ = try sslAlloc(RSA, ssl.RSA_new());
    errdefer ssl.RSA_free(sk_);
    const pk_ = try sslAlloc(RSA, ssl.RSA_new());
    errdefer ssl.RSA_free(pk_);

    var n_: ?*BIGNUM = try sslAlloc(BIGNUM, ssl.BN_dup(n));
    errdefer ssl.BN_free(n_);
    var e_: ?*BIGNUM = try sslAlloc(BIGNUM, ssl.BN_dup(e));
    errdefer ssl.BN_free(e_);

    try sslTry(ssl.RSA_set0_key(sk_, n, e, d));
    n = null;
    e = null;
    d = null;
    try sslTry(ssl.RSA_set0_key(pk_, n_, e_, null));
    n_ = null;
    e_ = null;
    var msg: [tv.msg.len / 2]u8 = undefined;
    _ = try fmt.hexToBytes(&msg, tv.msg);
    var signature: rsa.Signature = undefined;
    _ = try fmt.hexToBytes(&signature, tv.sig);

    const sk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    defer ssl.EVP_PKEY_free(sk_evp_pkey);
    _ = ssl.EVP_PKEY_up_ref(sk_evp_pkey);
    _ = ssl.EVP_PKEY_assign(sk_evp_pkey, ssl.EVP_PKEY_RSA, sk_);
    const sk = rsa.PrivateKey.fromKey(sk_evp_pkey);

    const pk_evp_pkey = try sslAlloc(EVP_PKEY, ssl.EVP_PKEY_new());
    defer ssl.EVP_PKEY_free(pk_evp_pkey);
    _ = ssl.EVP_PKEY_up_ref(pk_evp_pkey);
    _ = ssl.EVP_PKEY_assign(pk_evp_pkey, ssl.EVP_PKEY_RSA, pk_);
    const pk = rsa.PublicKey{
        .key = pk_evp_pkey,
        .mont_ctx = try newMont_ctx(ssl.RSA_get0_n(pk_).?),
    };

    const sig = try sk.sign(&msg, &signature);

    try rsa.verify(pk, &msg, signature[0..sig]);
}

test "Basic RSA-PSS Sign/Verify with Generated Keys" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    const priv_key = try rsa.generateKey();
    defer priv_key.deinit();

    const pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    const test_messages = [_][]const u8{
        "Hello, RSA-PSS!",
        "",
        "Zig is awesome!",

        "Тест на русском",
        "\x00\x01\x02\x03\x04",
    };

    for (test_messages) |msg| {
        std.debug.print("\n=== Testing message: {s} ===\n", .{msg});

        var sig: rsa.Signature = undefined;
        const sig_len = try priv_key.sign(msg, &sig);

        std.debug.print("Signature length: {}\n", .{sig_len});

        try rsa.verify(pub_key, msg, sig[0..sig_len]);

        var tampered_sig = sig;
        if (sig_len > 0) {
            tampered_sig[0] +%= 1;
        }
        try std.testing.expectError(error.VerifyFailed, rsa.verify(pub_key, msg, tampered_sig[0..sig_len]));

        const wrong_msg = "Wrong message";
        try std.testing.expectError(error.VerifyFailed, rsa.verify(pub_key, wrong_msg, sig[0..sig_len]));
    }

    const another_priv_key = try rsa.generateKey();
    defer another_priv_key.deinit();
    const another_pub_key = try another_priv_key.publicKey();
    defer another_pub_key.deinit();

    const msg = "Cross-key test";
    var sig: rsa.Signature = undefined;
    const sig_len = try priv_key.sign(msg, &sig);

    try std.testing.expectError(error.VerifyFailed, rsa.verify(another_pub_key, msg, sig[0..sig_len]));
    std.debug.print("Cross-key verification test passed\n", .{});
}

test "RSA-PSS with different hash functions" {
    const hashes = .{ .sha384, .sha512 };

    inline for (hashes) |hash| {
        const rsa_algo = RSAAlgorithm(2048, .RSA_PSS, hash);
        const priv_key = try rsa_algo.generateKey();
        defer priv_key.deinit();

        const pub_key = try priv_key.publicKey();
        defer pub_key.deinit();

        const msg = "Test with " ++ @tagName(hash);
        var sig: rsa_algo.Signature = undefined;
        const sig_len = try priv_key.sign(msg, &sig);

        try rsa_algo.verify(pub_key, msg, sig[0..sig_len]);
    }
}

test "RSA NULL pointer handling" {
    const rsa = RSAAlgorithm(2048, .RSA_PSS, .sha256);

    try std.testing.expectError(error.VerifyInitFailed, rsa.verify(.{ .key = undefined, .mont_ctx = undefined }, "test", &[0]u8{}));
}
