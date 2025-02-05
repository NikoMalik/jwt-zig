const std = @import("std");
const _algo_ = @import("algorithm.zig");

const privateKeyLen = std.crypto.sign.Ed25519.SecretKey.encoded_length;
const publicKeyLen = std.crypto.sign.Ed25519.PublicKey.encoded_length;
const signatureLen = std.crypto.sign.Ed25519.Signature.encoded_length;
const seedLen = std.crypto.sign.Ed25519.KeyPair.seed_length;
const SecretKey = std.crypto.sign.Ed25519.SecretKey;
const PublicKey = std.crypto.sign.Ed25519.PublicKey;
const Signature = std.crypto.sign.Ed25519.Signature;

pub const Eddsa = struct {
    keyPaid: std.crypto.sign.Ed25519.KeyPair,

    pub fn init(private_key: SecretKey, public_key: PublicKey) Eddsa {
        return Eddsa{ .keyPaid = .{
            .secret_key = private_key,
            .public_key = public_key,
        } };
    }

    pub fn generateKeys() !Eddsa {
        const kp = std.crypto.sign.Ed25519.KeyPair.generate();
        return Eddsa{
            .keyPaid = kp,
        };
    }
    pub fn initFromSecretKey(e: *const Eddsa, secret_key: SecretKey) !Eddsa {
        return e.keyPaid.fromSecretKey(secret_key);
    }

    pub fn sign(e: *const Eddsa, message: []const u8) !Signature {
        return e.keyPaid.sign(message, null);
    }

    pub fn verify(signature: Signature, message: []const u8, public_key: PublicKey) bool {
        if (!signature.verify(message, public_key)) {
            return false;
        }
    }

    pub fn algo(e: *const Eddsa) _algo_.Algorithm {
        _ = e;
        return _algo_.Algorithm.EDDSA;
    }
};
