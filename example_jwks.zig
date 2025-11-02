const std = @import("std");
const jwt = @import("root.zig");
const head = jwt.header;
const rsa = @import("rsa.zig");
const time = @import("time.zig");
const base64 = std.base64.url_safe_no_pad.Encoder;

// Example demonstrating JWT signing and verification with JWKS-style key management
// This mimics a server-to-server authentication scenario where:
// - Auth server signs tokens with a private key
// - Resource server verifies tokens using public keys from JWKS endpoint
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // =====================================================================
    // Part 1: Auth Server - Generate RSA Key Pair and Sign JWT
    // =====================================================================
    std.debug.print("\n=== AUTH SERVER ===\n", .{});

    const rsa_algo = rsa.RSAAlgorithm(2048, .RSASSA_PKCS1_v1_5, .sha256);

    // Generate key pair (in production, this would be done once and stored securely)
    var priv_key = try rsa_algo.generateKey();
    defer priv_key.deinit();

    var pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    // Export public key to PEM format (this would be published in JWKS endpoint)
    const pub_key_pem = try rsa.exportPublicKey(pub_key.key, allocator);
    defer allocator.free(pub_key_pem);

    std.debug.print("Generated RSA-2048 key pair\n", .{});
    std.debug.print("Public Key PEM:\n{s}\n", .{pub_key_pem});

    // Create and sign a JWT token
    const header = head.Header.init(allocator, jwt.typ.Type.JWT, jwt.typ.Algorithm.RS256, .{ .kid = "key-id-1" });

    const now = @as(u64, @intCast(std.time.timestamp()));
    const payload = jwt.payload.Payload{
        .allocator = allocator,
        .sub = "service-abc",
        .iss = "https://auth.example.com",
        .aud = "https://api.example.com",
        .exp = time.NumericDate.init(allocator, now + 3600), // 1 hour from now
        .iat = time.NumericDate.init(allocator, now),
    };

    var jwt_token = jwt.jwt.Token(jwt.payload.Payload).init(allocator, header, payload);
    defer jwt_token.deinit();

    // Sign the token with private key
    var der_buffer: [4096]u8 = undefined;
    const private_bytes = try priv_key.toBytes(&der_buffer);
    const signed_token = try jwt_token.signToken(private_bytes);
    defer allocator.free(signed_token);

    std.debug.print("\nSigned JWT:\n{s}\n", .{signed_token});

    // =====================================================================
    // Part 2: Resource Server - Verify JWT Using Public Key from JWKS
    // =====================================================================
    std.debug.print("\n=== RESOURCE SERVER ===\n", .{});

    // Parse the token to extract kid (Key ID)
    // First, we need to extract the signature from the raw token
    var iter = std.mem.splitSequence(u8, signed_token, ".");
    _ = iter.first(); // header
    _ = iter.next(); // payload
    const sig_b64 = iter.next() orelse return error.InvalidTokenFormat;

    // Decode the signature from base64
    const sig_decoded_size = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(sig_b64) catch 0;
    if (sig_decoded_size == 0) return error.InvalidSignature;
    var sig_buffer: [512]u8 = undefined;
    _ = try std.base64.url_safe_no_pad.Decoder.decode(sig_buffer[0..sig_decoded_size], sig_b64);
    const sig_decoded_slice = sig_buffer[0..sig_decoded_size];

    // Now parse with the signature
    var parsed_token = try jwt.parse.parseToken(jwt.payload.Payload, allocator, signed_token, sig_decoded_slice);
    defer parsed_token.deinit();

    // In a real scenario, you would:
    // 1. Extract kid from token header
    // 2. Fetch JWKS from auth server's /well-known/jwks.json endpoint
    // 3. Find the key matching the kid
    // 4. Parse the public key from JWKS (n, e values in base64)

    // For this example, we'll parse the PEM we exported earlier
    std.debug.print("Verifying token using public key from JWKS...\n", .{});

    const verification_pub_key = try rsa_algo.PublicKey.fromPem_Der(pub_key_pem);
    defer verification_pub_key.deinit();

    // Convert to DER for verification
    var der_verify_buffer: [4096]u8 = undefined;
    const pub_key_der = try verification_pub_key.toBytes(&der_verify_buffer);

    const is_valid = try parsed_token.verifyToken(pub_key_der);

    std.debug.print("Token verification: {}\n", .{is_valid});

    if (is_valid) {
        const payload_json = try parsed_token.payload.marshalJSON_PAYLOAD();
        defer allocator.free(payload_json);
        std.debug.print("Token is valid! Payload: {s}\n", .{payload_json});
    } else {
        std.debug.print("Token verification failed!\n", .{});
        return error.VerificationFailed;
    }
}
