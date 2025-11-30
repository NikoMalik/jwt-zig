const std = @import("std");
const rsa = @import("rsa.zig");

/// Example demonstrating how to serialize RSA keys to DER bytes for database storage
/// and deserialize them back into usable keys
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    std.debug.print("=== RSA Key Serialization/Deserialization Example ===\n\n", .{});

    const rsa_algo = rsa.RSAAlgorithm(2048, .RSASSA_PKCS1_v1_5, .sha256);

    // Generate a key pair
    std.debug.print("1. Generating RSA-2048 key pair...\n", .{});
    var priv_key = try rsa_algo.generateKey();
    defer priv_key.deinit();
    var pub_key = try priv_key.publicKey();
    defer pub_key.deinit();

    // Sign a test message with the original private key
    const msg = "Hello, this is a test message!";
    std.debug.print("2. Signing message: \"{s}\"\n", .{msg});
    var sig: rsa_algo.Signature = undefined;
    const sig_len = try priv_key.sign(msg, &sig);
    std.debug.print("   Signature length: {d} bytes\n", .{sig_len});

    // =====================================================================
    // SERIALIZE TO BYTES (as you would store in database)
    // =====================================================================
    std.debug.print("\n3. Serializing keys to DER bytes for database storage...\n", .{});

    // Private key serialization
    var priv_der_buffer: [4096]u8 = undefined;
    const priv_der_bytes = try priv_key.toBytes(&priv_der_buffer);
    std.debug.print("   Private key DER: {d} bytes\n", .{priv_der_bytes.len});
    std.debug.print("   First few bytes: ", .{});
    for (priv_der_bytes[0..@min(16, priv_der_bytes.len)], 0..) |byte, i| {
        std.debug.print("{x:0>2}", .{byte});
        if (i % 4 == 3) std.debug.print(" ", .{});
    }
    std.debug.print("\n", .{});

    // Public key serialization
    var pub_der_buffer: [4096]u8 = undefined;
    const pub_der_bytes = try pub_key.toBytes(&pub_der_buffer);
    std.debug.print("   Public key DER: {d} bytes\n", .{pub_der_bytes.len});
    std.debug.print("   First few bytes: ", .{});
    for (pub_der_bytes[0..@min(16, pub_der_bytes.len)], 0..) |byte, i| {
        std.debug.print("{x:0>2}", .{byte});
        if (i % 4 == 3) std.debug.print(" ", .{});
    }
    std.debug.print("\n", .{});

    // In a real scenario, you would store these bytes in your database:
    // INSERT INTO keys (id, private_key, public_key) VALUES (?, priv_der_bytes, pub_der_bytes);
    std.debug.print("\n   [Simulated DB storage]\n", .{});

    // =====================================================================
    // DESERIALIZE FROM BYTES (as you would load from database)
    // =====================================================================
    std.debug.print("\n4. Deserializing keys from DER bytes (reading from database)...\n", .{});

    // Load private key from bytes
    const loaded_priv_key = try rsa_algo.PrivateKey.fromBytes(priv_der_bytes);
    defer loaded_priv_key.deinit();
    std.debug.print("   ✅ Private key loaded successfully\n", .{});

    // Load public key from bytes
    const loaded_pub_key = try rsa_algo.PublicKey.fromBytes(pub_der_bytes);
    defer loaded_pub_key.deinit();
    std.debug.print("   ✅ Public key loaded successfully\n", .{});

    // =====================================================================
    // VERIFY THE LOADED KEYS WORK
    // =====================================================================
    std.debug.print("\n5. Testing the loaded keys...\n", .{});

    // Sign with the loaded private key
    var new_sig: rsa_algo.Signature = undefined;
    const new_sig_len = try loaded_priv_key.sign(msg, &new_sig);
    std.debug.print("   Signed with loaded private key: {d} bytes\n", .{new_sig_len});

    // Verify with the loaded public key
    try rsa_algo.verify(loaded_pub_key, msg, new_sig[0..new_sig_len]);
    std.debug.print("   ✅ Verification successful with loaded public key\n", .{});

    // Verify the original signature with the loaded public key
    try rsa_algo.verify(loaded_pub_key, msg, sig[0..sig_len]);
    std.debug.print("   ✅ Original signature verified with loaded public key\n", .{});

    // Verify loaded public key signature with original public key
    // (They should be identical)
    try rsa_algo.verify(pub_key, msg, new_sig[0..new_sig_len]);
    std.debug.print("   ✅ Loaded key signature verified with original public key\n", .{});

    std.debug.print("\n=== All tests passed! ===\n", .{});
    std.debug.print("\nYou can now store DER bytes in your database and restore them later.\n", .{});
    std.debug.print("The keys are completely portable and will work across different sessions.\n", .{});
}
