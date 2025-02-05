const std = @import("std");
const ed = @import("eddsa.zig");

test "Eddsa test" {
    const eddsa = try ed.Eddsa.generateKeys();

    const message = "test";

    const signature = eddsa.sign(message) catch |err| return err;
    try signature.verify(message, eddsa.keyPaid.public_key);

    std.debug.print("Signature: {any}\n", .{signature.toBytes()});

    std.debug.print("Public key: {any}\n", .{eddsa.keyPaid.public_key.toBytes()});
}
