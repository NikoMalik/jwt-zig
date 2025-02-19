const std = @import("std");
const date = @import("time.zig");
const p = @import("payload.zig");

test "Payload tests" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const nd = date.NumericDate.init(allocator, 1700000000);

    const ts = @as(u64, @intCast(std.time.timestamp()));

    const iat = date.NumericDate.init(allocator, ts);

    var payload = p.Payload{
        .allocator = allocator,
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .aud = "audience",
        .exp = nd,
        .iat = iat,
    };
    // defer payload.deinit();

    try std.testing.expectEqualStrings("issuer.com", payload.getIssuer().?);
    try std.testing.expectEqualStrings("subject", payload.getSubject().?);
    try std.testing.expectEqualStrings("audience", payload.getAudience().?);

    try std.testing.expectEqual(payload.getExpirationTime(), 1700000000);
    try std.testing.expect(payload.getNotBefore() == null);

    try std.testing.expect(payload.isId("test_id"));

    try std.testing.expect(!payload.isId("other_id"));
    try std.testing.expect(!payload.isId("wrong_id"));

    try std.testing.expectEqual(payload.getIssuedAt(), ts);

    const res = try payload.marshalJSON_PAYLOAD();
    defer allocator.free(res);

    std.debug.print("{s}\n", .{res});

    var unmarshal = try p.unmarshalJSON_custom(p.Payload, allocator, res);
    defer unmarshal.deinit();
    defer unmarshal.value.deinit();

    // std.debug.print("{any}\n", .{unmarshal.value});

    const resbase64 = payload.unmsarshalPayload() catch |err| return err;

    std.debug.print("{s}\n", .{resbase64});
    payload.free_base64url(resbase64);
}

const CustomFields = struct {
    user_type: []const u8,
};
//
test "custom payload test" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    //
    // defer {
    //     allocator.free(pl.jti);
    //     allocator.free(pl.iss);
    //     allocator.free(pl.sub);
    //     allocator.free(pl.aud);
    //     allocator..valuedestroy(pl);
    // }

    const customPayload = CustomFields{ .user_type = "admin" };
    var payload = p.CustomPayload(CustomFields).init(allocator, customPayload);
    defer payload.deinit();

    const json = try payload.marshalJSON_PAYLOAD();
    defer allocator.free(json);

    std.debug.print("{s}\n", .{json});
}

test "custom zero payload test" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();

    const customPayload = CustomFields{ .user_type = "user" };

    var payload = p.CustomPayload(CustomFields).init(allocator, customPayload);
    defer payload.deinit();

    const json = try payload.marshalJSON_PAYLOAD();
    defer allocator.free(json);
    std.debug.print("{s}\n", .{json});
}

const customSigma = struct {
    user_type: []const u8,
    admin: bool,
    die: u64,
};

test "custom zero payload test +u64 " {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const leaks = gpa.detectLeaks();
    std.debug.print("Leaks: {any}\n", .{leaks});

    const customPayload = customSigma{ .user_type = "user", .admin = false, .die = 0 };

    var payload = p.CustomPayload(customSigma).init(allocator, customPayload);
    defer payload.deinit();

    const json = try payload.marshalJSON_PAYLOAD();
    defer allocator.free(json);
    std.debug.print("{s}\n", .{json});
}

test "custom unmarshalJson test" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const leaks = gpa.detectLeaks();
    std.debug.print("Leaks: {any}\n", .{leaks});

    const customPayload = customSigma{ .user_type = "user", .admin = false, .die = 0 };

    var payload = p.CustomPayload(customSigma).init(allocator, customPayload);
    defer payload.deinit();

    const json = try payload.marshalJSON_PAYLOAD();
    defer allocator.free(json);

    const struct_unf = try p.unmarshalJSON_custom((p.CustomPayload(customSigma)), allocator, json);
    defer struct_unf.deinit();

    const json_2 = try struct_unf.value.marshalJSON_PAYLOAD();
    defer allocator.free(json_2);
    std.debug.print("{s}\n", .{json_2});
}
//
test "custom unmarshalJson to CustomPayload test" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    const allocator = gpa.allocator();
    defer _ = gpa.deinit();
    const leaks = gpa.detectLeaks();
    std.debug.print("Leaks: {any}\n", .{leaks});

    const customPayload = customSigma{ .user_type = "user", .admin = false, .die = 0 };

    var payload = p.CustomPayload(customSigma).init(allocator, customPayload);
    defer payload.deinit();

    const json = try payload.marshalJSON_PAYLOAD();
    defer allocator.free(json);

    var struct_unf = try p.unmarshalJSON_custom(p.CustomPayload(customSigma), allocator, json);
    defer struct_unf.deinit();

    const json_2 = try struct_unf.value.marshalJSON_PAYLOAD();
    defer allocator.free(json_2);

    std.debug.print("our hero: {s}\n", .{json_2});
}
