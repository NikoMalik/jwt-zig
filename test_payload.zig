const std = @import("std");
const date = @import("time.zig");
const p = @import("payload.zig");

test "Payload tests" {
    const allocator = std.heap.page_allocator;

    const nd = date.NumericDate.init(allocator, 1700000000);

    const ts = @as(u64, @intCast(std.time.timestamp()));

    const iat = date.NumericDate.init(allocator, ts);

    const payload = p.Payload{
        .allocator = allocator,
        .jti = "test_id",
        .iss = "issuer.com",
        .sub = "subject",
        .aud = "audience",
        .exp = nd,
        .nbf = null,
        .iat = iat,
    };

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

    std.debug.print("{s}\n", .{res});

    const unmarshal = try p.unmarshalJSON_PAYLOAD(allocator, res);

    std.debug.print("{any}\n", .{unmarshal});

    const resbase64 = payload.unmsarshalPayload() catch |err| return err;

    std.debug.print("{s}\n", .{resbase64});
    payload.free_base64url(resbase64);
}
