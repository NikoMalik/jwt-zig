const std = @import("std");
const Allocator = std.mem.Allocator;
const pl = @import("payload.zig");
const head = @import("header.zig");
const base64url = std.base64.url_safe_no_pad;
const jwt = @import("jwt.zig");

pub fn parseToken(comptime typ: type, allocator: Allocator, raw: []const u8, signature: ?[]u8) !jwt.Token(typ) {
    if (std.mem.count(u8, raw, ".") != 2) return error.InvalidTokenFormat;

    var iter = std.mem.splitSequence(u8, raw, ".");
    const header_b64 = iter.first();
    const payload_b64 = iter.next() orelse return error.InvalidTokenFormat;

    const header_parsed = try decodeComponent(allocator, header_b64, head.Header);
    // defer header_parsed.deinit();

    const payload_parsed = try decodeComponent(allocator, payload_b64, typ);

    var token = jwt.Token(typ).allocParsed(allocator, header_parsed, payload_parsed);

    token.raw = try allocator.dupe(u8, raw);
    if (signature) |sig| token.signature = try allocator.dupe(u8, sig);
    token.sep1 = header_b64.len;
    token.sep2 = header_b64.len + 1 + payload_b64.len;

    return token;
}

inline fn decodeComponent(allocator: Allocator, b64_data: []const u8, comptime T: type) !std.json.Parsed(T) {
    const decoded_size = base64url.Decoder.calcSizeForSlice(b64_data) catch 0;
    if (decoded_size == 0) return error.InvalidEncoding;

    const buffer = try allocator.alloc(u8, decoded_size);
    defer allocator.free(buffer);

    try base64url.Decoder.decode(buffer, b64_data);

    return try pl.unmarshalJSON_custom(T, allocator, buffer);
}
