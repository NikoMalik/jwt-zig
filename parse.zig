const std = @import("std");
const Allocator = std.mem.Allocator;
const pl = @import("payload.zig");
const head = @import("header.zig");
const base64url = std.base64.url_safe_no_pad;
const jwt = @import("jwt.zig");

pub fn parseToken(allocator: Allocator, raw: []u8, signature: ?[]u8) !jwt.Token {
    if (!std.mem.startsWith(u8, raw, "eyJ")) {
        return error.InvalidToken;
    }

    const sep_header = std.mem.indexOf(u8, raw, ".") orelse return error.InvalidToken;
    const sep_payload = std.mem.lastIndexOf(u8, raw, ".") orelse return error.InvalidToken;
    if (sep_header == 0 or sep_payload <= sep_header) return error.InvalidToken;

    const headerEncoded = raw[0..sep_header];
    const payloadEncoded = raw[sep_header + 1 .. sep_payload];
    //header
    var header_buf = std.ArrayList(u8).init(allocator);
    defer header_buf.deinit();
    const headerDecodeSize = base64url.Decoder.calcSizeForSlice(headerEncoded) catch return error.InvalidToken;
    if (headerDecodeSize == 0) return error.InvalidToken;
    try header_buf.resize(headerDecodeSize);
    try base64url.Decoder.decode(header_buf.items, headerEncoded);
    const header_struct = try allocator.create(head.Header);
    header_struct.* = try head.unmarshalJSON_HEADER(allocator, header_buf.items);
    // payload
    var payload_buf = std.ArrayList(u8).init(allocator);
    defer payload_buf.deinit();
    const payloadDecodeSize = base64url.Decoder.calcSizeForSlice(payloadEncoded) catch return error.InvalidToken;
    if (payloadDecodeSize == 0) return error.InvalidToken;
    try payload_buf.resize(payloadDecodeSize);
    try base64url.Decoder.decode(payload_buf.items, payloadEncoded);
    const payload_struct = try allocator.create(pl.Payload);
    payload_struct.* = try pl.unmarshalJSON_PAYLOAD(allocator, payload_buf.items);

    var token = jwt.Token.init(allocator, header_struct, payload_struct);
    token.sep1 = sep_header;
    token.sep2 = sep_payload;
    token.raw = try allocator.dupe(u8, raw);

    if (signature) |s| {
        token.signature = try allocator.dupe(u8, s);
    }

    return token;
}
