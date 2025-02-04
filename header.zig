const std = @import("std");
// const json = std.json;
const algo = @import("algorithm.zig");
const base64url = std.base64.url_safe_no_pad;

pub const Header = struct {
    allocator: std.mem.Allocator,

    typ: ?algo.Type,
    alg: ?algo.Algorithm,
    options: SignatureOptions,

    pub fn init(alloc: std.mem.Allocator, typ: ?algo.Type, alg: ?algo.Algorithm, options: SignatureOptions) Header {
        return Header{
            .options = options,
            .typ = typ,
            .alg = alg,
            .allocator = alloc,
        };
    }

    pub fn marshalJSON(h: *const Header) ![]const u8 {
        var js = std.ArrayList(u8).init(h.allocator);
        defer js.deinit();
        var writer = js.writer();

        try writer.writeAll("{");

        try writer.writeAll("\"alg\":\"");
        try writer.writeAll(h.alg.?.string());
        try writer.writeAll("\"");

        if (h.typ) |typ| {
            try writer.writeAll(",\"typ\":\"");
            try writer.writeAll(typ.string());
            try writer.writeAll("\"");
        } else {
            try writer.writeAll(",\"typ\":\"JWT\"");
        }

        if (h.options.cty) |cty| {
            try writer.writeAll(",\"cty\":\"");
            try writer.writeAll(cty);
            try writer.writeAll("\"");
        }

        if (h.options.kid) |kid| {
            try writer.writeAll(",\"kid\":\"");
            try writer.writeAll(kid);
            try writer.writeAll("\"");
        }

        try writer.writeAll("}");

        return js.toOwnedSlice();
    }

    pub fn unmarshalHeader(h: *const Header) ![]const u8 {
        // JSON PRESENTATION IN STRING
        const info = h.marshalJSON() catch "";

        // CALCULATING SAFETY LEN FOR BASE64URL
        const encodedLen = base64url.Encoder.calcSize(info.len);

        // BUFFER FOR RESULT
        const dest = try h.allocator.alloc(u8, encodedLen);
        // defer headerCopy.allocator.free(dest);

        // ENCODING
        const header_base64 = base64url.Encoder.encode(dest, info);
        //RETURN RESULT
        return header_base64;
    }
};

pub const SignatureOptions = struct {
    duplicate_field_behavior: enum {
        use_first,
        @"error",
        use_last,
    } = .@"error",
    kid: ?[]const u8 = null,
    cty: ?[]const u8 = null,
};

const HeaderJSON = struct {
    alg: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    kid: ?[]const u8 = null,
    cty: ?[]const u8 = null,
};

pub fn unmarshalJSON(allocator: std.mem.Allocator, json: []const u8) !Header {
    var parsed = try std.json.parseFromSlice(HeaderJSON, allocator, json, .{
        .ignore_unknown_fields = true,
    });

    defer parsed.deinit();
    var sigOpts: ?SignatureOptions = null;
    if (parsed.value.kid != null or parsed.value.cty != null) {
        sigOpts = SignatureOptions{
            .duplicate_field_behavior = .use_first,
            .kid = parsed.value.kid,
            .cty = parsed.value.cty,
        };
    }

    return Header.init(
        allocator,
        if (parsed.value.typ) |t| algo.Type.toType(t) else null,
        if (parsed.value.alg) |a| algo.Algorithm.toAlgo(a) else null, //make hint to make arguments on each line
        sigOpts orelse .{},
    );
}
