const std = @import("std");
// const json = std.json;
const algo = @import("algorithm.zig");
const base64url = std.base64.url_safe_no_pad;
const Allocator = std.mem.Allocator;

var count_free: usize = 0;

pub const Header = struct {
    allocator: Allocator,

    typ: algo.Type,
    alg: algo.Algorithm,
    options: SignatureOptions,

    pub fn init(alloc: Allocator, typ: algo.Type, alg: algo.Algorithm, options: SignatureOptions) Header {
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
        try writer.writeAll(h.alg.string());
        try writer.writeAll("\"");

        try writer.writeAll(",\"typ\":\"");
        try writer.writeAll(h.typ.string());
        try writer.writeAll("\"");

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
        if (h.typ == .JWT and h.alg == .EDDSA and h.options.cty == null and h.options.kid == null) {
            if (getAllocatedHeader(h.alg, h.typ)) |prealloc| {
                return prealloc;
            }
        }

        const info = try h.marshalJSON();
        defer h.allocator.free(info);

        // CALCULATING SAFETY LEN FOR BASE64URL
        const encodedLen = base64url.Encoder.calcSize(info.len);

        // BUFFER FOR RESULT
        const dest = try h.allocator.alloc(u8, encodedLen);
        // defer headerCopy.allocator.free(dest);

        // ENCODING
        const header_base64 = base64url.Encoder.encode(dest, info);
        count_free += 1;
        //RETURN RESULT
        return header_base64;
    }

    pub fn free_Base64URL(h: *const Header, dest: []const u8) void {
        if (count_free > 0) {
            h.allocator.free(dest);
            count_free -= 1;
        }
    }
};

pub const SignatureOptions = struct {
    kid: ?[]const u8 = null,
    cty: ?[]const u8 = null,
};

const HeaderJSON = struct {
    alg: ?[]const u8 = null,
    typ: ?[]const u8 = null,
    kid: ?[]const u8 = null,
    cty: ?[]const u8 = null,
};

pub fn unmarshalJSON_HEADER(allocator: Allocator, json: []const u8) !Header {
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

    const typ = if (parsed.value.typ) |t| algo.Type.toType(t) else null;
    const alg = if (parsed.value.alg) |a| algo.Algorithm.toAlgo(a) else null;

    return Header.init(
        allocator,
        typ.?,
        alg.?, //make hint to make arguments on each line
        sigOpts orelse .{},
    );
}

pub const allocatedHeaders = struct {
    pub const EDDSA = "eyJhbGciOiJFRERTQSIsInR5cCI6IkpXVCJ9";
};

pub fn getAllocatedHeader(alg: algo.Algorithm, typ: algo.Type) ?[]const u8 {
    return switch (alg) {
        .EDDSA => switch (typ) {
            .JWT => allocatedHeaders.EDDSA,
            else => null,
        },
        else => null,
    };
}
