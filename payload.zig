const std = @import("std");
const date = @import("time.zig");
const Allocator = std.mem.Allocator;
const base64url = std.base64.url_safe_no_pad;
const head = @import("header.zig");
const algo = @import("algorithm.zig");

var count: usize = 0;
var count2: usize = 0;
var unmarshal: bool = false;

pub fn CustomPayload(comptime ExtraFields: type) type {
    return struct {
        const Self = @This();
        allocator: Allocator,

        extra: ExtraFields,

        pub fn init(allocator: Allocator, extra: ExtraFields) Self {
            return .{
                .allocator = allocator,
                .extra = extra,
            };
        }
        pub fn deinit(self: *Self) void {
            _ = self;
        }

        fn extraset(self: *Self) void {
            _ = self;
        }
        pub fn marshalJSON_PAYLOAD(self: Self) ![]const u8 {
            var js = std.ArrayList(u8).init(self.allocator);
            defer js.deinit();
            var writer = js.writer();

            try writer.writeAll("{");

            var first: bool = true;
            inline for (std.meta.fields(ExtraFields)) |f| {
                if (@TypeOf(@field(self.extra, f.name)) == []const u8) {
                    if (!first) {
                        try writer.writeAll(",");
                    }
                    first = false;
                    try writer.writeAll("\"");
                    try writer.writeAll(f.name);
                    try writer.writeAll("\":\"");
                    try writer.writeAll(@field(self.extra, f.name));
                    try writer.writeAll("\"");
                }
                if (@TypeOf(@field(self.extra, f.name)) == bool) {
                    if (!first) {
                        try writer.writeAll(",");
                    }
                    first = false;
                    try writer.writeAll("\"");
                    try writer.writeAll(f.name);
                    try writer.writeAll("\":");
                    try writer.print("{any}", .{@field(self.extra, f.name)});
                }
                if (@TypeOf(@field(self.extra, f.name)) == u64) {
                    if (!first) {
                        try writer.writeAll(",");
                    }
                    first = false;
                    try writer.writeAll("\"");
                    try writer.writeAll(f.name);
                    try writer.writeAll("\":");
                    try writer.print("{d}", .{@field(self.extra, f.name)});
                }
                if (@TypeOf(@field(self.extra, f.name)) == f64) {
                    if (!first) {
                        try writer.writeAll(",");
                    }
                    first = false;
                    try writer.writeAll("\"");
                    try writer.writeAll(f.name);
                    try writer.writeAll("\":");
                    try writer.print("{d}", .{@field(self.extra, f.name)});
                }
            }

            try writer.writeAll("}");

            return js.toOwnedSlice();
        }
        pub fn unmarshalPayload(self: *Self) ![]const u8 {
            const info = try self.marshalJSON();
            defer self.allocator.free(info);

            const encodedLen = base64url.Encoder.calcSize(info.len);
            const dest = try self.allocator.alloc(u8, encodedLen);

            return base64url.Encoder.encode(dest, info);
        }

        pub fn free_base64url(self: *@This(), dest: []const u8) void {
            if (count2 > 0) {
                self.allocator.free(dest);
                count2 -= 1;
            }
        }
    };
}

//Free this slice
pub fn unmarshalPaylod_custom(T: anytype) ![]const u8 {
    const info = try T.marshalJSON_PAYLOAD();
    defer T.allocator.free(info);

    const encodedLen = base64url.Encoder.calcSize(info.len);

    const dest = try T.allocator.alloc(u8, encodedLen);
    return base64url.Encoder.encode(dest, info);
}
pub fn unmarshalJSON_custom(comptime T: type, allocator: Allocator, json: []const u8) !std.json.Parsed(T) {
    if (T == Payload) {
        const parsed = try std.json.parseFromSlice(struct {
            jti: ?[]const u8 = null,
            iss: ?[]const u8 = null,
            sub: ?[]const u8 = null,
            aud: ?[]const u8 = null,

            exp: ?u64 = null,
            nbf: ?u64 = null,
            iat: ?u64 = null,
        }, allocator, json, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
        errdefer parsed.deinit();

        const payload = Payload{
            .allocator = allocator,
            .jti = if (parsed.value.jti) |j| try allocator.dupe(u8, j) else null,
            .iss = if (parsed.value.iss) |i| try allocator.dupe(u8, i) else null,
            .sub = if (parsed.value.sub) |s| try allocator.dupe(u8, s) else null,

            .aud = if (parsed.value.aud) |a| try allocator.dupe(u8, a) else null,
            .exp = if (parsed.value.exp) |e| date.NumericDate.init(allocator, e) else null,
            .nbf = if (parsed.value.nbf) |n| date.NumericDate.init(allocator, n) else null,
            .iat = if (parsed.value.iat) |i| date.NumericDate.init(allocator, i) else null,
        };

        return .{
            .value = payload,
            .arena = parsed.arena,
        };
    }

    if (T == head.Header) {
        const parsed = try std.json.parseFromSlice(struct {
            alg: ?[]const u8 = null,
            typ: ?[]const u8 = null,
            kid: ?[]const u8 = null,
            cty: ?[]const u8 = null,
        }, allocator, json, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
        const typ = if (parsed.value.typ) |t| algo.Type.toType(t) else null;
        const alg = if (parsed.value.alg) |a| algo.Algorithm.toAlgo(a) else null;
        var sigOpts: ?head.SignatureOptions = null;
        if (parsed.value.kid != null or parsed.value.cty != null) {
            sigOpts = head.SignatureOptions{
                .kid = parsed.value.kid,
                .cty = parsed.value.cty,
            };
        }

        return .{
            .value = head.Header{
                .allocator = allocator,
                .alg = alg.?,
                .typ = typ.?,
                .options = sigOpts orelse .{},
            },
            .arena = parsed.arena,
        };
    }

    const ExtraType = blk: {
        const fields = std.meta.fields(T);
        inline for (fields) |f| {
            if (f.type != std.mem.Allocator) {
                break :blk f.type;
            }
        }
        @compileError("No extra field found");
    };

    const parsed = try std.json.parseFromSlice(ExtraType, allocator, json, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();
    return .{
        .value = T{
            .allocator = allocator,
            .extra = parsed.value,
        },
        .arena = parsed.arena,
    };
}

//debug features
fn printFields(comptime T: type) void {
    const info = @typeInfo(T);

    inline for (info.@"struct".fields) |field| {
        std.debug.print("Field: {s}\n", .{field.name});
        // std.debug.print("Types: {any}", .{field.type});
    }
}

pub const Payload = struct {
    allocator: Allocator,

    iss: ?[]const u8 = null,
    jti: ?[]const u8 = null,
    sub: ?[]const u8 = null,
    aud: ?[]const u8 = null,
    exp: ?date.NumericDate = null,
    nbf: ?date.NumericDate = null,
    iat: ?date.NumericDate = null,

    pub fn deinit(p: *Payload) void {
        if (p.jti) |j| {
            // if (unmarshal) {
            // unmarshal = false;
            p.allocator.free(j);
            // }
        }
        if (p.iss) |i| {
            // if (unmarshal) {
            p.allocator.free(i);
            // }
        }
        if (p.sub) |s| {
            // if (unmarshal) {
            p.allocator.free(s);
            // }
        }
        if (p.aud) |a| {
            // if (unmarshal) {
            p.allocator.free(a);
            // }
        }
    }

    pub fn getIssuer(p: *const Payload) ?[]const u8 {
        if (p.iss != null) {
            return p.iss.?;
        }
        return null;
    }

    pub fn getSubject(p: *const Payload) ?[]const u8 {
        if (p.sub != null) {
            return p.sub.?;
        }

        return null;
    }

    pub fn getAudience(p: *const Payload) ?[]const u8 {
        if (p.aud != null) {
            return p.aud.?;
        }
        return null;
    }

    pub fn getExpirationTime(p: *const Payload) ?u64 {
        if (p.exp != null) {
            return p.exp.?.time;
        }
        return null;
    }

    pub fn getNotBefore(p: *const Payload) ?u64 {
        if (p.nbf != null) {
            return p.nbf.?.time;
        }
        return null;
    }

    pub fn isId(p: *const Payload, id: []const u8) bool {
        if (p.jti != null) {
            return constTimeEqual(p.jti.?, id);
        }
        return false;
    }

    pub fn getIssuedAt(p: *const Payload) ?u64 {
        if (p.iat != null) {
            return p.iat.?.time;
        }

        return null;
    }

    pub fn isvalidnotbefore(p: *const Payload, now: u64) bool {
        if (p.nbf != null) {
            return p.nbf.?.time < now;
        }
        return true;
    }

    pub fn isvalidissuedat(p: *const Payload, now: u64) bool {
        if (p.iat != null) {
            return p.iat.?.time < now;
        }
        return true;
    }

    pub fn hasaudience(p: *const Payload, aud: []const u8) bool {
        if (p.aud != null) {
            return constTimeEqual(p.aud.?, aud);
        }
        return false;
    }

    pub fn isvalidExpirationTime(p: *const Payload, now: u64) bool {
        if (p.exp != null) {
            return p.exp.?.time > now;
        }
        return true;
    }

    pub fn isExpired(p: *const Payload, now: u64) bool {
        if (p.exp != null) {
            return p.exp.?.time < now;
        }
        return false;
    }

    pub fn isSubject(p: *const Payload, sub: []const u8) bool {
        if (p.sub != null) {
            return constTimeEqual(p.sub.?, sub);
        }
        return false;
    }

    pub fn isIssuer(p: *const Payload, iss: []const u8) bool {
        if (p.iss != null) {
            return constTimeEqual(p.iss.?, iss);
        }
        return false;
    }

    pub fn marshalJSON_PAYLOAD(p: Payload) ![]const u8 {
        var js = std.ArrayList(u8).init(p.allocator);
        defer js.deinit();
        var writer = js.writer();

        try writer.writeAll("{");

        var first: bool = true;

        if (p.jti != null) {
            if (!first) {
                try writer.writeAll(",");
            }
            first = false;
            try writer.writeAll("\"jti\":\"");
            try writer.writeAll(p.jti.?);
            try writer.writeAll("\"");
        }

        if (p.iss != null) {
            if (!first) {
                try writer.writeAll(",");
            }
            first = false;
            try writer.writeAll("\"iss\":\"");
            try writer.writeAll(p.iss.?);
            try writer.writeAll("\"");
        }

        if (p.sub != null) {
            if (!first) {
                try writer.writeAll(",");
            }
            first = false;
            try writer.writeAll("\"sub\":\"");
            try writer.writeAll(p.sub.?);
            try writer.writeAll("\"");
        }

        if (p.aud != null) {
            if (!first) {
                try writer.writeAll(",");
            }
            first = false;
            try writer.writeAll("\"aud\":\"");
            try writer.writeAll(p.aud.?);
            try writer.writeAll("\"");
        }

        if (p.exp != null) {
            if (!first) {
                try writer.writeAll(",");
            }
            first = false;
            try writer.writeAll("\"exp\":");
            try writer.print("{d}", .{p.exp.?.time});
        }

        if (p.nbf != null) {
            if (!first) {
                try writer.writeAll(",");
            }
            first = false;
            try writer.writeAll("\"nbf\":");
            try writer.print("{d}", .{p.nbf.?.time});
        }

        if (p.iat != null) {
            if (!first) {
                try writer.writeAll(",");
            }
            first = false;
            try writer.writeAll("\"iat\":");
            try writer.print("{d}", .{p.iat.?.time});
        }

        try writer.writeAll("}");
        return js.toOwnedSlice();
    }

    pub fn unmsarshalPayload(p: *const Payload) ![]const u8 {
        const info = p.marshalJSON_PAYLOAD() catch "";
        defer p.allocator.free(info);

        const encodedLen = base64url.Encoder.calcSize(info.len);

        const dest = try p.allocator.alloc(u8, encodedLen);

        const payload_base64 = base64url.Encoder.encode(dest, info);
        count += 1;
        return payload_base64;
    }

    pub fn free_base64url(p: *const Payload, dest: []const u8) void {
        if (count > 0) {
            p.allocator.free(dest);
            count -= 1;
        }
    }
};
//
pub fn unmarshalJSON_PAYLOAD(allocator: Allocator, js: []const u8) !Payload {
    const PayloadJson = struct {
        jti: ?[]const u8 = null,
        iss: ?[]const u8 = null,
        sub: ?[]const u8 = null,
        aud: ?[]const u8 = null,
        exp: ?u64 = null,
        nbf: ?u64 = null,
        iat: ?u64 = null,
    };

    var parsed = try std.json.parseFromSlice(PayloadJson, allocator, js, .{
        .ignore_unknown_fields = true,
    });

    defer parsed.deinit();

    var iaat: ?date.NumericDate = null;
    if (parsed.value.iat) |iat_val| {
        iaat = date.NumericDate.init(allocator, iat_val);
    }

    var exp: ?date.NumericDate = null;
    if (parsed.value.exp) |exp_val| {
        exp = date.NumericDate.init(allocator, exp_val);
    }

    var nbf: ?date.NumericDate = null;
    if (parsed.value.nbf) |nbf_val| {
        nbf = date.NumericDate.init(allocator, nbf_val);
    }

    var jti: ?[]const u8 = null;
    if (parsed.value.jti) |jti_val| {
        jti = try allocator.dupe(u8, jti_val);
    }

    var sub: ?[]const u8 = null;
    if (parsed.value.sub) |sub_val| {
        sub = try allocator.dupe(u8, sub_val);
    }

    var iss: ?[]const u8 = null;
    if (parsed.value.iss) |iss_val| {
        iss = try allocator.dupe(u8, iss_val);
    }

    var aud: ?[]const u8 = null;
    if (parsed.value.aud) |aud_val| {
        aud = try allocator.dupe(u8, aud_val);
    }

    return Payload{
        .allocator = allocator,
        .jti = jti,
        .iss = iss,
        .sub = sub,
        .aud = aud,
        .exp = exp,
        .nbf = nbf,
        .iat = iaat,
    };
}

pub fn constTimeEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) {
        return false;
    }

    return constantTimeCompare(a, b) == 1;
}

inline fn constantTimeCompare(a: []const u8, b: []const u8) usize {
    if (a.len != b.len) {
        return 0;
    }

    var v: u8 = 0;
    var i: usize = 0;

    while (i < a.len) : (i += 1) {
        v |= a[i] ^ b[i];
    }

    return constantTimeByteEq(v, 0);
}

inline fn constantTimeByteEq(x: u8, y: u8) u8 {
    const xor = x ^ y;
    return @intFromBool(xor == 0);
}

// {
//   "Issuer": "example.com",
//   "Subject": "user123",
//   "Audience": ["admin", "co-admin"],
//   "ExpirationTime": "2024-12-01T00:00:00Z",
//   "NotBefore": "2024-11-01T00:00:00Z",
//   "IssuedAt": "2024-11-30T12:00:00Z"
// }
