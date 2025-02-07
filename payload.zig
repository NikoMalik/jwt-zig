const std = @import("std");
const date = @import("time.zig");
const Allocator = std.mem.Allocator;
const base64url = std.base64.url_safe_no_pad;

var count: usize = 0;

pub const Payload = struct {
    allocator: Allocator,
    jti: ?[]const u8 = null,
    iss: ?[]const u8 = null,
    sub: ?[]const u8 = null,
    aud: ?[]const u8 = null,
    exp: ?date.NumericDate = null,
    nbf: ?date.NumericDate = null,
    iat: ?date.NumericDate = null,

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

    pub fn marshalJSON_PAYLOAD(p: *const Payload) ![]const u8 {
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

    return Payload{
        .allocator = allocator,
        .jti = if (parsed.value.jti) |jti| jti else null,
        .iss = if (parsed.value.iss) |iss| iss else null,
        .sub = if (parsed.value.sub) |sub| sub else null,
        .aud = if (parsed.value.aud) |aud| aud else null,
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
