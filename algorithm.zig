const std = @import("std");

const eddsa = std.crypto.sign.Ed25519;

//

pub const Algorithm = union(enum) {
    EDDSA,
    ES256,
    ES384,
    ES512,
    HS256,
    HS384,
    HS512,
    PS256,
    PS384,
    PS512,
    RS256,
    RS384,
    RS512,
    none,

    pub fn string(a: Algorithm) []const u8 {
        return switch (a) {
            .EDDSA => "EDDSA",
            .ES256 => "ES256",
            .ES384 => "ES384",
            .ES512 => "ES512",
            .HS256 => "HS256",
            .HS384 => "HS384",
            .HS512 => "HS512",
            .PS256 => "PS256",
            .PS384 => "PS384",
            .PS512 => "PS512",
            .RS256 => "RS256",
            .RS384 => "RS384",
            .RS512 => "RS512",
            .none => "none",
        };
    }

    pub fn toAlgo(n: []const u8) ?Algorithm {
        const lookup = [_]struct {
            tag: []const u8,
            value: Algorithm,
        }{
            .{ .tag = "EDDSA", .value = Algorithm.EDDSA },
            .{ .tag = "ES256", .value = Algorithm.ES256 },
            .{ .tag = "ES384", .value = Algorithm.ES384 },
            .{ .tag = "ES512", .value = Algorithm.ES512 },
            .{ .tag = "HS256", .value = Algorithm.HS256 },
            .{ .tag = "HS384", .value = Algorithm.HS384 },
            .{ .tag = "HS512", .value = Algorithm.HS512 },
            .{ .tag = "PS256", .value = Algorithm.PS256 },
            .{ .tag = "PS384", .value = Algorithm.PS384 },
            .{ .tag = "PS512", .value = Algorithm.PS512 },
            .{ .tag = "RS256", .value = Algorithm.RS256 },
            .{ .tag = "RS384", .value = Algorithm.RS384 },
            .{ .tag = "RS512", .value = Algorithm.RS512 },
            .{ .tag = "none", .value = Algorithm.none },
        };
        for (lookup) |e| {
            if (std.mem.eql(u8, n, e.tag)) {
                return e.value;
            }
        }

        return null;
    }
};

pub const Type = union(enum) {
    JWT,
    JWS,

    pub fn string(t: Type) []const u8 {
        return switch (t) {
            .JWT => "JWT",
            .JWS => "JWS",
        };
    }

    pub fn toType(n: []const u8) ?Type {
        const lookup = [_]struct {
            tag: []const u8,
            value: Type,
        }{
            .{ .tag = "JWT", .value = Type.JWT },
            .{ .tag = "JWS", .value = Type.JWS },
        };

        for (lookup) |entry| {
            if (std.mem.eql(u8, n, entry.tag)) {
                return entry.value;
            }
        }
        return null;
    }
};
