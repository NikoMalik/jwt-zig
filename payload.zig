const std = @import("std");
const date = @import("time.zig");

pub const Payload = struct {
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
            return p.exp.?;
        }
        return null;
    }

    pub fn getNotBefore(p: *const Payload) ?u64 {
        if (p.nbf != null) {
            return p.nbf.?;
        }
        return null;
    }
};

// {
//   "Issuer": "example.com",
//   "Subject": "user123",
//   "Audience": ["admin", "co-admin"],
//   "ExpirationTime": "2024-12-01T00:00:00Z",
//   "NotBefore": "2024-11-01T00:00:00Z",
//   "IssuedAt": "2024-11-30T12:00:00Z"
// }
