const std = @import("std");
const time = @This();
const Allocator = std.mem.Allocator;

const since1970 = std.time.epoch.EpochDay;

//A JSON numeric value representing the number of seconds from
//      1970-01-01T00:00:00Z UTC until the specified UTC date/time,
//      ignoring leap seconds.  This is equivalent to the IEEE Std 1003.1,
//      2013 Edition [POSIX.1] - https://datatracker.ietf.org/doc/html/rfc7519#ref-POSIX.1

pub const NumericDate = struct {
    allocator: Allocator,
    time: u64,
    //
    pub fn init(alloc: Allocator, tm: u64) NumericDate {
        return NumericDate{
            .allocator = alloc,
            .time = tm,
        };
    }

    pub fn string(n: *NumericDate) ![]const u8 {
        var list = std.ArrayList(u8).init(n.allocator);
        defer list.deinit();

        try list.writer().print("{d}", .{n.time});

        return list.toOwnedSlice();
    }

    pub fn unmarshalJSON(n: *NumericDate, json: []const u8) !void {
        const unixTime = try std.fmt.parseInt(u64, json, 10);
        n.time = unixTime;
    }
};
