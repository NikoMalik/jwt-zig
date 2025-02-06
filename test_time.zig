const std = @import("std");
const time = @import("time.zig");

test "NumericDate tests" {
    const allocator = std.heap.page_allocator;

    const ts = @as(u64, @intCast(std.time.timestamp()));

    var nd_before = time.NumericDate.init(allocator, ts);
    const format = nd_before.string() catch |err| return err;
    std.debug.print("{d} get unix\n", .{nd_before.time});
    std.debug.print("{d} timestamp\n", .{ts});
    std.debug.print("{s}\n", .{format});
    try std.testing.expectEqual(nd_before.time, ts);

    const nd_exact = time.NumericDate.init(allocator, ts);
    try std.testing.expectEqual(nd_exact.time, ts);
}
