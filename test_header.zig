const std = @import("std");
const head = @import("header.zig");
const typ = @import("algorithm.zig");

test "HeaderMarsh" {
    const alloc = std.heap.page_allocator;

    const h = head.Header.init(alloc, typ.Type.JWS, typ.Algorithm.EDDSA, .{});

    const marsh = try h.marshalJSON();
    std.debug.print("{s}\n", .{marsh});

    const unmarshall = try head.unmarshalJSON(alloc, marsh);

    std.debug.print("{any}\n", .{unmarshall});

    const resBase64 = h.unmarshalHeader() catch |err| return err;
    // _ = resBase64;

    std.debug.print("{s}\n", .{resBase64});
    h.allocator.free(resBase64);
}

test "Header Zero typ" {
    const alloc = std.heap.page_allocator;

    const h = head.Header.init(alloc, null, typ.Algorithm.EDDSA, .{});

    const marsh = try h.marshalJSON();
    std.debug.print("{s}\n", .{marsh});

    const unmarshall = try head.unmarshalJSON(alloc, marsh);

    std.debug.print("{any}\n", .{unmarshall});

    const resBase64 = h.unmarshalHeader() catch |err| return err;
    // _ = resBase64;
    //
    std.debug.print("{s}\n", .{resBase64});
    h.allocator.free(resBase64);
}
