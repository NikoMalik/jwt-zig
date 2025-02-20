# JWT Zig Library 🚀

![Github Repo Issues](https://img.shields.io/github/issues/NikoMalik/jwt-zig?style=flat) ![GitHub Repo stars](https://img.shields.io/github/stars/NikoMalik/jwt-zig?style=social)

A lightweight and performant JSON Web Token (JWT) library written in Zig. This library provides a simple, type-safe API for creating, signing, verifying, and parsing JWTs. It's designed to leverage Zig’s compile‐time safety and efficient memory management.

---

## Overview ✨

This library is built with simplicity and efficiency in mind. Whether you're building an API server or a command-line tool, our JWT library helps you manage token‐based authentication seamlessly with minimal overhead.


---

## Features 🔥


- **Token Creation & Signing:** Easily create tokens with customizable headers and payloads.
- **Verification:** Securely verify token signatures and check expiration dates.
- **Custom Payloads:** Support for both standard and custom payload structures.

- **Compile-time Safety:** Benefit from Zig’s compile-time type safety.
- **Efficient Memory Management:** Uses Zig’s allocator interface for optimal resource handling.


---

## Algorithms 🔑

| Supported | Algorithm     | Description |
|:---------:|---------------|-------------|

| ✅        | none          | No digital signature or MAC value included |
| ✅        | HS256         | HMAC using SHA-256 hash algorithm |
| ✅        | HS384         | HMAC using SHA-384 hash algorithm |
| ✅        | HS512         | HMAC using SHA-512 hash algorithm |
| ✅        | ES256         | ECDSA using P-256 curve and SHA-256 hash algorithm |
| ✅        | ES384         | ECDSA using P-384 curve and SHA-384 hash algorithm |
| ❌        | PS256         | RSASSA-PSS using SHA-256 hash algorithm |
| ❌        | ES512         | ECDSA using P-521 curve and SHA-512 hash algorithm |
| ❌        | PS384         | RSASSA-PSS using SHA-384 hash algorithm |
| ❌        | PS512         | RSASSA-PSS using SHA-512 hash algorithm |
| ❌        | RS256         | RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm |
| ❌        | RS384         | RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm |
| ❌        | RS512         | RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm |





## Installation 📦


`zig fetch --save https://github.com/NikoMalik/jwt-zig/archive/refs/tags/v0.5.0.tar.gz`

or


```zig
.dependencies = .{
    .jwt = .{
        .url = "https://github.com/NikoMalik/jwt-zig/archive/refs/tags/v0.5.0.tar.gz",
        //the correct hash will be suggested by zig
    }
}

```

# Installation/2 📦 


```bash

git clone https://github.com/NikoMalik/jwt-zig.git
mv jwt-zig /path/to/your/project/directory

```






---
# Usage 🛠


### Registered Payload

```



pub fn main() !void {
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const allocator = alloc.allocator();

    // Initialize header with kid value
    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.ES256, .{ .kid = "kid" });

    // Create standard payload
    const payload = p.Payload{
        .allocator = allocator,
        .jti = " boy",
        .iss = "iss",
        .sub = "trump",
    };

    // Create token from header and payload
    var jwtToken = jwt.Token(p.Payload).init(allocator, header, payload);
    defer jwtToken.deinit();

    // Load keys from PEM files
    var privPem = try jwt.keyFromFile(allocator, "private_key.pem");
    defer privPem.deinit();
    var publicPem = try jwt.keyFromFile(allocator, "public_key.pem");
    defer publicPem.deinit();


    var privateBytes: [32]u8 = undefined;
    @memcpy(&privateBytes, privPem.value.bytes);
    var publicBytes: [65]u8 = undefined;
    @memcpy(&publicBytes, publicPem.value.bytes);

    // Sign and verify token
    try jwtToken.sign(privateBytes[0..]); // or  signToken to get full copy jwt raw

    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    
    assert(verify);
}

```

---
### Custom Payload

```


const customPayload = struct {
    user_type: []const u8,
};

pub fn main() !void {
    
   
    var alloc = std.heap.GeneralPurposeAllocator(.{ .thread_safe = true }){};
    defer _ = alloc.deinit();
    const allocator = alloc.allocator();
    const leaks = alloc.detectLeaks();


    
  
    //header init
    const header = head.Header.init(allocator, typ.Type.JWT, typ.Algorithm.ES256, .{ .kid = "kid" });

    //payload init
    const payload = p.CustomPayload(customPayload).init(allocator, .{ .user_type = "admin" });
    var jwtToken = jwt.Token(p.CustomPayload(customPayload)).init(allocator, header, payload);
    defer jwtToken.deinit();

    var privPem = try jwt.keyFromFile(allocator, "private_key.pem");
    defer privPem.deinit();
    var publicPem = try jwt.keyFromFile(allocator, "public_key.pem");
    defer publicPem.deinit();
    std.debug.print("private len = {d}\n", .{privPem.value.bytes.len});
    std.debug.print("public len  = {d}\n", .{publicPem.value.bytes.len});

    var privateBytes: [32]u8 = undefined;
    @memcpy(&privateBytes, privPem.value.bytes);
    var publicBytes: [65]u8 = undefined;
    @memcpy(&publicBytes, publicPem.value.bytes);

    try jwtToken.sign(privateBytes[0..]);
    const verify = try jwtToken.verifyToken(publicBytes[0..]);
    std.debug.print("Verification: {any}\n", .{verify});
    std.debug.print("Token: {s}\n", .{jwtToken.raw.?});
    assert(verify);
}

```




---


# Parsing a Token 

```zig


const token = "eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCIsImN0eSI6ImpqIn0.eyJleHAiOjJ9.UAf2dBrW6aPhw9bOteeGqda9RGlqqKA4l9XRhK3Bg";

const custom = struct {
    user_type: []const u8,
};

pub fn main() void {


    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();




    var token = try parse.parseToken(pl.CustomPayload(customPayload), alloc,token, null);
    defer token.deinit();

    const heads = try token.header.marshalJSON();
    const payloads = try token.payload.marshalJSON_PAYLOAD();
    defer alloc.free(payloads);
    defer alloc.free(heads);
    assert(verify);


}
```





# Memory Management 🧠

This library uses Zig's allocator interface to manage memory. When using functions like allocator.dupe(), the allocated memory must be freed by calling the corresponding deinitialization method (e.g., deinit()). Always call deinit() on tokens and parsed objects when they're no longer needed to prevent memory leaks.


# Contributing 🤝

Contributions are welcome! Please fork the repository, open issues, or submit pull requests with your improvements or bug fixes. Follow the project's coding style and include tests for any changes.


# License 📜

This library is distributed under the [MIT License](https://opensource.org/licenses/MIT). You are free to use, modify, and distribute this library as per the terms of the license.

# Acknowledgements 🙌

- Inspired by various JWT libraries in different languages.
- Built using Zig’s modern, safe, and efficient design principles.




