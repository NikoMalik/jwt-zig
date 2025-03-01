#!/usr/bin/env sh
set -eu


ZIG_RELEASE="0.14.0-dev.2851+b074fb7dd"
ZIG_TARBALL="zig-linux-x86_64-$ZIG_RELEASE.tar.xz" 

ZIG_URL="https://ziglang.org/builds/$ZIG_TARBALL"

echo "Downloading Zig $ZIG_RELEASE..."
echo "URL: $ZIG_URL"


if command -v wget > /dev/null; then
    wget -4 --quiet "$ZIG_URL"

else
    curl --silent --output "$ZIG_TARBALL" "$ZIG_URL"
fi


echo "Extracting $ZIG_TARBALL..."
tar -xf "$ZIG_TARBALL"
rm "$ZIG_TARBALL"


ZIG_DIR="zig-linux-x86_64-$ZIG_RELEASE"  
rm -rf zig/doc zig/lib
mv "$ZIG_DIR/LICENSE" zig/
mv "$ZIG_DIR/README.md" zig/
mv "$ZIG_DIR/doc" zig/

mv "$ZIG_DIR/lib" zig/
mv "$ZIG_DIR/zig" zig/
rmdir "$ZIG_DIR"

echo "Zig $ZIG_RELEASE installed to $(pwd)/zig"
