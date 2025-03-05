#!/usr/bin/env sh
set -eu

ZIG_RELEASE_DEFAULT="0.14.0"

# Default to the release build, or allow the latest dev build, or an explicit release version:
ZIG_RELEASE=${1:-$ZIG_RELEASE_DEFAULT}

[ "$ZIG_RELEASE" = "latest" ] && ZIG_RELEASE="master"


# Validate the release version explicitly:

if echo "$ZIG_RELEASE" | grep -q '^master$'; then
    echo "Downloading Zig latest build..."
elif echo "$ZIG_RELEASE" | grep -q '^[0-9]\+\.[0-9]\+\.[0-9]\+$'; then
    echo "Downloading Zig $ZIG_RELEASE release build..."
else
    echo "Release version invalid"
    exit 1
fi

# Determine the architecture:
ZIG_ARCH="x86_64"
[ "$(uname -m)" = 'arm64' ] || [ "$(uname -m)" = 'aarch64' ] && ZIG_ARCH="aarch64"

# Determine the operating system:
case "$(uname)" in
    Linux) ZIG_OS="linux" ;;
    Darwin) ZIG_OS="macos" ;;

    CYGWIN*) ZIG_OS="windows" ;;
    *) echo "Unknown OS"; exit 1 ;;

esac

ZIG_TARGET="zig-${ZIG_OS}-${ZIG_ARCH}"

# Get download URL with proper JSON parsing
if command -v wget >/dev/null; then
    ipv4=$([ -f /etc/alpine-release ] || echo "-4")
    ZIG_URL=$(wget $ipv4 -qO - https://ziglang.org/download/index.json | 
              grep -F "\"$ZIG_TARGET\"" -A 2 | 
              grep -F "\"$ZIG_RELEASE\"" -A 1 |
              awk -F'"' '/tarball/{print $4}')
else
    ZIG_URL=$(curl -s https://ziglang.org/download/index.json | 
              grep -F "\"$ZIG_TARGET\"" -A 2 | 
              grep -F "\"$ZIG_RELEASE\"" -A 1 |

              awk -F'"' '/tarball/{print $4}')
fi

# Clean URL from potential newline characters
ZIG_URL=$(printf "%s" "$ZIG_URL" | tr -d '\r\n')

[ -z "$ZIG_URL" ] && { echo "Release not found"; exit 1; }


ZIG_ARCHIVE=$(basename "$ZIG_URL")
ZIG_DIRECTORY="${ZIG_ARCHIVE%.tar.xz}"
ZIG_DIRECTORY="${ZIG_DIRECTORY%.zip}"

echo "Downloading $ZIG_URL..."
if command -v wget >/dev/null; then
    ipv4=$([ -f /etc/alpine-release ] || echo "-4")
    wget $ipv4 -q --show-progress -O "$ZIG_ARCHIVE" "$ZIG_URL"
else
    curl -# -o "$ZIG_ARCHIVE" "$ZIG_URL"

fi


echo "Extracting $ZIG_ARCHIVE..."
case "$ZIG_ARCHIVE" in
    *.tar.xz) tar -xf "$ZIG_ARCHIVE" ;;
    *.zip) unzip -q "$ZIG_ARCHIVE" ;;
    *) echo "Unknown archive format"; exit 1 ;;
esac

rm "$ZIG_ARCHIVE"
rm -rf zig/doc zig/lib

mv -f "$ZIG_DIRECTORY"/{LICENSE,README.md,doc,lib,zig} zig/
rmdir "$ZIG_DIRECTORY"

echo "Downloading completed! Zig available at: $(pwd)/zig/zig"
