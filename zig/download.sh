#!/usr/bin/env sh
set -eu

ZIG_RELEASE_DEFAULT="0.14.0"


# Default to the release build, or allow the latest dev build, or an explicit release version:
ZIG_RELEASE=${1:-$ZIG_RELEASE_DEFAULT}

if [ "$ZIG_RELEASE" = "latest" ]; then
    ZIG_RELEASE="builds"
fi

# Validate the release version explicitly:
if echo "$ZIG_RELEASE" | grep -q '^builds$'; then
    echo "Downloading Zig latest build..."
elif echo "$ZIG_RELEASE" | grep -q '^[0-9]\+\.[0-9]\+\.[0-9]\+$'; then
    echo "Downloading Zig $ZIG_RELEASE release build..."
else
    echo "Release version invalid"
    exit 1
fi

# Determine the architecture:
if [ "$(uname -m)" = 'arm64' ] || [ "$(uname -m)" = 'aarch64' ]; then

    ZIG_ARCH="aarch64"
else
    ZIG_ARCH="x86_64"
fi

# Determine the operating system:
case "$(uname)" in
    Linux)
        ZIG_OS="linux"
        ;;
    Darwin)
        ZIG_OS="macos"
        ;;
    CYGWIN*)
        ZIG_OS="windows"
        ;;

    *)
        echo "Unknown OS"
        exit 1
        ;;
esac

ZIG_TARGET="zig-$ZIG_OS-$ZIG_ARCH"


# Determine the build, ensuring the server sends uncompressed data:
if command -v wget > /dev/null; then
    ipv4="-4"
    if [ -f /etc/alpine-release ]; then
        ipv4=""
    fi
    ZIG_URL=$(wget $ipv4 --header='Accept-Encoding: identity' --quiet -O - https://ziglang.org/download/index.json | grep -F "$ZIG_TARGET" | grep -F "$ZIG_RELEASE" | awk '{print $2}' | sed 's/[",]//g')
else
    ZIG_URL=$(curl -H 'Accept-Encoding: identity' --silent https://ziglang.org/download/index.json | grep -F "$ZIG_TARGET" | grep -F "$ZIG_RELEASE" | awk '{print $2}' | sed 's/[",]//g')
fi

# Ensure the release exists:
if [ -z "$ZIG_URL" ]; then
    echo "Release not found on ziglang.org"
    exit 1
fi

ZIG_ARCHIVE=$(basename "$ZIG_URL")

case "$ZIG_ARCHIVE" in
    *".tar.xz")
        ZIG_ARCHIVE_EXT=".tar.xz"
        ;;

    *".zip")
        ZIG_ARCHIVE_EXT=".zip"
        ;;
    *)
        echo "Unknown archive extension"
        exit 1
        ;;
esac


ZIG_DIRECTORY=$(basename "$ZIG_ARCHIVE" "$ZIG_ARCHIVE_EXT")

echo "Downloading $ZIG_URL..."
if command -v wget > /dev/null; then
    ipv4="-4"
    if [ -f /etc/alpine-release ]; then
        ipv4=""
    fi
    wget $ipv4 --header='Accept-Encoding: identity' --quiet --output-document="$ZIG_ARCHIVE" "$ZIG_URL"
else
    curl -H 'Accept-Encoding: identity' --silent --output "$ZIG_ARCHIVE" "$ZIG_URL"
fi

# Extract and clean up:
echo "Extracting $ZIG_ARCHIVE..."
case "$ZIG_ARCHIVE_EXT" in
    ".tar.xz")
        tar -xf "$ZIG_ARCHIVE"

        ;;
    ".zip")
        unzip -q "$ZIG_ARCHIVE"
        ;;
    *)
        echo "Unexpected error"
        exit 1
        ;;
esac

rm "$ZIG_ARCHIVE"

# Move files and clean up:
rm -rf zig/doc zig/lib
mv "$ZIG_DIRECTORY/LICENSE" zig/

mv "$ZIG_DIRECTORY/README.md" zig/
mv "$ZIG_DIRECTORY/doc" zig/
mv "$ZIG_DIRECTORY/lib" zig/
mv "$ZIG_DIRECTORY/zig" zig/

rmdir "$ZIG_DIRECTORY"

ZIG_BIN="$(pwd)/zig/zig"
echo "Downloading completed ($ZIG_BIN)! Enjoy!"
