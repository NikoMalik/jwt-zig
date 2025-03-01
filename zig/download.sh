#!/usr/bin/env sh
set -eu


ZIG_RELEASE="0.14.0-dev.2851+b074fb7dd"


if ! echo "$ZIG_RELEASE" | grep -q '^[0-9]\+\.[0-9]\+\.[0-9]\+.*$'; then
    echo "wtf format : $ZIG_RELEASE"
    exit 1
fi


if [ "$(uname -m)" = 'arm64' ] || [ "$(uname -m)" = 'aarch64' ]; then
    ZIG_ARCH="aarch64"
else
    ZIG_ARCH="x86_64"
fi


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
        echo "idk ОС"
        exit 1
        ;;
esac


ZIG_TARGET="zig-$ZIG_OS-$ZIG_ARCH"


if command -v wget > /dev/null; then

    ipv4="-4"
    if [ -f /etc/alpine-release ]; then

        ipv4=""
    fi
    ZIG_URL=$(wget $ipv4 --quiet -O - https://ziglang.org/download/index.json | grep -F "$ZIG_TARGET" | grep -F "$ZIG_RELEASE" | awk '{print $2}' | sed 's/[",]//g')
else
    ZIG_URL=$(curl --silent https://ziglang.org/download/index.json | grep -F "$ZIG_TARGET" | grep -F "$ZIG_RELEASE" | awk '{print $2}' | sed 's/[",]//g')
fi

if [ -z "$ZIG_URL" ]; then
    echo "release not found ziglang.org"
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
        echo "idk this format for zip"
        exit 1
        ;;
esac

ZIG_DIRECTORY=$(basename "$ZIG_ARCHIVE" "$ZIG_ARCHIVE_EXT")


echo "download $ZIG_URL..."

if command -v wget > /dev/null; then
    ipv4="-4"
    if [ -f /etc/alpine-release ]; then
        ipv4=""
    fi
    wget $ipv4 --quiet --output-document="$ZIG_ARCHIVE" "$ZIG_URL"
else
    curl --silent --output "$ZIG_ARCHIVE" "$ZIG_URL"
fi

echo "Exctract $ZIG_ARCHIVE..."
case "$ZIG_ARCHIVE_EXT" in
    ".tar.xz")
        tar -xf "$ZIG_ARCHIVE"
        ;;
    ".zip")
        unzip -q "$ZIG_ARCHIVE"

        ;;
    *)
        echo "idk error"
        exit 1
        ;;
esac


rm "$ZIG_ARCHIVE"


rm -rf zig/doc zig/lib
mv "$ZIG_DIRECTORY/LICENSE" zig/
mv "$ZIG_DIRECTORY/README.md" zig/
mv "$ZIG_DIRECTORY/doc" zig/
mv "$ZIG_DIRECTORY/lib" zig/
mv "$ZIG_DIRECTORY/zig" zig/
rmdir "$ZIG_DIRECTORY"


ZIG_BIN="$(pwd)/zig/zig"
echo "zig complete ($ZIG_BIN)! enjoy!"

