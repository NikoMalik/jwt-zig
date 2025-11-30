#!/usr/bin/env sh
set -eu


ZIG_RELEASE=${1:-"0.15.2"}

# Detect OS
case "$(uname)" in
    Linux)  ZIG_OS="linux" ;;
    Darwin) ZIG_OS="macos" ;;
    CYGWIN*|MINGW*) ZIG_OS="windows" ;;
    *) echo "Unknown OS"; exit 1 ;;
esac

# Detect architecture
case "$(uname -m)" in
    x86_64|amd64) ZIG_ARCH="x86_64" ;;
    aarch64|arm64) ZIG_ARCH="aarch64" ;;
    *) echo "Unknown architecture"; exit 1 ;;
esac

ZIG_KEY="$ZIG_ARCH-$ZIG_OS"

echo "Platform: $ZIG_KEY"

# Fetch index.json
if command -v wget > /dev/null; then
    INDEX=$(wget -q -O - https://ziglang.org/download/index.json)
else
    INDEX=$(curl -s https://ziglang.org/download/index.json)
fi

# If latest → remap to "builds"
if [ "$ZIG_RELEASE" = "latest" ]; then
    ZIG_RELEASE="builds"
fi

# Extract tarball URL
ZIG_URL=$(
    printf "%s\n" "$INDEX" \
        | awk -v ver="$ZIG_RELEASE" -v key="$ZIG_KEY" '
            $0 ~ "\""ver"\"" { inver=1 }
            inver && $0 ~ "\""key"\"" { inkey=1 }
            inver && inkey && $0 ~ /"tarball"/ {
                gsub(/[",]/, "", $2)
                print $2
                exit
            }
        '
)

if [ -z "${ZIG_URL:-}" ]; then
    echo "ERROR: Release \"$ZIG_RELEASE\" not found for platform $ZIG_KEY"
    exit 1
fi

echo "Downloading: $ZIG_URL"

ARCHIVE=$(basename "$ZIG_URL")
DIR="${ARCHIVE%.tar.xz}"
DIR="${DIR%.zip}"

# Download
if command -v wget > /dev/null; then
    wget -q -O "$ARCHIVE" "$ZIG_URL"
else
    curl -s -o "$ARCHIVE" "$ZIG_URL"
fi

echo "Extracting..."
case "$ARCHIVE" in
    *.tar.xz) tar -xf "$ARCHIVE" ;;
    *.zip) unzip -q "$ARCHIVE" ;;
    *) echo "Unknown archive format"; exit 1 ;;
esac

rm "$ARCHIVE"

# Install into ./zig/ directory
rm -rf zig
mkdir zig

mv "$DIR"/* zig/
rmdir "$DIR" 2>/dev/null || true

echo "Installed Zig into $(pwd)/zig"
echo "Binary: $(pwd)/zig/zig"
