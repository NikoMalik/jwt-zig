#!/usr/bin/env sh
set -eu

ZIG_RELEASE="0.14.0-dev.2851+b074fb7dd"
ZIG_TARBALL="zig-linux-x86_64-${ZIG_RELEASE}.tar.xz"

LOCAL_TARBALL="$(dirname "$0")/${ZIG_TARBALL}"

if [ -f "${LOCAL_TARBALL}" ]; then
    echo "Using local Zig archive: ${LOCAL_TARBALL}"
    cp "${LOCAL_TARBALL}" .

else
    echo "Local archive not found, downloading..."
    ZIG_URL="https://ziglang.org/builds/${ZIG_TARBALL}"
    curl --silent --output "${ZIG_TARBALL}" "${ZIG_URL}" || { 
        echo "Download failed"; 
        exit 1; 
    }
fi


echo "Extracting ${ZIG_TARBALL}..."

tar -xf "${ZIG_TARBALL}" || { echo "Extraction failed"; exit 1; }

ZIG_DIR="zig-linux-x86_64-${ZIG_RELEASE}"
[ -d "${ZIG_DIR}" ] || { echo "Directory ${ZIG_DIR} not found"; exit 1; }

rm -rf zig/doc zig/lib 2>/dev/null
mv -f "${ZIG_DIR}"/* zig/
rmdir "${ZIG_DIR}"

echo "Zig ${ZIG_RELEASE} ready in: $(pwd)/zig"
