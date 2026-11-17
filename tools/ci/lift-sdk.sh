#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Lifts what a host cargo needs to cross-build for the Sailfish OS target out of the Platform SDK image: SDK's aarch64
# gcc and binutils (/opt/cross, i486 binaries), host libraries they load, the target's sysroot. Then adds what the image
# leaves to scratchbox2: binutils under the names gcc looks for, a linker wrapper, unversioned libsqlite3.so (the target
# lacks it without sqlite-devel; binaries still record libsqlite3.so.0). Host needs libc6-i386 and qemu-user-static.
# Usage: lift-sdk.sh <image> <target name> <dir>
set -eu
image=$1
target=$2
dir=$3
triple=aarch64-meego-linux-gnu
rm -rf "$dir"
mkdir -p "$dir/hostlib" "$dir/bin" "$dir/linklib"
dir=$(cd "$dir" && pwd)
cid=$(docker create "$image" /bin/true)
trap 'docker rm "$cid" > /dev/null' EXIT
# Through tar so an unprivileged user can unpack: no device nodes, no ownership, every file readable and removable.
lift() {
    from=$1
    to=$2
    mkdir -p "$to"
    docker cp "$cid:$from/." - | tar -x -C "$to" --no-same-owner --exclude='./dev/*'
    chmod -R u+rwX "$to"
}
lift /opt/cross "$dir/cross"
lift "/srv/mer/targets/$target" "$dir/sysroot"
for lib in libmpc.so.3 libmpfr.so.6 libgmp.so.10 libz.so.1 libzstd.so.1; do
    docker cp -L "$cid:/usr/lib/$lib" "$dir/hostlib/$lib"
done
# gcc runs as and ld from <prefix>/<triple>/bin; in the SDK sb2 maps them.
mkdir -p "$dir/cross/$triple/bin"
for tool in as ld ld.bfd ar nm objcopy objdump ranlib readelf strip; do
    if [ -e "$dir/cross/bin/$triple-$tool" ]; then
        ln -sf "../../bin/$triple-$tool" "$dir/cross/$triple/bin/$tool"
    fi
done
for tool in gcc g++; do
    cat > "$dir/bin/$triple-$tool" <<WRAP
#!/bin/sh
LD_LIBRARY_PATH="$dir/hostlib" exec "$dir/cross/bin/$triple-$tool" --sysroot="$dir/sysroot" -Wl,-rpath-link,"$dir/sysroot/usr/lib64:$dir/sysroot/lib64" "\$@"
WRAP
    chmod +x "$dir/bin/$triple-$tool"
done
ln -sf "$dir/sysroot/usr/lib64/libsqlite3.so.0" "$dir/linklib/libsqlite3.so"
"$dir/bin/$triple-gcc" --version | head -n 1
