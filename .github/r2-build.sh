set -ex
ROOT=$PWD
NDK="${ANDROID_NDK_LATEST_HOME:-${ANDROID_NDK_HOME:-$ANDROID_NDK_ROOT}}"
TC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
API=26
PREFIX=/data/data/com.brruham.myradare2/files/r2
pip install meson ninja
git clone --depth 1 https://github.com/radareorg/radare2 r2src
cat > cross.ini <<EOT
[binaries]
c = '$TC/aarch64-linux-android$API-clang'
cpp = '$TC/aarch64-linux-android$API-clang++'
ar = '$TC/llvm-ar'
strip = '$TC/llvm-strip'
[host_machine]
system = 'android'
cpu_family = 'aarch64'
cpu = 'aarch64'
endian = 'little'
[properties]
needs_exe_wrapper = true
EOT
cd r2src
meson setup build --cross-file ../cross.ini --prefix=$PREFIX --libdir=lib --buildtype=release
DESTDIR=$ROOT/stage ninja -C build install
cd $ROOT
S=$ROOT/stage$PREFIX
test -x $S/bin/radare2
rm -rf $S/include $S/lib/pkgconfig $S/share/man $S/share/doc
find $S -name '*.a' -delete
find $S/bin $S/lib -type f -exec $TC/llvm-strip --strip-unneeded {} + 2>/dev/null || true
cd $(dirname $S) && zip -qr $ROOT/r2.zip r2
ls -la $ROOT/r2.zip
