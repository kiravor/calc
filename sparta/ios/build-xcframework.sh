#!/bin/sh
set -eu
# OpenSSL must already be built for each SDK. No downloads and no trust bypasses.
: "${OPENSSL_IOS_DEVICE:?Path to iOS arm64 OpenSSL prefix (include/, lib/)}"
: "${OPENSSL_IOS_SIMULATOR:?Path to simulator OpenSSL prefix (include/, lib/)}"
command -v xcrun >/dev/null
command -v xcodebuild >/dev/null
sparta_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
repo_root=$(dirname -- "$sparta_root")
out="$sparta_root/build/ios"
mkdir -p "$out/headers"
cp "$sparta_root/include/sparta.h" "$out/headers/"
cp "$sparta_root/ios/module.modulemap" "$out/headers/"
for variant in device-arm64 simulator-arm64 simulator-x86_64; do
    case "$variant" in
        device-arm64) sdk=iphoneos; target=arm64-apple-ios15.0; prefix=$OPENSSL_IOS_DEVICE ;;
        simulator-arm64) sdk=iphonesimulator; target=arm64-apple-ios15.0-simulator; prefix=$OPENSSL_IOS_SIMULATOR ;;
        simulator-x86_64) sdk=iphonesimulator; target=x86_64-apple-ios15.0-simulator; prefix=$OPENSSL_IOS_SIMULATOR ;;
    esac
    dir="$out/$variant"
    mkdir -p "$dir"
    cc=$(xcrun --sdk "$sdk" --find clang)
    sysroot=$(xcrun --sdk "$sdk" --show-sdk-path)
    for source in "$repo_root"/src/*.c "$sparta_root"/src/common.c "$sparta_root"/src/client.c \
                  "$sparta_root"/src/client_udp.c "$sparta_root"/src/websocket.c "$sparta_root"/src/wire.c \
                  "$sparta_root"/vendor/cJSON.c; do
        case "$source" in */src/main.c) continue ;; esac
        name=$(basename "$source" .c)
        case "$source" in "$repo_root"/src/*) name="base_$name" ;; esac
        "$cc" -target "$target" -isysroot "$sysroot" -std=c17 -O2 -fPIC -pthread \
            -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -DSPARTA_CLIENT_ONLY \
            -I"$repo_root/include" -I"$sparta_root/include" -I"$sparta_root/vendor" -I"$prefix/include" \
            -c "$source" -o "$dir/$name.o"
    done
    xcrun ar rcs "$dir/core.a" "$dir"/*.o
    xcrun libtool -static -o "$dir/libSpartaC.a" "$dir/core.a" "$prefix/lib/libssl.a" "$prefix/lib/libcrypto.a"
done
xcrun lipo -create "$out/simulator-arm64/libSpartaC.a" "$out/simulator-x86_64/libSpartaC.a" -output "$out/libSpartaC-simulator.a"
if [ -e "$out/SpartaC.xcframework" ]; then
    echo 'Output already exists; move it aside before rebuilding.' >&2
    exit 1
fi
xcodebuild -create-xcframework \
    -library "$out/device-arm64/libSpartaC.a" -headers "$out/headers" \
    -library "$out/libSpartaC-simulator.a" -headers "$out/headers" \
    -output "$out/SpartaC.xcframework"
