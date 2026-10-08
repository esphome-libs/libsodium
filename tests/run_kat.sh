#!/bin/sh
# Apply the patches if the tree is still pristine, build the library and the
# known-answer tests, then run them.
# Usage: tests/run_kat.sh <build dir> [extra CFLAGS]
# Run from the repository root; the 32-bit CI job runs the same script inside
# a linux/386 container.
set -eu
build=$1
cflags=${2:-}
# A pristine tree has no tracked changes; files the patches add can survive a
# reset --hard, so they are cleaned before applying rather than trusted
if git -C libsodium diff --quiet; then
  git -C libsodium clean -fdq
  patches/apply.sh
fi
if git -C libsodium diff --quiet; then
  echo "libsodium is unpatched; run patches/apply.sh" >&2
  exit 1
fi
test -f libsodium/src/libsodium/crypto_core/ed25519/ref10/base_packed.h
cmake -B "$build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="$cflags" .
cmake --build "$build" -j
# upstream's SHA256, SHA512 and ref10 X25519 at the pinned tag, for the
# differentials in kat.c: the references are compiled against a pristine copy
# of the upstream tree and without the caller's flags, so neither a fork
# header nor a fork switch can reach them
up=$build/upstream
rm -rf "$up" && mkdir -p "$up"
git -C libsodium archive HEAD src/libsodium | tar -x -C "$up"
for ref in sha256 sha512 x25519; do
  gcc -O2 -Wall -Wextra -DCONFIGURED=1 -c -o "$build/${ref}_reference.o" \
    "tests/${ref}_reference.c" -I"$up/src/libsodium" -I"$up/src/libsodium/include" \
    -I"$up/src/libsodium/include/sodium" \
    -I"$up/src/libsodium/crypto_core/ed25519/ref10" \
    -I"$up/src/libsodium/crypto_scalarmult/curve25519/ref10"
done
# shellcheck disable=SC2086
gcc -O2 -Wall -Wextra -DCONFIGURED=1 $cflags -o "$build/kat" tests/kat.c \
  "$build/sha256_reference.o" "$build/sha512_reference.o" "$build/x25519_reference.o" \
  -Ilibsodium/src/libsodium/include -Ilibsodium/src/libsodium/include/sodium \
  -Iport_include "$build/libsodium.a"
"$build/kat"
