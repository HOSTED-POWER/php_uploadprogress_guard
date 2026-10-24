#!/bin/bash
# build dist/hp_uploadprogress_guard-<v>[-aarch64].so per PHP minor and architecture, from src/ (the module
# source and per-branch parser copy rfc1867/rfc1867_copy-<v>.c), on the OLDEST official PHP image that ships
# that minor. The .so must load on every host in the fleet (Debian 10+, Ubuntu 18.04+, EL7+): a binary built on
# a newer glibc references symbol versions older hosts lack (glibc 2.38 turned strtoll into
# __isoc23_strtoll@GLIBC_2.38, which broke the v3.0 rollout: "GLIBC_2.38 not found" on Debian 12).
# Every built file is checked inside its own image and rejected if it requires anything above GLIBC_2.17 (EL7).
#   ./build.sh 8.5 8.4 8.3 8.2 8.1 8.0 7.4 7.3 7.2 7.1 7.0 5.6        # ARCHS="x86_64 aarch64" by default
#   ARCHS=aarch64 ./build.sh 8.4                                       # one architecture only
# aarch64 on an x86_64 host needs QEMU user emulation in Docker: docker run --privileged --rm tonistiigi/binfmt --install arm64
set -u
R="$(cd "$(dirname "$0")" && pwd)"; S="$R/src"
OUT="${HP_UPG_OUT:-$R/dist}"
ARCHS="${ARCHS:-x86_64 aarch64}"
MAX_GLIBC=2.17
image() {
  case "$1" in
    5.6|7.0|7.1|7.2|7.3) echo "php:$1-cli-stretch" ;;   # glibc 2.24
    7.4|8.0|8.1)         echo "php:$1-cli-buster" ;;    # glibc 2.28
    8.2|8.3|8.4)         echo "php:$1-cli-bullseye" ;;  # glibc 2.31
    *)                   echo "php:$1-cli-bookworm" ;;  # glibc 2.36 (8.5: no older image exists)
  esac
}
platform() { case "$1" in x86_64) echo linux/amd64 ;; aarch64) echo linux/arm64 ;; *) echo "unknown arch $1" >&2; exit 1 ;; esac; }
rc=0
for v in "$@"; do
  for arch in $ARCHS; do
    suffix=""; [ "$arch" = x86_64 ] || suffix="-$arch"
    d="$S/build-$v-$arch"; rm -rf "$d"; mkdir -p "$d"
    cp "$S/config.m4" "$S/hp_uploadprogress_guard.c" "$S/hp_uploadprogress_guard.h" "$S/hp_glibc_compat.h" "$d/"
    cp "$S/rfc1867/rfc1867_copy-$v.c" "$d/rfc1867_copy.c"
    img=$(image "$v")
    echo "=== $img ($arch)"
    docker run --rm --platform "$(platform "$arch")" -e MAX_GLIBC="$MAX_GLIBC" -e SUFFIX="$suffix" -v "$d:/src:ro" -v "$OUT:/out" "$img" bash -c '
      [ "$(uname -m)" = "'"$arch"'" ] || { echo "image is $(uname -m), wanted '"$arch"'"; exit 1; }
      cp -r /src /build && cd /build && phpize >/dev/null 2>&1 && ./configure --quiet >/dev/null 2>&1 && make -s >/tmp/make.log 2>&1
      grep -E "warning: |error" /tmp/make.log | grep -v shtool | head -20
      v=$(php -r "echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;")
      so=modules/hp_uploadprogress_guard.so; [ -f $so ] || exit 1
      need=$(objdump -T $so | grep -o "GLIBC_[0-9.]*" | sed "s/GLIBC_//" | sort -uV | tail -1)
      if [ "$(printf "%s\n%s\n" "$need" "$MAX_GLIBC" | sort -V | tail -1)" != "$MAX_GLIBC" ]; then
        echo "REJECTED, requires GLIBC_$need > $MAX_GLIBC: $(objdump -T $so | grep "GLIBC_$need" | awk "{print \$NF}" | tr "\n" " ")"; exit 2
      fi
      cp $so /out/hp_uploadprogress_guard-$v$SUFFIX.so
      echo "ok, $(uname -m), glibc $(ldd --version | head -1 | sed "s/.*) //") image, max required GLIBC_$need: $(php -n -d extension=/out/hp_uploadprogress_guard-$v$SUFFIX.so --ri hp_uploadprogress_guard | grep -E "^version" | tr -s " ")"' 2>&1 | grep -vE "^$|shtool|Pulling|Pull complete|Download complete|Digest:|Status:|Unable to find image"
    [ -f "$OUT/hp_uploadprogress_guard-$v$suffix.so" ] || { echo "$v ($arch): BUILD FAILED"; rc=1; }
    rm -rf "$d"
  done
done
(cd "$OUT" && sha256sum hp_uploadprogress_guard-*.so > SHA256SUMS)
exit $rc
