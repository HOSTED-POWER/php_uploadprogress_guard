#!/bin/bash
# build dist/hp_uploadprogress_guard-5.4.so and -5.5.so (and their -aarch64 variants): no official Docker image
# exists for these, so PHP itself is compiled from the php.net source archive (minimal: session + cgi + cli,
# NTS) inside the stretch image used for 5.6, and the module is built against that. The extension ABI is fixed
# by the minor version, so the result loads on any NTS build of that minor. Same glibc gate as build.sh.
#   ./build-legacy.sh 5.5 5.4              # ARCHS="x86_64 aarch64" by default
set -u
R="$(cd "$(dirname "$0")" && pwd)"; S="$R/src"
OUT="${HP_UPG_OUT:-$R/dist}"
ARCHS="${ARCHS:-x86_64 aarch64}"
MAX_GLIBC=2.17
source_url() { case "$1" in 5.5) echo https://www.php.net/distributions/php-5.5.38.tar.xz ;; 5.4) echo https://www.php.net/distributions/php-5.4.45.tar.bz2 ;; *) echo "only 5.4 and 5.5" >&2; exit 1 ;; esac; }
platform() { case "$1" in x86_64) echo linux/amd64 ;; aarch64) echo linux/arm64 ;; *) echo "unknown arch $1" >&2; exit 1 ;; esac; }
rc=0
for v in "$@"; do
  for arch in $ARCHS; do
    suffix=""; [ "$arch" = x86_64 ] || suffix="-$arch"
    d="$S/build-$v-$arch"; rm -rf "$d"; mkdir -p "$d/rfc1867"
    cp "$S/config.m4" "$S/hp_uploadprogress_guard.c" "$S/hp_uploadprogress_guard.h" "$S/hp_glibc_compat.h" "$d/"; cp "$S/rfc1867/rfc1867_copy-5.6.c" "$d/rfc1867/"
    echo "=== php-$(source_url "$v" | grep -o '5\.[45]\.[0-9]*') from source on php:5.6-cli-stretch ($arch)"
    docker run --rm --platform "$(platform "$arch")" -e URL="$(source_url "$v")" -e MAX_GLIBC="$MAX_GLIBC" -e SUFFIX="$suffix" -v "$d:/src:ro" -v "$OUT:/out" php:5.6-cli-stretch bash -c '
      [ "$(uname -m)" = "'"$arch"'" ] || { echo "image is $(uname -m), wanted '"$arch"'"; exit 1; }
      cd /tmp && curl -fsSL "$URL" -o php.tar && { case "$URL" in *.xz) tar xJf php.tar ;; *) tar xjf php.tar ;; esac; } && cd php-5.* || exit 1
      # the GNU config.guess/config.sub shipped with PHP 5.x predate aarch64
      for f in config.guess config.sub; do curl -fsSL "https://git.savannah.gnu.org/cgit/config.git/plain/$f" -o $f || curl -fsSL "https://raw.githubusercontent.com/gcc-mirror/gcc/master/$f" -o $f || { echo "no fresh $f"; exit 1; }; done
      ./configure --quiet --build="$(gcc -dumpmachine)" --prefix=/opt/php --disable-all --enable-session --enable-cgi --enable-cli >/tmp/cfg.log 2>&1 || { tail -5 /tmp/cfg.log; exit 1; }
      make -s -j"$(nproc)" >/tmp/mk.log 2>&1 || { grep error /tmp/mk.log | head -5; exit 1; }
      make -s install >/dev/null 2>&1; export PATH=/opt/php/bin:$PATH
      cp -r /src /build && cd /build && phpize >/dev/null 2>&1 && ./configure --quiet --with-php-config=/opt/php/bin/php-config >/dev/null 2>&1 && make -s >/tmp/make.log 2>&1
      grep -E "warning: |error" /tmp/make.log | grep -v shtool | head -20
      v=$(php -n -r "echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;"); so=modules/hp_uploadprogress_guard.so; [ -f $so ] || exit 1
      need=$(objdump -T $so | grep -o "GLIBC_[0-9.]*" | sed "s/GLIBC_//" | sort -uV | tail -1)
      if [ "$(printf "%s\n%s\n" "$need" "$MAX_GLIBC" | sort -V | tail -1)" != "$MAX_GLIBC" ]; then echo "REJECTED, requires GLIBC_$need > $MAX_GLIBC"; exit 2; fi
      cp $so /out/hp_uploadprogress_guard-$v$SUFFIX.so
      echo "ok, $(uname -m), PHP $(php -n -r "echo PHP_VERSION;"), max required GLIBC_$need: $(php -n -d extension=/out/hp_uploadprogress_guard-$v$SUFFIX.so --ri hp_uploadprogress_guard | grep -E "^version" | tr -s " ")"' 2>&1 | grep -vE "^$|shtool|Pulling|Pull complete|Download complete|Digest:|Status:|Unable to find image"
    [ -f "$OUT/hp_uploadprogress_guard-$v$suffix.so" ] || { echo "$v ($arch): BUILD FAILED"; rc=1; }
    rm -rf "$d"
  done
done
(cd "$OUT" && sha256sum hp_uploadprogress_guard-*.so > SHA256SUMS)
exit $rc
