#!/bin/bash
# Functional test with PHP's built-in web server inside an official php:<X.Y>-cli image.
# Sends a multipart upload that carries the PHP_SESSION_UPLOAD_PROGRESS field plus a session cookie,
# once without and once with the guard. Expected: without the guard the session file gets an
# upload_progress_* entry; with the guard it stays empty while $_POST/$_FILES are unchanged.
#
#   ./test/run-builtin-server.sh 8.3          # Docker's native architecture
#   ./test/run-builtin-server.sh 8.3 arm64    # or force one: amd64, arm64 (non-native runs under emulation)
#
set -u
v="${1:-8.3}"
platform=(${2:+--platform "linux/$2"})
HERE="$(cd "$(dirname "$0")/.." && pwd)"
docker run --rm "${platform[@]}" -v "$HERE/dist:/dist:ro" -v "$HERE/test:/test:ro" "php:${v}-cli" bash -c '
  set -u
  apt-get -qq update >/dev/null 2>&1; apt-get -qq install -y curl >/dev/null 2>&1
  mkdir -p /tmp/sess; head -c 300000 /dev/urandom > /tmp/blob.bin
  v=$(php -r "echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;")
  echo "===== php $v on $(uname -m)"
  for mode in without with; do
    args=(-n -d session.upload_progress.enabled=1 -d session.upload_progress.cleanup=0 -d session.use_strict_mode=0 -d session.save_path=/tmp/sess)
    [ $mode = with ] && args+=(-d extension=/dist/hp_uploadprogress_guard-${v}-$(uname -m).so)
    php "${args[@]}" -S 127.0.0.1:8099 -t /test >/tmp/srv.log 2>&1 &
    pid=$!; sleep 1
    echo "===== $mode guard: multipart upload WITH progress field + session cookie"
    curl -s -b PHPSESSID=abcdef0123456789 -F PHP_SESSION_UPLOAD_PROGRESS=probe -F name=jo -F f=@/tmp/blob.bin http://127.0.0.1:8099/probe.php
    echo "===== $mode guard: plain multipart upload"
    curl -s -b PHPSESSID=abcdef0123456789 -F name=jo -F f=@/tmp/blob.bin http://127.0.0.1:8099/probe.php
    kill $pid; wait $pid 2>/dev/null; rm -f /tmp/sess/*
  done
'
