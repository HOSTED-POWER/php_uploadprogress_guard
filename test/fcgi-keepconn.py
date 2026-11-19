#!/usr/bin/env python3
"""Connection reuse after a partly read request body (GHSA-qc49-hpvq-g2w6). Stdlib only.

Sends two requests over ONE FastCGI connection with FCGI_KEEP_CONN, as nginx does with fastcgi_keep_conn on.
The first carries a 100 KB body of which the script reads 16 bytes through php://input; the second is a plain
GET. PHP must discard the unread body before it reads the next request, or the second request never completes.

    python3 test/fcgi-keepconn.py /run/php/php8.4-fpm.sock /var/www/html/keepconn.php

php.ini: enable_post_data_reading = 0 (the body is left to php://input, as streaming-upload frameworks do)
keepconn.php:  <?php $f = fopen('php://input', 'r'); fread($f, 16); echo "ok\n";
Expected with the guard (or a fixed PHP): "request 1: ok" and "request 2: ok", exit status 0.
"""
import socket, struct, sys

sock_path, script = sys.argv[1], sys.argv[2]
BEGIN, END, PARAMS, STDIN, STDOUT = 1, 3, 4, 5, 6
KEEP_CONN = 1


def rec(t, rid, c=b""):
    return struct.pack(">BBHHBx", 1, t, rid, len(c), 0) + c


def nv(k, v):
    k, v = k.encode(), v.encode()
    return bytes([len(k)]) + (struct.pack(">I", len(v) | 0x80000000) if len(v) > 127 else bytes([len(v)])) + k + v


def request(rid, method, body):
    params = {"GATEWAY_INTERFACE": "FastCGI/1.0", "REQUEST_METHOD": method, "SCRIPT_FILENAME": script,
              "SCRIPT_NAME": "/keepconn.php", "REQUEST_URI": "/keepconn.php", "SERVER_PROTOCOL": "HTTP/1.1",
              "REMOTE_ADDR": "127.0.0.1", "SERVER_NAME": "localhost"}
    if body:
        params.update({"CONTENT_TYPE": "application/octet-stream", "CONTENT_LENGTH": str(len(body))})
    out = rec(BEGIN, rid, struct.pack(">HB5x", 1, KEEP_CONN))
    out += rec(PARAMS, rid, b"".join(nv(k, v) for k, v in params.items())) + rec(PARAMS, rid)
    for i in range(0, len(body), 65535):
        out += rec(STDIN, rid, body[i:i + 65535])
    return out + rec(STDIN, rid)


def response(s):
    buf, data = b"", b""
    while True:
        while len(buf) < 8:
            chunk = s.recv(65536)
            if not chunk:
                return None  # connection closed before END_REQUEST
            buf += chunk
        _, t, _, clen, plen = struct.unpack(">BBHHB", buf[:7])
        while len(buf) < 8 + clen + plen:
            chunk = s.recv(65536)
            if not chunk:
                return None
            buf += chunk
        content, buf = buf[8:8 + clen], buf[8 + clen + plen:]
        if t == STDOUT:
            data += content
        elif t == END:
            return data.split(b"\r\n\r\n", 1)[-1].decode(errors="replace").strip()


s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(sock_path)
rc = 0
for rid, method, body in ((1, "POST", b"A" * 100000), (2, "GET", b"")):
    try:
        s.sendall(request(rid, method, body))
        r = response(s)
    except (socket.timeout, BrokenPipeError, ConnectionResetError):
        r = None
    print(f"request {rid}: {r if r is not None else 'FAILED (no complete response on the reused connection)'}")
    rc |= r != "ok"
sys.exit(rc)
