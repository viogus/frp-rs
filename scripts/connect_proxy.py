#!/usr/bin/env python3
"""Tiny HTTP CONNECT proxy for compat tests. Logs each CONNECT to a file.

Usage: connect_proxy.py PORT LOG_FILE
"""
import socket
import sys
import threading

port = int(sys.argv[1])
log_file = sys.argv[2]

def log(msg: str):
    with open(log_file, "a") as f:
        f.write(msg + "\n")

def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass

def handle(conn):
    try:
        conn.settimeout(10)
        request = b""
        while b"\r\n\r\n" not in request:
            chunk = conn.recv(4096)
            if not chunk:
                return
            request += chunk
        first_line = request.split(b"\r\n")[0].decode()
        parts = first_line.split()
        if len(parts) >= 3 and parts[0] == "CONNECT":
            host, port_s = parts[1].rsplit(":", 1)
            log(f"CONNECT {host}:{port_s}")
            upstream = socket.create_connection((host, int(port_s)), timeout=10)
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            # Data already buffered after the CONNECT headers belongs to the
            # tunnel (e.g. TLS ClientHello pipelined with the CONNECT) — push
            # it into the upstream before the relay loops take over.
            leftover = request.split(b"\r\n\r\n", 1)
            if len(leftover) == 2 and leftover[1]:
                upstream.sendall(leftover[1])
            threading.Thread(target=pipe, args=(conn, upstream), daemon=True).start()
            pipe(upstream, conn)
        elif len(parts) >= 3 and parts[1].startswith("http://"):
            # absolute-form request (oauth2 http client via proxy): forward
            # the raw bytes to the origin and relay the response
            from urllib.parse import urlsplit
            url = urlsplit(parts[1])
            host = url.hostname
            port_s = str(url.port or 80)
            log(f"FORWARD {parts[0]} {host}:{port_s}{url.path}")
            upstream = socket.create_connection((host, int(port_s)), timeout=10)
            # read any request body after the header block (loop until the
            # full Content-Length is consumed — a single recv may return a
            # partial body)
            body = b""
            for line in request.split(b"\r\n")[1:]:
                if line.lower().startswith(b"content-length:"):
                    try:
                        want = int(line.split(b":")[1].strip())
                        if want < 0:
                            want = 0
                        conn.settimeout(10)
                        while len(body) < want:
                            part = conn.recv(want - len(body))
                            if not part:
                                break
                            body += part
                    except (ValueError, OSError):
                        body = b""
                    break
            new_line = f"{parts[0]} {url.path or '/'}{('?' + url.query) if url.query else ''} HTTP/1.1".encode()
            forwarded = new_line + b"\r\n" + request.split(b"\r\n", 1)[1] + body
            upstream.sendall(forwarded)
            pipe(upstream, conn)
        else:
            log(f"REJECT {first_line}")
            conn.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
    except OSError as e:
        log(f"ERR {e}")
    finally:
        try:
            conn.close()
        except OSError:
            pass

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(128)
log("LISTEN")
while True:
    conn, _ = srv.accept()
    threading.Thread(target=handle, args=(conn,), daemon=True).start()
