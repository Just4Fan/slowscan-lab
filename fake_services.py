#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
在 127.0.0.1 的 8001-8020 上开 20 个"假服务"，回一个 HTTP banner。
目的：让 nmap -sV 有东西可以探测，从而产生"带载荷"的流量。

用法：
    python3 fake_services.py &
    python3 fake_services.py stop   # 停止
"""
import os
import signal
import socket
import sys
import threading

PORTS = range(8001, 8021)
# pid 文件放在脚本同目录（避免 /tmp 的权限坑）
PIDFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fake_services.pid")

BANNER = (
    b"HTTP/1.1 200 OK\r\n"
    b"Server: FakeService/1.0\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 5\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"hello"
)


def serve(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
    except OSError as e:
        print(f"[skip] {port}: {e}", flush=True)
        return
    s.listen(16)
    while True:
        try:
            conn, _ = s.accept()
        except OSError:
            break
        try:
            conn.settimeout(2.0)
            try:
                conn.recv(4096)      # 读请求，不解析
            except Exception:
                pass
            conn.sendall(BANNER)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


def stop():
    try:
        with open(PIDFILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, signal.SIGTERM)
        print(f"stopped pid={pid}")
    except Exception as e:
        print("stop failed:", e)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "stop":
        stop()
        sys.exit(0)

    for p in PORTS:
        threading.Thread(target=serve, args=(p,), daemon=True).start()

    with open(PIDFILE, "w") as f:
        f.write(str(os.getpid()))

    print("fake services listening on 127.0.0.1:" ,
          ",".join(str(p) for p in PORTS), flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
