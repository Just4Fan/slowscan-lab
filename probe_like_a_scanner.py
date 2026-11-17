#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
"无指纹扫描器"：对 8001-8010 发起 TCP 连接并发送 HTTP 请求，
行为上等价于一次带载荷的端口扫描，但**不使用任何 nmap 的指纹载荷**。

用途：验证 ET SCAN 规则检测的是"扫描行为"还是"扫描器品牌"。
"""
import socket
import time

PORTS = range(8001, 8011)
REQ = b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\nUser-Agent: myprobe/1.0\r\n\r\n"


def main():
    print("probe start", flush=True)
    for p in PORTS:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(("127.0.0.1", p))
            s.sendall(REQ)
            try:
                data = s.recv(4096)
            except Exception:
                data = b""
            s.close()
            print(f"  {p}: connected, got {len(data)} bytes", flush=True)
        except Exception as e:
            print(f"  {p}: {e}", flush=True)
        time.sleep(0.05)
    print("probe done", flush=True)


if __name__ == "__main__":
    main()
