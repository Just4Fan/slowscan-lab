#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
实验二：行为层扫描检测器（不依赖 tshark，用 tcpdump 读 pcap）

原理：同一源 IP 在滑动窗口内，访问了多少个**不同**的目的端口。
      正常用户集中在少数端口；扫描器必须触碰大量不同端口。

用法：
    python3 behavior_detector.py A.pcap B.pcap D.pcap normal.pcap
    python3 behavior_detector.py *.pcap --window 60 --threshold 8
"""
import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict

LINE_RE = re.compile(
    r"^(?P<t>\d+\.\d+) IP (?P<src>\d+\.\d+\.\d+\.\d+)\.(?P<sport>\d+) > "
    r"(?P<dst>\d+\.\d+\.\d+\.\d+)\.(?P<dport>\d+): Flags \[(?P<flags>[^\]]+)\]"
)


def syn_attempts(pcap):
    """用 tcpdump 抽取连接尝试（SYN 且非 ACK）"""
    bpf = "tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0"
    cmd = ["tcpdump", "-r", pcap, "-nn", "-tt", bpf]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except Exception as e:
        print(f"  [错误] {pcap}: {e}")
        return []
    if res.returncode != 0 and not res.stdout:
        print(f"  [错误] tcpdump 读取失败：{res.stderr.strip()[:200]}")
        return []

    recs = []
    for line in res.stdout.splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        try:
            t = float(m.group("t"))
            dport = int(m.group("dport"))
        except ValueError:
            continue
        recs.append((t, m.group("src"), m.group("dst"), dport))
    recs.sort(key=lambda x: x[0])
    return recs


def analyze(recs, window=60.0):
    by_src = defaultdict(list)
    for t, src, dst, port in recs:
        by_src[src].append((t, port))

    best_ports = set()
    for src, items in by_src.items():
        items.sort()
        n = len(items)
        for i in range(n):
            t0 = items[i][0]
            ports = set()
            j = i
            while j < n and items[j][0] < t0 + window:
                ports.add(items[j][1])
                j += 1
            if len(ports) > len(best_ports):
                best_ports = ports

    all_ports = {p for _, _, _, p in recs}
    return len(best_ports), best_ports, len(recs), all_ports


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--window", type=float, default=60.0, help="滑动窗口（秒），默认 60")
    ap.add_argument("--threshold", type=int, default=8, help="窗口内不同端口数达到多少判定为扫描")
    args = ap.parse_args()

    rows = []
    for pcap in args.pcaps:
        if not os.path.exists(pcap):
            print(f"[跳过] 文件不存在：{pcap}")
            continue
        recs = syn_attempts(pcap)
        if not recs:
            print(f"[跳过] {pcap}：没有连接尝试")
            continue
        max_ports, port_set, attempts, all_ports = analyze(recs, args.window)
        verdict = "ALERT 扫描" if max_ports >= args.threshold else "normal 正常"
        rows.append((os.path.basename(pcap), attempts, len(all_ports), max_ports, verdict, port_set))

    if not rows:
        print("没有可分析的数据")
        return

    print("=" * 66)
    print(f"行为层检测器（窗口 {args.window:.0f}s，阈值 {args.threshold} 个不同端口）")
    print("=" * 66)
    print(f"{'pcap':<14}{'SYN尝试':>9}{'总端口':>9}{'窗口内最大':>12}   判定")
    print("-" * 66)
    for name, attempts, total_ports, max_ports, verdict, _ in rows:
        print(f"{name:<14}{attempts:>9}{total_ports:>9}{max_ports:>12}   {verdict}")
    print("-" * 66)
    print("触及的端口（每个文件）：")
    for name, _, _, max_ports, _, port_set in rows:
        ps = ",".join(str(p) for p in sorted(port_set)[:12])
        more = "" if len(port_set) <= 12 else f" ...(+{len(port_set)-12})"
        print(f"  {name:<14} 最多 {max_ports} 个：{ps}{more}")
    print()
    print("说明：本检测器完全不看载荷，因此对裸 SYN 扫描同样有效。")
    print("      代价是误报：正常用户若访问很多不同端口，也会被判定为扫描。")


if __name__ == "__main__":
    main()
