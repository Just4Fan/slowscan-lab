#!/bin/bash
# A2 补充实验：极低载荷扫描（--version-intensity 0）
# 自带"先起服务、再验证、再扫描"的完整流程，避免假阴性。
#
# 用法：sudo bash run_a2.sh
set -u
cd "$(dirname "$0")" || exit 1

PORTS="8001-8010"

# ---------- 1. 确保假服务在跑 ----------
count_ports() {
    python3 - <<'PY'
import socket
n = 0
for p in range(8001, 8011):
    s = socket.socket()
    s.settimeout(0.3)
    if s.connect_ex(("127.0.0.1", p)) == 0:
        n += 1
    s.close()
print(n)
PY
}

n=$(count_ports)
if [ "$n" -lt 10 ]; then
    echo "[*] 假服务未就绪（当前 $n 个端口可连），正在启动..."
    rm -f fake_services.pid fake.log
    nohup python3 fake_services.py > ./fake.log 2>&1 &
    sleep 3
    n=$(count_ports)
fi

echo "[*] 可连接的假服务端口数：$n / 10"
if [ "$n" -lt 10 ]; then
    echo "[!] 启动失败，fake.log 内容："
    tail -20 ./fake.log 2>/dev/null
    exit 1
fi

# ---------- 2. 确认 nmap 看到 open ----------
opens=$(nmap -sT -p "$PORTS" 127.0.0.1 | grep -c ' open ')
echo "[*] nmap -sT 看到 open 端口数：$opens"
if [ "$opens" -lt 10 ]; then
    echo "[!] 端口没全开，中止（否则会得到假阴性）"
    exit 1
fi

# ---------- 3. 抓包 + 极低载荷扫描 ----------
echo
echo "[*] 开始抓包并扫描（--version-intensity 0）..."
tcpdump -i lo -w A2.pcap "tcp portrange ${PORTS}" >/dev/null 2>&1 &
TP=$!
sleep 2

nmap -sV --version-intensity 0 -T4 -p "$PORTS" 127.0.0.1

sleep 2
kill -INT "$TP" 2>/dev/null
wait "$TP" 2>/dev/null

# ---------- 4. 分析 ----------
mkdir -p out2_A2
suricata -r A2.pcap -l out2_A2 -k none >/dev/null 2>&1

ALL="out2_A2/fast.log"
et_total=$(grep -v 'SURICATA ' "$ALL" 2>/dev/null | wc -l)
et_scan=$(grep 'ET SCAN' "$ALL" 2>/dev/null | wc -l)
raw_total=$(wc -l < "$ALL" 2>/dev/null || echo 0)

echo
echo "======================================================"
echo "A2 结果"
echo "  原始告警总数      : $raw_total"
echo "  排除引擎自带告警后: $et_total"
echo "  其中 ET SCAN      : $et_scan"
echo "======================================================"
if [ "$et_scan" -gt 0 ]; then
    echo "命中的规则："
    grep 'ET SCAN' "$ALL" | grep -oE '\[1:[0-9]+:[0-9]+\]' | sort | uniq -c
fi

echo
echo "对照表（把 A2 填进去）："
echo "  无载荷   -sS              → 0"
echo "  极低载荷 -sV -I0          → $et_scan"
echo "  标准载荷 -sV              → 28"
