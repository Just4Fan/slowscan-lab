#!/bin/bash
# 条件 E：无指纹的"自制扫描器"
# 目的：同样的行为（连 10 个端口 + 发 HTTP 请求），但没有 nmap 指纹。
# 预期：ET SCAN 告警为 0 → 证明规则检测的是"工具品牌"，不是"扫描行为"。
#
# 用法：sudo bash run_probe.sh
set -u
cd "$(dirname "$0")" || exit 1

PORTS_RANGE="8001-8010"

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
    echo "[*] 假服务未就绪，启动中..."
    rm -f fake_services.pid fake.log
    nohup python3 fake_services.py > ./fake.log 2>&1 &
    sleep 3
    n=$(count_ports)
fi
echo "[*] 假服务端口数：$n / 10"
[ "$n" -lt 10 ] && { echo "[!] 启动失败"; tail -20 ./fake.log; exit 1; }

# 抓包 + 自制探测器
tcpdump -i lo -w E.pcap "tcp portrange ${PORTS_RANGE}" >/dev/null 2>&1 &
TP=$!
sleep 2

python3 probe_like_a_scanner.py

sleep 2
kill -INT "$TP" 2>/dev/null
wait "$TP" 2>/dev/null

mkdir -p out2_E
suricata -r E.pcap -l out2_E -k none >/dev/null 2>&1

ALL="out2_E/fast.log"
et_scan=$(grep 'ET SCAN' "$ALL" 2>/dev/null | wc -l)
et_all=$(grep -v 'SURICATA ' "$ALL" 2>/dev/null | wc -l)
raw=$(wc -l < "$ALL" 2>/dev/null || echo 0)

echo
echo "======================================================"
echo "条件 E（自制探测器，无 nmap 指纹）"
echo "  原始告警总数      : $raw"
echo "  排除引擎自带后    : $et_all"
echo "  其中 ET SCAN      : $et_scan"
echo "======================================================"
[ "$et_scan" -gt 0 ] && grep 'ET SCAN' "$ALL" | grep -oE '\[1:[0-9]+:[0-9]+\]' | sort | uniq -c

echo
echo "完整对照表："
echo "  A  nmap -sV（标准载荷）      → 28"
echo "  B  nmap -sS（裸 SYN）        → 0"
echo "  D  nmap -sS 慢速             → 0"
echo "  A2 nmap -sV -I0（极低载荷）  → 0"
echo "  E  自制探测器（无 nmap 指纹）→ $et_scan"
