#!/bin/bash
# 生成 60 秒"正常访问"流量：只反复访问 2 个固定端口。
# 用来测行为检测器的误报率：正常用户集中在少数端口。
#
# 用法：sudo bash make_normal_traffic.sh
set -u
cd "$(dirname "$0")" || exit 1

# 确保假服务在跑
if ! python3 - <<'PY'
import socket, sys
s = socket.socket(); s.settimeout(0.3)
sys.exit(0 if s.connect_ex(("127.0.0.1", 8001)) == 0 else 1)
PY
then
    echo "[*] 启动假服务..."
    rm -f fake_services.pid fake.log
    nohup python3 fake_services.py > ./fake.log 2>&1 &
    sleep 3
fi

echo "[*] 抓包 60 秒，模拟正常用户只访问 8001 和 8008 ..."
tcpdump -i lo -w normal.pcap "tcp portrange 8001-8010" >/dev/null 2>&1 &
TP=$!
sleep 2

for i in $(seq 1 30); do
    curl -s -o /dev/null --max-time 2 http://127.0.0.1:8001/ || true
    curl -s -o /dev/null --max-time 2 http://127.0.0.1:8008/ || true
    sleep 1
done

sleep 1
kill -INT "$TP" 2>/dev/null
wait "$TP" 2>/dev/null

echo "[*] 完成，生成 normal.pcap"
ls -lh normal.pcap
echo
echo "下一步：python3 behavior_detector.py normal.pcap A.pcap B.pcap D.pcap A2.pcap E.pcap"
