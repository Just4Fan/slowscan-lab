#!/bin/bash
# 慢速扫描检测实验：四个条件对照
#
# 用法（必须以 root 运行：整个脚本一次授权，避免后台 sudo 卡住）：
#     sudo bash run.sh
#
# 可选：把 C 组也跑上（很慢，约 10 分钟）
#     sudo WITH_C=1 bash run.sh
#
# 产出：
#     A.pcap B.pcap (C.pcap D.pcap)  —— 抓到的流量
#     out_*/fast.log                 —— Suricata 告警
#     summary.txt                    —— 汇总表
set -u

PORTS="8001-8010"          # 10 个开放端口（假服务监听在这）
SLOW_RATE="0.05"           # 每秒 0.05 个包 = 20 秒一个，低于 5次/60秒 的阈值
WITH_C="${WITH_C:-0}"
LAST_COUNT=0

cd "$(dirname "$0")" || exit 1

# ---------- 前置检查 ----------
if [ "$(id -u)" -ne 0 ]; then
    echo "请用 sudo 运行：sudo bash run.sh"
    exit 1
fi
for t in nmap tcpdump suricata python3; do
    command -v "$t" >/dev/null 2>&1 || { echo "缺少 $t"; exit 1; }
done

# ---------- 启动假服务 ----------
python3 fake_services.py &
FAKE_PID=$!
sleep 2

if ! ss -tln 2>/dev/null | grep -q ':8001'; then
    echo "假服务没起来（8001 端口未监听）"
    kill "$FAKE_PID" 2>/dev/null
    exit 1
fi
echo "假服务已启动（$PORTS），PID=$FAKE_PID"
echo

# ---------- 单次实验 ----------
scan() {
    local name="$1"; shift
    echo "=================================================="
    echo "[$name] 扫描命令：$*"
    echo "=================================================="

    tcpdump -i lo -w "${name}.pcap" "tcp portrange ${PORTS}" >/dev/null 2>&1 &
    local TP=$!
    sleep 2

    "$@"

    sleep 2
    kill -INT "$TP" 2>/dev/null
    wait "$TP" 2>/dev/null

    mkdir -p "out_${name}"
    suricata -r "${name}.pcap" -l "out_${name}" >/dev/null 2>&1

    LAST_COUNT=0
    if [ -f "out_${name}/fast.log" ]; then
        LAST_COUNT=$(wc -l < "out_${name}/fast.log")
    fi
    echo ">>> [$name] 告警数：$LAST_COUNT"
    echo
}

# ---------- 四个条件 ----------
scan A nmap -sV -T4 -p "$PORTS" 127.0.0.1
echo "$LAST_COUNT" > /tmp/count_A

scan B nmap -sS -T4 -p "$PORTS" 127.0.0.1
echo "$LAST_COUNT" > /tmp/count_B

scan D nmap -sS --max-rate "$SLOW_RATE" -p "$PORTS" 127.0.0.1
echo "$LAST_COUNT" > /tmp/count_D

if [ "$WITH_C" = "1" ]; then
    scan C nmap -sV --version-light --max-rate "$SLOW_RATE" -p "$PORTS" 127.0.0.1
    echo "$LAST_COUNT" > /tmp/count_C
else
    echo 0 > /tmp/count_C
    echo "（C 组未运行；要跑就在前面加 WITH_C=1）"
fi

kill "$FAKE_PID" 2>/dev/null

# ---------- 汇总 ----------
{
    echo "条件            速率      载荷   告警数"
    echo "------------------------------------------------"
    printf "A  快 + 带载荷    -T4       有     %s\n" "$(cat /tmp/count_A)"
    printf "B  快 + 裸 SYN    -T4       无     %s\n" "$(cat /tmp/count_B)"
    printf "C  慢 + 带载荷    0.05/s    有     %s\n" "$(cat /tmp/count_C)"
    printf "D  慢 + 裸 SYN    0.05/s    无     %s\n" "$(cat /tmp/count_D)"
} | tee summary.txt

echo
echo "各条件的告警内容（前 3 条）："
for n in A B C D; do
    [ -f "out_${n}/fast.log" ] || continue
    echo "--- $n ---"
    head -3 "out_${n}/fast.log"
done

echo
echo "全部完成。结果见 summary.txt 与 out_*/fast.log"
