#!/bin/bash
# v2：修正两个致命问题后，重新分析已有的 pcap（不重扫，几秒钟跑完）
#
# 修正 1：-k none     关掉校验和检查（回环抓包必然校验和错误，否则全是噪声）
# 修正 2：HOME_NET/EXTERNAL_NET 设为 any（否则 127.0.0.1 不匹配任何扫描规则）
#
# 用法：sudo bash rescan.sh
set -u
cd "$(dirname "$0")" || exit 1
[ "$(id -u)" -eq 0 ] || { echo "请用 sudo 运行"; exit 1; }

CFG=/etc/suricata/suricata.yaml

# ---------- 备份并修改配置 ----------
if [ ! -f "${CFG}.orig" ]; then
    cp "$CFG" "${CFG}.orig"
    echo "已备份原配置到 ${CFG}.orig"
fi

sed -i 's|^\( *\)HOME_NET:.*|\1HOME_NET: "any"|' "$CFG"
sed -i 's|^\( *\)EXTERNAL_NET:.*|\1EXTERNAL_NET: "any"|' "$CFG"
echo "当前地址变量："
grep -nE '^ *HOME_NET:|^ *EXTERNAL_NET:' "$CFG" | head -4
echo

# ---------- 对每个 pcap 重新分析 ----------
for f in A B C D; do
    [ -f "${f}.pcap" ] || continue
    rm -rf "out2_${f}"
    mkdir -p "out2_${f}"
    suricata -r "${f}.pcap" -l "out2_${f}" -k none >/dev/null 2>&1

    LOG="out2_${f}/fast.log"
    total=0
    [ -f "$LOG" ] && total=$(wc -l < "$LOG")
    scan=$(grep -c 'ET SCAN' "$LOG" 2>/dev/null || true)
    [ -z "$scan" ] && scan=0

    echo "======================================================"
    echo "[$f] 总告警 ${total} 条，其中 ET SCAN 类 ${scan} 条"
    echo "======================================================"
    if [ "$total" -gt 0 ]; then
        echo "  告警类型分布（前 5）："
        sed -n 's/.*\[\*\*\] \[[0-9:]*\] \(.*\) \[\*\*\].*/  \1/p' "$LOG" \
            | sort | uniq -c | sort -rn | head -5
        echo "  ET SCAN 明细（前 3 条）："
        grep 'ET SCAN' "$LOG" | head -3 | cut -c1-160
    else
        echo "  （无告警）"
    fi
    echo
done

echo "完成。结果在 out2_*/fast.log"
echo "注意：配置已被修改。要恢复原配置： sudo cp ${CFG}.orig ${CFG}"
