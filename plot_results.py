# -*- coding: utf-8 -*-
"""
把慢速扫描实验的最终结果画成一张图（两个子图）。

用法：
    pip install matplotlib
    python plot_results.py
产出：
    figures/fig_final.png
"""
import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei", "DejaVu Sans"]
plt.rcParams["axes.unicode_minus"] = False
plt.rcParams["figure.dpi"] = 140

BASE = os.path.dirname(os.path.abspath(__file__))
FIG = os.path.join(BASE, "figures")
os.makedirs(FIG, exist_ok=True)

# ============================================================
# 实验数据（来自 Suricata 8.0.3 + ET Open，仅统计 ET 社区规则）
# ============================================================
conditions = [
    "A  nmap -sV\n标准载荷",
    "A2 nmap -sV -I0\n极低载荷",
    "B  nmap -sS\n裸 SYN",
    "D  nmap -sS\n裸 SYN + 慢速",
    "E  自制探测器\n有载荷·无指纹",
]
alerts = [28, 0, 0, 0, 0]
colors = ["#E45756", "#4C78A8", "#4C78A8", "#4C78A8", "#54A24B"]

fig, axes = plt.subplots(1, 2, figsize=(13.5, 4.8), gridspec_kw={"width_ratios": [3, 2]})

# ---------- 左图：五个条件的告警数 ----------
ax = axes[0]
bars = ax.bar(conditions, alerts, color=colors, width=0.6)
for b, v in zip(bars, alerts):
    ax.text(b.get_x() + b.get_width() / 2, v + 0.6, str(v),
            ha="center", fontsize=13, fontweight="bold")
ax.set_ylabel("ET SCAN 告警数")
ax.set_ylim(0, 33)
ax.set_title("只有带 nmap 指纹的扫描才被检出", fontsize=13)
ax.tick_params(axis="x", labelsize=9)
ax.grid(axis="y", ls="--", alpha=0.35)

# ---------- 右图：28 条告警的成分 ----------
ax = axes[1]
parts = ["含 “nmap” 字样\n2009358 / 2024364", "nmap 的 RDP 探测字节\n2023753", "检测到“扫描行为”"]
vals = [8, 20, 0]
pcolors = ["#F58518", "#E45756", "#4C78A8"]
bars2 = ax.barh(parts, vals, color=pcolors, height=0.55)
for b, v in zip(bars2, vals):
    ax.text(v + 0.4, b.get_y() + b.get_height() / 2, str(v),
            va="center", fontsize=13, fontweight="bold")
ax.set_xlim(0, 24)
ax.set_xlabel("告警条数")
ax.set_title("28 条告警的构成：全是“认工具”，不是“看行为”", fontsize=12)
ax.tick_params(axis="y", labelsize=8.5)
ax.grid(axis="x", ls="--", alpha=0.35)

fig.suptitle("低速率/无指纹扫描在 ET Open 320 条扫描规则下的检出结果（Suricata 8.0.3）",
             fontsize=13.5)
fig.tight_layout()
out = os.path.join(FIG, "fig_final.png")
fig.savefig(out)
plt.close(fig)
print("已保存：", out)
print()
print("结论：28 条告警中，8 条匹配 'nmap' 字符串，20 条匹配 nmap 的 RDP 探测字节，")
print("      0 条检测到端口扫描行为本身；换掉工具指纹后（条件 E）归零。")
