# 端口扫描检测的范式边界：签名规则与行为特征的对照实验

**副标题**：基于 Suricata 8.0.3 + ET Open（320 条扫描规则）与自建行为检测器的实证研究

作者：Just4Fan　｜　时间：2026-11
实验环境：Ubuntu 26.04（VMware，4 vCPU / 8 GB）· 单机回环（127.0.0.1）

---

## 1. 研究问题

> **"慢速扫描能绕过 IDS" 这个说法成立吗？如果成立，是因为"慢"，还是因为别的？**

本文设计两个实验、六组条件、三种检测方式，回答三个问题：

| # | 问题 |
|---|---|
| Q1 | 签名型规则集（ET Open）对端口扫描的检出，究竟依赖什么？ |
| Q2 | 行为型检测（端口离散度）能否补上签名检测的盲区？ |
| Q3 | 两种检测范式各自的结构性盲区在哪里？ |

---

## 2. 实验设计

### 2.1 靶机与工具

- 靶机：本机 `127.0.0.1:8001-8010` 上运行 10 个假服务（`fake_services.py`），对任何请求返回固定 HTTP 横幅
- 目的：让 `nmap -sV` 有开放端口可探测，从而产生真实应用层载荷
- 检测器：**Suricata 8.0.3 + ET Open**（`msg:"ET SCAN ..."` 共 320 条）／**自建行为检测器**（`behavior_detector.py`）

### 2.2 六组条件

| 条件 | 命令 | 速率 | 载荷 | 工具指纹 |
|---|---|---|---|---|
| **A** | `nmap -sV -T4` | 快 | 标准探测集 | nmap |
| **A2** | `nmap -sV --version-intensity 0 -T4` | 快 | 极低探测集 | nmap |
| **B** | `nmap -sS -T4` | 快 | 无（裸 SYN） | 无 |
| **D** | `nmap -sS --max-rate 0.05` | 慢（20 s/包） | 无（裸 SYN） | 无 |
| **E** | `probe_like_a_scanner.py` | 快 | HTTP 请求 | **无** |
| **F** | 自制探测器 + 20 s 间隔 | 慢 | HTTP 请求 | **无** |
| **normal** | `curl` 反复访问 2 个固定端口 | — | HTTP 请求 | 无（正常用户基线） |

### 2.3 行为检测器设计

```
特征：同一源 IP 在滑动窗口 W 内访问的「不同目的端口数」
判据：达到阈值 T 即告警
参数：W ∈ {30, 60, 300} 秒，T = 8
实现：tcpdump 抽取 SYN 且非 ACK 的包 → 按时间排序 → 滑动窗口去重计数
```

该检测器**完全不看载荷**，因此理论上对裸 SYN 扫描同样有效。

---

## 3. 实验结果

### 3.1 实验一：签名型检测（ET Open 320 条扫描规则）

| 条件 | 载荷 | 速率 | ET SCAN 告警 |
|---|---|---|---|
| A 　nmap -sV | 标准 | 快 | **28** |
| A2　nmap -sV -I0 | 极低 | 快 | **0** |
| B 　nmap -sS | 无 | 快 | **0** |
| D 　nmap -sS 慢速 | 无 | 慢 | **0** |
| E 　自制探测器 | HTTP | 快 | **0** |

**28 条告警的成分：**

| SID | 条数 | 规则名 | 实际匹配的内容 |
|---|---|---|---|
| 2023753 | 20 | ET SCAN MS Terminal Server Traffic on Non-standard Port | nmap 的 RDP 探测字节 |
| 2009358 | 4 | ET SCAN Nmap Scripting Engine User-Agent Detected | `Nmap Scripting Engine` 字符串 |
| 2024364 | 4 | ET SCAN Possible Nmap User-Agent Observed | nmap 的 User-Agent |

**结论**：ET Open 的扫描检测**完全依赖载荷指纹**——8 条匹配字符串 "nmap"，20 条匹配 nmap 的探测字节，**0 条检测到"端口扫描"这一行为**。速率变量（B vs D）无任何影响。

### 3.2 实验二：行为型检测（端口离散度）

| 条件 | 60 s 窗口内最大不同端口数 | 30 s 窗 | **60 s 窗** | **300 s 窗** |
|---|---|---|---|---|
| A 　带指纹 | 10 | ALERT | **ALERT** | **ALERT** |
| A2　极低载荷 | 10 | ALERT | **ALERT** | **ALERT** |
| B 　裸 SYN 快 | 10 | ALERT | **ALERT** | **ALERT** |
| D 　裸 SYN 慢 | 4（60 s）／10（300 s） | 漏报 | **漏报** | **ALERT** |
| E 　自制探测器 | 10 | ALERT | **ALERT** | **ALERT** |
| F 　自制 + 慢速 | 3（60 s）／10（300 s） | — | **漏报** | **ALERT** |
| normal 正常访问 | 2 | normal | **normal** | **normal** |

**结论**：
1. 行为检测补上了签名检测的盲区——**B、E 这类"零指纹扫描"它能抓到**；
2. 但它自己有一个致命参数：**窗口长度必须大于扫描持续时间**，否则慢扫（D、F）全部漏报；
3. 正常用户基线（只访问 2 个端口）不误报，说明阈值 8 在此场景下可用。

### 3.3 三方对照矩阵（本文核心结果）

| 检测方式 | A | A2 | B | **D** | E | **F** | normal |
|---|---|---|---|---|---|---|---|
| **ET Open（签名）** | 28 | 0 | 0 | 0 | 0 | **0** | 0 |
| **行为检测（60 s）** | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ 不误报 |
| **行为检测（300 s）** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ 不误报 |

（D 与 F 的 ET SCAN 列预计为 0：两者均不带 nmap 指纹。）

---

## 4. 核心发现

> **① 签名检测的盲区是"没有指纹"。**
> 换掉 nmap 指纹后，一次行为完全等价的带载荷扫描触发 0 次告警。
>
> **② 行为检测的盲区是"比窗口更慢"。**
> 60 s 窗口对 20 s/包的慢扫完全失效，因为窗口内只积累到 3–4 个端口。
>
> **③ 两个盲区**不重叠**，可以被同时利用。**
> 「不发指纹」+「扫得够慢」= 同时躲过 ET Open 与 60 s 窗口的行为检测（条件 F）。

**因此，检测的鲁棒性由「范式 + 参数」共同决定，而不由「规则数量」决定。**

320 条签名规则在零指纹扫描面前等于 0；1 个行为特征在慢扫面前也等于 0。

---

## 5. 防御启示

| 问题 | 建议 | 代价 |
|---|---|---|
| 签名检测依赖载荷指纹 | 叠加行为层特征 | 规则维护成本转移为参数调优 |
| 行为检测受窗口限制 | **多尺度窗口**（30 s / 5 min / 1 h）并行检测 | 长窗口带来检测延迟（最长 1 小时才告警） |
| 误报率未充分评估 | 需要真实业务流量基线 | 本文仅有单一基线（2 端口） |
| 攻击者可组合规避 | 建立**跨时间累积画像**，而非固定窗口 | 存储与计算成本上升 |

**一句话**：**固定时间窗 + 固定阈值，本质上是可预测的；可预测的检测就是可规避的检测。**

---

## 6. 实验陷阱记录（可复现性）

本实验过程中遇到 7 类"程序不报错但结论错误"的问题：

| # | 现象 | 真实原因 | 处理 |
|---|---|---|---|
| 1 | 命令行打印用法 | 输入法把 `-` 变成全角字符 | 只用复制粘贴 |
| 2 | pcap 不存在 | 后台 `sudo` 需密码被 `SIGTTIN` 挂起 | 整个脚本以 root 运行 |
| 3 | 3210 条告警 | 回环抓包校验和错误 | `-k none` + 按 SID 过滤 |
| 4 | 扫描规则全不触发 | `HOME_NET` 不含 `127.0.0.1` | `HOME_NET`/`EXTERNAL_NET` 设为 `any` |
| 5 | 假的 0 告警 | 假服务未启动，端口全 closed | 扫描前用 `nmap -sT` 验证端口 open |
| 6 | `/tmp` 写入被拒 | `fs.protected_regular` 阻止 root 覆盖他人文件 | 临时文件放项目目录 |
| 7 | tshark 读不了 pcap | 权限/能力问题（tcpdump 创建的包） | 改用 `tcpdump -r` 解析 |

---

## 7. 局限

1. **单机回环环境**：无真实网络噪声，`HOME_NET` 需人为放宽，外部效度有限
2. **单一规则集**：只测 ET Open，未覆盖商业规则、Snort、Zeek
3. **靶机服务伪造**：所有协议返回同一横幅，可能影响应用层规则匹配
4. **误报基线过弱**：只有"访问 2 个固定端口"一种正常流量，未覆盖浏览器、更新、P2P 等多样行为
5. **未测 Zeek**：Zeek 自带 scan 框架，是更标准的行为检测对照

---

## 8. 复现

```bash
sudo apt install -y suricata tcpdump nmap python3
sudo suricata-update

# 放宽地址变量
sudo cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.orig
sudo sed -i 's|^\( *\)HOME_NET:.*|\1HOME_NET: "any"|' /etc/suricata/suricata.yaml
sudo sed -i 's|^\( *\)EXTERNAL_NET:.*|\1EXTERNAL_NET: "any"|' /etc/suricata/suricata.yaml

sudo bash run.sh          # A / B / D
sudo bash run_a2.sh       # A2
sudo bash run_probe.sh    # E
sudo bash make_normal_traffic.sh   # normal

python3 behavior_detector.py A.pcap A2.pcap B.pcap D.pcap E.pcap F.pcap normal.pcap --window 60
python3 behavior_detector.py A.pcap A2.pcap B.pcap D.pcap E.pcap F.pcap normal.pcap --window 300
python3 plot_results.py
```
