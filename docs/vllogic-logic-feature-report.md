# vllogic-logic 功能对比报告

- 日期：2026-10-30
- 对象：`vllogic-logic`（VLLogic Logic20，20 通道） vs `sipeed-slogic-analyzer`（SLogic 8U2/16U3/32U3）
- 方法：仅静态阅读源码、协议头与 RTL，不访问硬件、不执行采集/编译/烧录
- 路径约定：正文表格为节省宽度，`api.c`/`protocol.c` 等省略仓库前缀，按所在小节/列区分；完整路径见文末“附录 A/B 证据索引”。RTL 位于 `logic_analyzer/fpga.h7p20/src/`
- 图例：✅ 有　◐ 部分/受限　❌ 无

---

## 1. 当前 vllogic-logic 功能清单

### 1.1 能力总表

| # | 能力 | 用户入口 | 实现位置 | 限制/说明 |
|---|------|----------|----------|-----------|
| 1 | 设备识别与扫描 | `sigrok-cli -d vllogic-logic --scan` | `src/hardware/vllogic-logic/api.c:185`、`api.c:137` | 仅接受 VID:PID `1209:6688`、`bcdDevice=0x0820`、产品串 `Logic20`；同 VID:PID 的 USB Sniffer 2（`0x0602`）被排除，见 `api.c:145-167` |
| 2 | `conn=` 精确选择 | `-d vllogic-logic:conn=<bus>.<addr>` 或 `VID.PID` | `src/hardware/vllogic-logic/api.c:91`、`api.c:199-215` | 用 `sr_usb_find()` 过滤；无匹配直接返回 NULL；`connection_id` 优先取 USB 端口路径，失败回退 bus.address（`api.c:249-262`） |
| 3 | 设备实例与序列号 | 扫描结果展示 vendor/model/serial | `api.c:255-289` | 序列号仅在能打开设备时读取（`api.c:170-178`）；打不开也仍接受该设备（`api.c:148-152`） |
| 4 | 20 路逻辑通道 | `--channels 0-19`，任意子集 | `api.c:264-271`、`protocol.h:53` | 固定 20 通道、无通道组；通道名 `0..19`；无 `SR_CONF_NUM_LOGIC_CHANNELS` |
| 5 | 逻辑→物理通道映射 | 自动 | `protocol.h:56-60`、`protocol.c:149-191` | 前 16 路两两交换（`1,0,3,2,...`），16..19 直通；映射后 `unitsize = 最高逻辑通道/8+1` |
| 6 | 通道 LUT 下发 | 自动 | `protocol.c:93-138`、`vllogic_usb.c:1197-1202` | 32 项 5-bit 升序环；FPGA 复位为全 0，LUT 必须显式重建，否则快照会重复通道 0 |
| 7 | 任意通道子集 | 只使能需要的通道 | `api.c:797-830`、`protocol.c:162-188` | 只把使能通道写入 mask，线上只传这些 lane；不是“连续前缀”模式，通道可以跳选（如 0、5、12） |
| 8 | 采样率 GET/SET/LIST | `-c samplerate=<Hz>` | `api.c:47-71`、`api.c:507-532`、`api.c:592-599` | 23 档：1M/2.5M/5M/10M/20M/24M/30M/40M/48M/60M/80M/96M/100M/120M/150M/200M/240M/300M/400M/480M/600M/800M/1200M；只接受精确档位，不静默钳位（`api.c:512-526`） |
| 9 | 硬件分频 | 随采样率自动 | `api.c:47-71`、`vllogic_usb.c:1204` | 时钟 2.4 GHz，`div` 2..120（`protocol.h:63-65`）；≥20 MHz 用 div=120..2 |
| 10 | PC 侧抽稀 | 随采样率自动 | `api.c:47-71`、`uhsif_rx.c:119-147`、`uhsif_rx.c:398` | <20 MHz 固定 div=120（20 MHz 线上），PC 按 1/2/4/8/20 抽稀到 10/5/2.5/1 MHz；抽稀相位跨快照保持 |
| 11 | 每速率通道上限 | 自动拒绝 | `api.c:77-89`、`api.c:816-825` | >800M:2ch、>400M:4ch、>200M:8ch、>160M:16ch、≤160M:20ch；超限 `SR_ERR_ARG` |
| 12 | `LIMIT_SAMPLES` | `-c limit_samples=N` 或 CLI `--samples N` | `api.c:101`、`api.c:534-538`、`uhsif_rx.c:132-136` | 计数的是抽稀后的输出样本；0=不限；解析器到点即停并 flush（`uhsif_rx.c:166-176`），会话侧再按已发送/已生产双条件收尾（`api.c:759-763`） |
| 13 | `VOLTAGE_THRESHOLD` GET/SET/LIST | `-c voltage_threshold=<V>` | `api.c:102`、`api.c:539-583`、`api.c:600-601` | 单端阈值：GET 返回 `(vth,vth)`（`api.c:475-480`），SET 取 low/high 平均；范围 -2.5..+5.0 V、步进 0.1；越界拒绝而非钳位（`api.c:548-557`） |
| 14 | 阈值实测模型 | 自动换算 PWM | `protocol.c:193-203`、`protocol.c:233-270` | `Vth = 2.405 - 0.0402*pwm0 + 0.0216*pwm1`；反解按符号选分支并带回退；旧 `V/3.3*127.5` 公式已废弃 |
| 15 | 采集中调阈值 | 采集运行时再 SET | `api.c:563-579` | RTL 支持采样中改 VBIAS（0x30/0x31）；驱动不发 ACK 等待，避免 ACK 被采集流吞掉；仅在 `state != IDLE && rx` 时走该路径 |
| 16 | 链路带宽探测 | 每次会话自动一次 | `api.c:844-876`、`vllogic_usb.c:1102-1180` | 3×200 ms COUNTER 模式突发，取中位数；结果乘 1.10 校准；仅在本会话首次采集前执行 |
| 17 | 严格带宽准入 | 默认严格，`VLLOGIC_STRICT=0` 放宽 | `api.c:887-983`、`api.c:347-352` | 需求 `rate*nchan/8`；实测×1.10×平台安全系数（Linux 0.98 / Windows 0.85），上限 400 MB/s；超限严格模式拒绝，宽松模式只告警 |
| 18 | 静态回退与人工覆盖 | `VLLOGIC_MAX_MBPS=<N>` | `api.c:936-963` | 探测失败按链路回退 350/35/5 MB/s（SS/HS/其它）；环境变量可强制覆盖并打印来源 |
| 19 | 首块头校验 | 自动 | `vllogic_usb.c:263-285`、`api.c:750-755` | 首个数据块必须 `div`、`mask`、`mode==0`、`capturing==1` 全匹配；否则报错并停止，避免“看起来有数据但配置没生效” |
| 20 | 启动看门狗 | 自动 | `api.c:764-771` | START 后 1000 ms 内没有 CRC 有效块即报错停止 |
| 21 | `drop_flag` 检测 | 自动日志 | `uhsif_rx.c:244-253`、`api.c:737-746` | FPGA FIFO 丢快照时 W2[22] 锁存；只统计 0→1 沿，因此只能说明“本次采集至少丢过一次”，不能给出丢块数量/位置 |
| 22 | 驱动内数据质量统计 | 结束时 `sr_info` 一行 | `uhsif_rx.h:41-55`、`uhsif_rx.c:207-258`、`api.c:703-715` | 13 项 `uhsif_stats`（blocks/acks/data_blocks/crc_fail/bad_len/seq_jumps/drop_blocks/junk_bytes/mask_mismatch/payload_words/partial/sink_short/sink_short_bytes）+ 5 项队列/链路原子计数 |
| 23 | 接收线程模型 | 自动 | `vllogic_usb.c:20-30`、`vllogic_usb.c:366-560`、`vllogic.h:33-48` | 事件线程独占 `libusb_handle_events_timeout()`；解析线程跑 UHSIF/反交织；会话线程发 datafeed；16×256 KiB URB、32 buffer、256×64 KiB chunk、每 tick 最多 4 MiB |
| 24 | 停止与收尾 | `Ctrl-C` / `--samples` 到点 / 关闭设备 | `api.c:615-635`、`api.c:685-724`、`vllogic_usb.c:788-842` | 先发 STOP 再停止重提交；保留 200 ms 排空窗口（`vllogic.h:57-58`）；取消 IN、join 两线程、排空队列、打统计、只发一次 `SR_DF_END` |
| 25 | 异常收尾 | 自动 | `api.c:756-758`、`api.c:772-777`、`vllogic_usb.c:822-834` | USB 致命错误/首块不匹配立即停；5 s 内 URB 未归零则标记 abandoned 并泄漏接收状态，避免 use-after-free |
| 26 | 独立自测 | `./vllogic-selftest [--quiet]` | `src/hardware/vllogic-logic/selftest.c:43`、`uhsif_rx.c:1267`、`Makefile.am:766` | 不依赖硬件/libusb/libsigrok；覆盖协议向量、LUT、头字段、CRC 重同步/重叠、sink short、17 个解析/抽稀/限额用例 |
| 27 | sigrok-cli 验证入口 | 驱动名 `vllogic-logic` | `api.c:1080-1099` | 已注册标准 `scan/dev_open/config_*/acquisition_*`；CLI 只能看到 samplerate/limit_samples/voltage_threshold/conn 四项 |

### 1.2 采样率分层

| 输出速率 | 硬件 `div` | PC 抽稀 | 线上速率 | 备注 |
|---|---:|---:|---:|---|
| 1 / 2.5 / 5 / 10 MHz | 120 | 20 / 8 / 4 / 2 | 20 MHz | 复用同一硬件档，靠抽稀降速 |
| 20 MHz | 120 | 1 | 20 MHz | 抽稀边界 |
| 24..1200 MHz | 100..2 | 1 | 等于输出速率 | 逐档独立 div，见 `api.c:53-70` |

### 1.3 统计字段口径

- `drop_blocks`：`drop_flag` 的 0→1 沿次数，不是丢块数（`uhsif_rx.c:244-253`）。
- `seq_jumps`：块头 seq 不连续次数，能提示丢块但不能定位（`uhsif_rx.c:225-228`）。
- `mask_mismatch`：块头通道 mask 与配置不一致次数（`uhsif_rx.c:254-255`）。
- `partial_snapshots`：STOP/重同步截断的快照数（`uhsif_rx.c:217-220`、`uhsif_rx.c:371-375`）。
- `sink_short*`：下游 chunk 层没接住的整样本（`uhsif_rx.c:149-162`）。
- 队列侧另有 `dropped_bytes`、`dropped_chunks`、`drop_flag_events`、`produced_bytes`、`blocks_seen`（`vllogic_usb.c:120-135`）。
- 需求文档中提到“96 项统计”，但当前代码实际是 13 个 `uhsif_stats` 字段 + 5 个原子计数；本报告按代码口径描述，不把外部测试项算进驱动能力。

### 1.4 当前明确没有的能力

- 无触发：无 `SR_CONF_TRIGGER_MATCH`、无预触发、无 `SR_DF_TRIGGER`（`api.c:99-104` 的 devopts 中没有 trigger 键）。
- 无 `LIMIT_MSEC`、无显式 `SR_CONF_CONTINUOUS` 声明；`limit_samples=0` 只是“一直采到用户停止”。
- 无 `PATTERN_MODE`、无外部时钟/时钟沿、无通道组、无 `SR_CONF_NUM_LOGIC_CHANNELS`。
- 无多设备独立 source key：固定用 `-1`（`api.c:1009`），关闭时也固定移除 `-1`（`api.c:416-417`）。
- 无重插恢复：`dev_open()` 直接用扫描时缓存的 bus/address 打开（`api.c:286-287`、`api.c:314`），不像 sipeed 那样按端口/序列号重新查找。
- 无结束报告行（拟合 MB/s、冷启动、drop/CRC/seq 汇总只有 `sr_info` 键值对，`api.c:703-715`）。

### 1.5 sigrok-cli 验证清单（静态核对，本次未执行采集）

| 验证点 | 命令/配置 | 预期 | 当前支持 |
|---|---|---|---|
| 枚举设备 | `sigrok-cli -d vllogic-logic --scan` | 列出 `VLLogic Logic20`，带 `conn`/serial | ✅ `api.c:185-295` |
| 按端口选择 | `-d vllogic-logic:conn=<bus>.<addr>` | 只打开指定设备 | ✅ `api.c:199-215` |
| 定长采集 | `-c samplerate=100000000 -C 0-7 --samples 100000` | 8 通道、100 MS/s、10 万样本 | ✅ `api.c:507-532`、`api.c:797-830` |
| 任意通道子集 | `-C 0,5,12` | 只传 3 条 lane，unitsize=2 | ✅ `protocol.c:162-188` |
| 阈值 | `-c voltage_threshold=<V>` | 单端阈值，越界报错 | ✅ `api.c:539-583`（元组 CLI 写法随 sigrok-cli 版本） |
| 样本限额 | `--samples N` / `-c limit_samples=N` | 到点自动 STOP 并收尾 | ✅ `api.c:759-763`、`api.c:1045-1059` |
| 严格准入 | `VLLOGIC_STRICT=1`（默认） | 超带宽直接拒绝并打印原因 | ✅ `api.c:965-982` |
| 触发/按时间 | `-t ...` / `--time N` | 当前应明确报“不支持”，不能假装成功 | ❌ 无 trigger/`LIMIT_MSEC` 键 |
| 统计 | 采集结束看日志 | 打印 blocks/CRC/seq/drop/sink 汇总 | ✅ `api.c:703-715` |

---


## 2. 竞品 sipeed-slogic-analyzer 功能矩阵

### 2.1 总矩阵

| 能力 | sipeed 结论 | sipeed 证据 | vllogic 结论 | vllogic 证据/说明 |
|---|---|---|---|---|
| 采样率 GET/SET/LIST | ✅ 有，且按“链路×通道”动态裁剪 | `src/hardware/sipeed-slogic-analyzer/api.c:41`、`api.c:307-317`、`api.c:411-420`、`slogic/slogic_data.c:92-152` | ✅ 有，但固定 23 档、不随链路裁剪 | `src/hardware/vllogic-logic/api.c:47-71`、`api.c:592-599` |
| 通道数与通道组 | ✅ 有 `SR_CONF_NUM_LOGIC_CHANNELS` + `LA` 组 | `api.c:45`、`api.c:191-199`、`api.c:273-275`、`api.c:421-428` | ◐ 固定 20 通道、无组、无 NUM 键 | `api.c:264-271`、`api.c:99-104` |
| 动态通道使能 | ✅ 有：使能变化自动选最小覆盖档 | `api.c:368-398`、`api.c:318-335` | ✅ 有：任意子集直接改 mask，比“前缀档位”更灵活 | `api.c:797-830`、`protocol.c:162-188` |
| 触发 `TRIGGER_MATCH` | ✅ 有：zero/one/rising/falling/edge | `api.c:42`、`api.c:48-51`、`api.c:433-435` | ❌ 无 | `api.c:99-104` 无 trigger 键 |
| 触发实现位置 | ◐ 主机侧软件触发，不是硬件触发 | `slogic/slogic_data.c:304-359`、`slogic_data.c:508-549` | ❌ 无 | — |
| 单阶段/多阶段 | ◐ 仅单阶段；>1 阶段直接报错 | `protocol.c:100-103` | ❌ 无 | — |
| 预触发 / `CAPTURE_RATIO` | ✅ 有：GET/SET 0..100，预触发样本 = limit×ratio/100 | `api.c:43`、`api.c:283-285`、`api.c:347-352`、`protocol.c:126-128` | ❌ 无 | — |
| trigger 包 | ✅ 有：`std_session_send_df_trigger()` | `protocol.c:53-57`、`protocol.c:146-147`、`slogic_data.c:541-543` | ❌ 无 | — |
| `LIMIT_SAMPLES` | ✅ 有，样本精确计数 | `api.c:39`、`api.c:280-282`、`api.c:344-346`、`slogic_data.c:444-447` | ✅ 有 | `api.c:101`、`api.c:534-538`、`uhsif_rx.c:132-136` |
| `LIMIT_MSEC` | ❌ 无 | devopts 列表 `api.c:37-46` 中没有该键 | ❌ 无 | devopts `api.c:99-104` 中没有该键 |
| `CONTINUOUS` | ◐ 声明支持，但没有 GET/SET；靠 `limit_samples=0` 表达 | `api.c:38`、`protocol.c:144` | ◐ 未声明；`limit_samples=0` 隐式连续 | `api.c:534-538`、`api.c:759-763` |
| `PATTERN_MODE` | ✅ 有 3 种：Normal / USB connection test / Emulation | `api.c:40`、`api.c:337-343`、`api.c:430-432`、`slogic/slogic.c:44-48` | ❌ 无 | `api.c:99-104`；协议头虽定义 `MODE_WAVE=0x05`（`protocol.h:84`）但驱动未使用 |
| 外部时钟 / 时钟沿 | ❌ 无 | devopts `api.c:37-46`；`clock_base_mhz` 只是内部 PLL 基频选择（`slogic/slogic.h:154-162`） | ❌ 无 | devopts `api.c:99-104`；RTL 只有内部 PLL（`logic_analyzer/fpga.h7p20/src/top.v:70-86`） |
| 阈值 GET/SET/LIST | ✅ 有：0..6 V、步进 0.1 | `api.c:44`、`api.c:286-289`、`api.c:353-356`、`api.c:436-438` | ✅ 有：-2.5..5.0 V、步进 0.1 | `api.c:102`、`api.c:539-583`、`api.c:600-601` |
| 运行中可调阈值 | ❌ 否：只在下次 configure 生效 | `protocol.c:141-142`、`slogic/slogic.c:532` | ✅ 是：采集中可直接发 0x30/0x31 | `api.c:563-579` |
| 多设备 | ✅ 有：按型号/PID 全量枚举 | `api.c:142-205`、`slogic/slogic.h:54-59` | ◐ 扫描支持多台，但 session source key 冲突 | `api.c:223-290`、`api.c:1009` |
| `conn=` | ✅ 有 | `api.c:132-140` | ✅ 有 | `api.c:199-215` |
| 重插恢复 | ✅ 有：按端口路径优先、序列号兜底重新查找 | `api.c:219-240`、`api.c:221` | ❌ 无 | `api.c:286-287` 缓存 bus/address，`api.c:314` 直接打开 |
| 每设备唯一负数 source key | ✅ 有：由 sdi 指针派生 | `protocol.c:60-69` | ❌ 无：固定 `-1` | `api.c:1009`、`api.c:416-417` |
| 数据质量/overflow | ◐ 主机队列溢出即 abort；设备 FIFO 溢出只能靠速率看门狗推断 | `slogic/slogic_usb.c:549-576`、`slogic_usb.c:812-850`、`slogic/slogic.c:183-248` | ✅ 有设备侧 `drop_flag`、CRC、seq、mask 统计 | `uhsif_rx.h:41-55`、`uhsif_rx.c:207-258` |
| 速率自适应/停滞恢复 | ✅ 有：最小 4 URB、一次 RUN 重试、停滞重配 | `slogic/slogic_usb.c:1056-1082`、`slogic/slogic.c:216-232`、`slogic_usb.c:812-850` | ◐ 有探测+准入，但失败不自动降速 | `api.c:887-983` |
| 前端集成 | ✅ `config_list` 全量、`config_channel_set`；无 `config_commit` | `api.c:400-443`、`api.c:368-398`、`api.c:445-464` | ◐ `config_list` 有，无 `config_channel_set`/`config_commit` | `api.c:592-609`、`api.c:1080-1097` |
| 固件上传/DFU | ❌ 无；DFU PID 明确“不处理” | `slogic/slogic.h:59` | ❌ 无 | 驱动内无 DFU/上传代码 |
| 校准/私有键 | ◐ 无逐通道校准；阈值默认 1.7 V，无校准模型；无私有键 | `api.c:188-189`、`api.c:240` | ◐ 有全局实测阈值模型，无逐通道校准、无私有键 | `protocol.c:193-203`、`protocol.c:233-270` |

### 2.2 触发链路（sipeed 的完整路径）

| 环节 | 行为 | 证据 |
|---|---|---|
| 用户配置 | `-t <ch>=<match>`，支持 zero/one/rising/falling/edge | `api.c:48-51`、`api.c:433-435` |
| 读取触发 | `sr_session_trigger_get()`，只允许 1 个 stage | `protocol.c:98-103` |
| 通道合法性 | 触发通道必须已使能且 `< cur_samplechannel` | `protocol.c:109-115` |
| 预触发 | 有 limit 时 `pretrigger = limit * capture_ratio / 100` | `protocol.c:126-128` |
| 扫描 | 在主机侧对解包后的样本逐点匹配；整字跳跃优化 | `slogic_data.c:280-359` |
| 缓存/回放 | 触发前环形缓存，触发后先 flush 预触发再继续发 | `slogic_data.c:368-400`、`slogic_data.c:468-505` |
| 触发包 | 在触发样本索引处发 `SR_DF_TRIGGER` | `protocol.c:53-57`、`slogic_data.c:541-543` |
| 无 limit 时 | `capture_ratio` 被忽略，触发点即流起点 | `protocol.c:126-128`、`slogic_data.c:394` |

### 2.3 限额、连续、模式

| 项 | sipeed | vllogic | 差异结论 |
|---|---|---|---|
| `LIMIT_SAMPLES` | 精确样本计数，`0=continuous` | 抽稀后输出样本计数，`0=unlimited` | 等价 |
| `LIMIT_MSEC` | ❌ | ❌ | 双方都缺，适合用 `sr_sw_limits` 补 |
| `CONTINUOUS` | devopts 声明，无 GET/SET | 未声明，隐式 | 都只能靠“limit=0 + 用户停止” |
| `PATTERN_MODE` | Normal/USB test/Emulation | 无 | sipeed 有完整前端入口，但模式语义是厂商私有 |
| WAVE | sipeed 的 “Emulation” 是厂商模式 | 驱动未用 0x05；RTL 的 mode=1 只是 `virtual_wave` 计数器（`request_handler.v:36`、`logicin.v:190`） | 不应把 WAVE 当已实现功能暴露 |
| 外部时钟 | ❌ | ❌ | 需 RTL 增加时钟输入选择 |

### 2.4 多设备、重插、source key

| 项 | sipeed | vllogic |
|---|---|---|
| 扫描多台 | 按型号表遍历 PID，每个 USB 设备建一个 sdi（`api.c:142-205`） | 遍历 libusb 列表，每个匹配设备建一个 sdi（`api.c:223-290`） |
| `conn=` | 先 `sr_usb_find` 得到 wanted，再按 bus/address 求交（`api.c:132-153`） | 先 `sr_usb_find`，再按 bus/address 过滤（`api.c:208-239`） |
| 端口路径 | `slogic_port_path()` 写入 `connection_id`（`api.c:170-172`） | `usb_get_port_path()` 写入 `connection_id`（`api.c:249-253`） |
| 重插 | `dev_open` 用 `slogic_find(pid, connection_id, serial)` 重新枚举（`api.c:219-222`） | 直接用旧 bus/address（`api.c:286-287`、`api.c:314`） |
| source key | `-1 - ((uintptr_t)sdi >> 4 & 0x3fffffff)`，每设备唯一（`protocol.c:66-69`） | 固定 `-1`（`api.c:1009`），关闭也移除 `-1`（`api.c:416-417`） |
| 结论 | ✅ 多设备/重插可用 | ◐ 单设备稳定；同 session 多设备会 key 冲突，重插需重新 scan |

### 2.5 质量、报告、前端集成

| 项 | sipeed | vllogic |
|---|---|---|
| 链路速率统计 | 最小二乘拟合 MB/s + 冷启动 ms（`slogic_data.c:603-650`） | 无拟合；只有探测一次（`api.c:844-876`） |
| 结束报告 | `slogic-report v1 ... mbps= cold_ms= trig= q_peak_mb=` 一行（`slogic_data.c:656-699`） | 13 项 `sr_info` 键值对（`api.c:703-715`） |
| 主机队列溢出 | 超过 `max_queue_bytes` 直接 abort `"host-too-slow"`（`slogic_usb.c:568-576`） | chunk 环满时丢 chunk 并计数（`vllogic_usb.c:242-256`、`vllogic_usb.c:313-314`） |
| 设备侧丢数 | 无 drop 标志；靠停滞/速率推断 | `drop_flag` + CRC + seq + mask 四类统计（`uhsif_rx.c:207-258`） |
| 停滞恢复 | 一次 RUN 重试 + 重配（`slogic.c:223-229`、`slogic_usb.c:1056-1082`） | 1 s 无块或 USB 致命错误即停（`api.c:756-771`） |
| `config_list` | 全量键（`api.c:400-443`） | 仅 samplerate/threshold/conn（`api.c:592-609`） |
| `config_channel_set` | 有（`api.c:368-398`） | 无（依赖通用 core 改 `ch->enabled`） |
| `config_commit` | 无；api_version 1 不需要 | 无；api_version 1 不需要 |
| 固件/校准 | 无上传；阈值固定 1.7 V | 无上传；全局阈值模型已实测校准 |

---

## 3. 差距与机会

### 3.1 我们已有、sipeed 没有

| 能力 | 价值 | 我们的证据 | 说明 |
|---|---|---|---|
| 设备侧 `drop_flag` + CRC/seq/mask 统计 | 高：能区分“链路丢数”与“主机处理不过来” | `uhsif_rx.c:207-258`、`api.c:737-746` | sipeed 协议没有等价块头，只能推断 |
| 链路探测 + 严格准入 | 高：采集前就拒绝必然丢数的配置 | `api.c:844-983`、`vllogic_usb.c:1102-1180` | sipeed 是“先跑，跑不动再 abort/重配” |
| 采集中调阈值 | 高：扫阈值不用反复重启采集 | `api.c:563-579` | sipeed 只在下次 configure 生效 |
| 任意通道子集 | 中高：只传需要的 lane，省带宽 | `protocol.c:162-188`、`api.c:797-830` | sipeed 按最高使能通道选“连续前缀档”，会多传中间通道 |
| PC 抽稀低速率档 | 中：1/2.5/5/10 MHz 无需改硬件分频 | `api.c:47-71`、`uhsif_rx.c:119-147` | sipeed 依赖其固件档位 |
| 首块头校验 + 启动看门狗 | 中高：配置没生效时立刻失败，不产出伪数据 | `vllogic_usb.c:263-285`、`api.c:764-771` | sipeed 主要靠速率/停滞判断 |
| 13+5 项驱动内统计 | 中：现场排障可定位到 CRC/seq/mask/sink | `uhsif_rx.h:41-55` | sipeed 只有聚合 report 行 |
| 无硬件自测 | 中：CI 可跑，不需要设备 | `selftest.c:43`、`uhsif_rx.c:1267` | sipeed 未见等价独立自测入口 |

### 3.2 sipeed 有、我们没有（价值/成本/RTL 依赖）

| 功能 | 价值 | 成本 | RTL/固件依赖 | 结论 |
|---|---|---|---|---|
| 主机侧软件触发 | 高：逻辑分析仪最核心的缺失能力 | 中（3–4 人日） | 无 | **优先做**，见 P0 |
| 预触发 `CAPTURE_RATIO` | 高：没有预触发，触发点前的现场看不到 | 低（随 P0，0.5 人日） | 无 | 与 P0 一起做 |
| `SR_DF_TRIGGER` 触发包 | 中：前端/解码器需要知道触发位置 | 低（随 P0） | 无 | 与 P0 一起做 |
| `LIMIT_MSEC` | 中：按时间采集比按样本数直观 | 低（1 人日） | 无 | P1 |
| 显式 `CONTINUOUS` | 中：前端可正确显示“连续采集” | 低（随 P1） | 无 | P1 |
| 每设备唯一 source key | 高：多设备同 session 的正确性 | 低（0.5 人日） | 无 | P2 |
| 重插恢复 | 中高：USB 抖动/重新插拔后不用重扫 | 中（1–2 人日） | 无 | P3 |
| `PATTERN_MODE` | 中：Normal/Counter 可做链路自检 | 低（1 人日） | 无（RTL 已有 0x04/0x06） | P4 |
| 速率列表按链路×通道裁剪 | 中：避免用户选到必然失败的组合 | 中（1–1.5 人日） | 无 | P5 |
| 结束报告行（拟合/冷启动） | 中：现场性能回归可量化 | 低（1–1.5 人日） | 无 | P6 |
| 通道组 | 中低：前端组织更清晰 | 中（1 人日，纯软件分组） | 无；但“组不同阈值”需 RTL | P7 的一部分 |
| 停滞自动重配 | 中：长采集更鲁棒 | 中高（3 人日） | 无 | 可后置；先做 P6 观察 |
| 固件上传/DFU | 低（对本产品） | 高 | 有（DFU + 固件包） | 不做 |
| 硬件触发 | 高 | 高 | 有（触发状态机 + 预触发 FIFO） | 等 RTL |
| 外部时钟/时钟沿 | 中 | 高 | 有（时钟输入 MUX/边沿检测） | 等 RTL |
| 真正 WAVE/任意码型 | 低中 | 高 | 有（码型 RAM/ROM） | 不做假实现 |
| 逐通道阈值 | 高 | 高 | 有（多路 VBIAS/DAC） | 等 RTL |

### 3.3 双方都没有、驱动层可做

| 机会 | 用户价值 | 实现位置 | 是否需 RTL | 备注 |
|---|---|---|---|---|
| `LIMIT_MSEC` + 统一 `sr_sw_limits` | 高 | `api.c` devopts/config/receive_data | 否 | 两家的共同空白，可直接补齐 |
| 自动选择“链路能承载的最高档” | 中高 | `api.c:config_set/config_list` + 探测结果 | 否 | 现在是“用户选，超了拒绝”；可改为建议/钳位并告知 |
| 触发 holdoff / 多阶段软件触发 | 中 | `uhsif_rx.c` 触发扫描器 | 否 | sipeed 只有单阶段；纯软件可扩展 |
| “最近 N 秒”滚动缓存 | 中高：抓偶发故障不用一直落盘 | `vllogic_usb.c` chunk 环 + `api.c` | 否 | 只保留尾部窗口，停止时导出 |
| 通道重命名/分组元数据 | 中低 | `api.c:scan` + `sr_channel_group_new` | 否 | 纯展示，不影响采样 |
| 采样率/通道/阈值的“配置快照”日志 | 中 | `api.c:dev_acquisition_start` | 否 | 便于复现，不增加协议 |
| 队列高水位/背压告警 | 中 | `vllogic_usb.c` chunk 环 | 否 | sipeed 有 q_peak；我们可补 |
| 触发条件持久化到 session 文件 | 中低 | `api.c` 配置层 | 否 | 需与前端约定键名 |
| 多设备近似同步启动 | 中 | `api.c` 多 sdi 协调 | 否（精确同步需硬件） | 只能做到“先后 START”，不能保证同拍 |
| 采样数据 CSV/统计旁路 | 低中 | 输出模块，不是驱动 | 否 | 不建议塞进驱动 |

---

## 4. 建议（P0–P7）

| 优先级 | 功能 | 用户价值 | 实现位置 | 需 RTL/固件 | 预估工作量 | 风险 |
|---|---|---|---|---|---|---|
| **P0** | 软件触发 + `TRIGGER_MATCH` + `CAPTURE_RATIO` + trigger 包 | 补上逻辑分析仪最核心能力；可抓“触发前发生了什么” | `api.c` 增 devopts/config_get/set/list；`uhsif_rx.c` 增触发匹配 + 预触发环（参考 `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_data.c:304-359` 的扫描器与 `:468-505` 的预触发环）；`vllogic_usb.c` chunk 带样本索引；`receive_data()` 在索引处发 `std_session_send_df_trigger()` | **否（纯驱动）** | 3–4 人日 | 预触发内存上限（建议同 sipeed 1 GiB 上限）；触发索引要跨 chunk 精确切分；抽稀后索引必须用输出域；`limit_samples` 与触发后剩余样本的语义要定清楚 |
| **P1** | `LIMIT_MSEC` + 显式 `CONTINUOUS` | 按时间采集；前端能正确显示连续模式 | `api.c` devopts + `sr_sw_limits_init/config_get/config_set/acquisition_start/check`；`receive_data()` 每 tick 检查 | **否（纯驱动）** | 1 人日 | 时间基准从 START 还是首块算；与 `LIMIT_SAMPLES` 同时设置时的优先级；`samples_read` 不能重复计数 |
| **P2** | 每设备唯一负数 source key | 同一 session 多台 Logic20 不互踢 | `api.c:1009` 改为 sipeed 同款指针派生；`api.c:416-417` 移除时用同一 key | **否（纯驱动）** | 0.5 人日 | 指针截断后仍可能碰撞（概率极低）；负数范围要避开 libsigrok 的 fd 语义；key 必须在整个 session 生命周期稳定 |
| **P3** | 打开时清理残留 + 按端口路径重插恢复 | 上次异常退出/重新插拔后无需重扫 | `api.c:dev_open` 增加 `sync_drain` + STOP/FLUSH 静默；用 `connection_id`（端口路径）优先、序列号兜底重新 `sr_usb_find`；更新 `usb->bus/address` | **否（纯驱动）** | 1–2 人日 | 端口路径在 HUB/Windows 上可能变化；必须校验 PID/bcdDevice，避免误抓另一台；重插后 `devhdl`/claim 顺序要重排 |
| **P4** | `PATTERN_MODE`：Normal / Counter（不暴露 WAVE） | Normal 保持现有采样；Counter 作为确定性链路自检图样 | `api.c` 增 `SR_CONF_PATTERN_MODE` GET/SET/LIST；`vllogic_usb.c:1210` 按模式发 0x04/0x06；`uhsif_rx.c` 对 Counter 绕过反交织并明确标注；首块校验改为期望模式而非硬编码 0 | **否（RTL 已支持 0x04/0x06；`request_handler.v:108-110`）** | 1–1.5 人日 | Counter 的 payload 是内部计数器，不是通道快照；若直接走现有 parser 会产出无意义波形；WAVE（0x05）只是 `virtual_wave` 计数器，不要暴露 |
| **P5** | 速率列表按“链路×通道”动态裁剪 + 钳位告警 | 用户看不到必然失败的组合；减少“启动即拒绝” | `api.c:config_list(SR_CONF_SAMPLERATE)` 用当前链路速度 + 使能通道数过滤；`config_set` 超限时给明确告警并按策略钳位（或保留严格拒绝） | **否（纯驱动）** | 1–1.5 人日 | 通道使能变化后列表需重新查询；前端可能缓存列表；钳位必须打印“请求值→实际值”，不能静默 |
| **P6** | 结束报告行：拟合 MB/s、冷启动、drop/CRC/seq | 性能回归/现场排障可量化，不用翻多行日志 | `vllogic_usb.c` 在 `in_cb` 记录每 URB 时间/字节；`api.c:vllogic_finish()` 最小二乘拟合并打印 `vllogic-report v1 ...`；复用现有 `uhsif_stats` | **否（纯驱动）** | 1–1.5 人日 | 回调时间受调度抖动影响；要用单调时钟；短采集 fit_n<2 时输出 `nan`；不要把“探测值”当“实测值” |
| **P7** | 逐通道阈值校准 / 通道组 | 多通道同阈值下 duty 偏差可解释、可校准 | 纯驱动部分：`api.c` 增通道组与校准元数据、按实测表给全局建议阈值；逐通道生效需 RTL 多路 VBIAS/DAC | **是（逐通道生效需 RTL；分组展示可纯驱动）** | 驱动 2 人日 + RTL 2–3 周 | 现有硬件只有 PWM0/PWM1 两路全局阈值（`protocol.h:97-99`、`api.c:475-480`）；在 RTL 未支持前暴露“逐通道阈值”就是假实现；校准数据来自 `logic_analyzer/docs/前端改良建议.20261029.md` 的实测表，需版本化 |

### 4.1 P0 落地要点

1. 触发匹配在**抽稀后的输出样本域**做，保证 `trig_index` 与发给前端的样本索引一致。
2. 预触发环按 `limit_samples * capture_ratio / 100` 分配；无 limit 时按固定上限（如 1 GiB / unitsize）并告警。
3. chunk 元数据增加 `first_sample_index`；会话线程在跨触发点的 chunk 处切成两段，先发前半段，再发 `SR_DF_TRIGGER`，再发后半段。
4. `TRIGGER_MATCH` 先支持 zero/one/rising/falling/edge，和 sipeed 对齐；多 stage 先拒绝并给出明确错误。
5. 触发超时（一直不触发）要有用户可停的路径，不能把 session 卡死。

### 4.2 P1 落地要点

- `sr_sw_limits` 已是 libsigrok 公共设施，直接复用可同时拿到 `LIMIT_SAMPLES`/`LIMIT_MSEC` 的一致性。
- `SR_CONF_CONTINUOUS` 是能力声明键，不参与 GET/SET；声明后前端才会显示连续采集。
- 建议语义：`limit_samples=0 && limit_msec=0` 才是连续；任一非 0 都按限额停。

### 4.3 P2 落地要点

- 采用 `-1 - (int)(((uintptr_t)sdi >> 4) & 0x3fffffff)`，与 sipeed `protocol.c:66-69` 同款。
- 添加和移除必须用同一个函数计算，避免 `-1` 与派生 key 混用。
- 多设备场景加一条 `sr_info` 打印实际 key，便于排障。

### 4.4 不建议现在做的

- 不要把 `MODE_WAVE`（0x05）包装成“任意波形/码型”卖点：RTL 只是 `virtual_wave` 计数器（`request_handler.v:36`、`logicin.v:190`）。
- 不要在没有多路 VBIAS 的情况下提供“逐通道阈值”UI。
- 不要把 Counter 模式当正常采样模式展示；它没有通道语义。
- 不要用“提高静态 cap”替代链路探测；探测+准入已经是我们的优势。

---

## 5. 必须等 RTL/固件的功能

| 功能 | 当前 RTL/固件状态 | 为什么驱动做不了 | 需要什么 | 证据 |
|---|---|---|---|---|
| 硬件触发 | `logicin.v` 里的 `trigger_edge` 只是采样节拍同步，不是触发匹配；没有触发状态机/预触发 FIFO | 驱动只能看到已经上传的样本；要“触发前”数据必须设备端缓存 | 触发比较器（每通道 match/edge）、预触发 FIFO、触发点写入块头/独立事件包 | `logic_analyzer/fpga.h7p20/src/logicin.v:63-72`、`logicin.v:95` |
| 外部时钟 / 时钟沿 | 采样时钟来自内部 PLL；`iserdes_clk_div` 只做分频 | 没有时钟输入选择、边沿极性、丢失检测寄存器 | 外部时钟 MUX + 边沿检测 + 状态位；驱动再暴露 `SR_CONF_EXTERNAL_CLOCK` | `top.v:70-86`、`uhsif_logic.v:75` |
| 真正的 pattern / WAVE | `mode=1` 只切到 `virtual_wave` 计数器；`MODE_WAVE=0x05` 驱动未用 | 没有码型存储/播放逻辑，无法生成用户定义波形 | 码型 RAM/ROM、循环/单次、速率控制；或明确只做固定测试图样 | `protocol.h:84`、`request_handler.v:36`、`logicin.v:190` |
| 精确丢块位置/时间戳 | 块头只有锁存的 `drop_flag`、seq、div、mask；没有样本索引/时间戳 | 只能统计 0→1 沿和 seq 跳变，无法知道丢了哪一块、何时丢 | 扩展块头（样本计数/时间戳/丢块计数）或独立事件包；注意 UHSIF v2.2 兼容性 | `uhsif_rx.c:45-70`、`uhsif_rx.c:244-253` |
| 逐通道/分组阈值 | 只有 `VBIAS_PWM0`/`VBIAS_PWM1` 两路全局 DAC | 一个 PWM 值作用于所有通道，软件无法让每个通道不同 | 多路 VBIAS/DAC 或通道分组模拟开关 + 寄存器 | `protocol.h:90-91`、`protocol.h:97-99`、`api.c:475-480` |
| 多设备硬件同步采样 | 无同步触发/时钟总线 | 软件先后 START 只能近似同步，不能保证同拍 | 同步触发线/共享时钟/广播 START | `uhsif_logic.v:29-51`（无同步接口） |
| 固件上传/DFU | 驱动不处理 DFU；本产品也没有固件包管理 | libsigrok 驱动不适合做 DFU 主流程 | 独立 DFU 工具/固件包；驱动只做版本识别 | `protocol.h:42-46`（仅识别 bcdDevice） |

---

## 6. 结论

**我们强在“可信采集”而不是“功能数量”**：设备侧 `drop_flag` + CRC/seq/mask 统计、首块头校验、启动看门狗、链路探测 + 严格准入、采集中调阈值、任意通道子集，这些让 vllogic-logic 在“采到的数据是否可信”上明显强于 sipeed；sipeed 的强项是**主机侧软件触发/预触发、限额与连续的完整前端语义、多设备/重插恢复、链路自适应与报告**，这些恰好都是纯驱动层能补的。

**最值得先做**：P2（半天，修多设备 source key 的正确性）→ P0（3–4 天，补触发/预触发/trigger 包，直接补上最大功能缺口）→ P1（1 天，`LIMIT_MSEC` + 显式 `CONTINUOUS`）。P3/P5/P6 紧随其后；P4 只做 Normal/Counter，且 Counter 必须标注为链路自检图样。

**不要做假实现**：硬件触发、外部时钟、真正 WAVE、逐通道阈值、精确丢块位置都必须等 RTL/固件；在 RTL 没有对应状态机/多路 DAC/扩展块头之前，驱动层只能做统计、告警和近似，不应把它们包装成已实现能力。保持“严格准入 + 明确失败”的产品性格，比静默钳位/静默丢数更有价值。

---

## 附录 A：vllogic-logic 证据索引（完整路径）

| # | 能力/结论 | `file:line` |
|---|---|---|
| A1 | 同 VID:PID 设备识别（bcdDevice/产品串） | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:137` |
| A2 | 扫描主循环 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:185` |
| A3 | `conn=` 过滤 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:208` |
| A4 | 20 通道创建 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:264` |
| A5 | 逻辑→物理通道排列 | `libsigrok_vllogic/src/hardware/vllogic-logic/protocol.h:58` |
| A6 | 通道映射构建 | `libsigrok_vllogic/src/hardware/vllogic-logic/protocol.c:149` |
| A7 | 32 项 LUT 构建 | `libsigrok_vllogic/src/hardware/vllogic-logic/protocol.c:93` |
| A8 | 23 档采样率表 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:47` |
| A9 | 每速率通道上限 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:77` |
| A10 | PC 抽稀与相位 | `libsigrok_vllogic/src/hardware/vllogic-logic/uhsif_rx.c:119` |
| A11 | `LIMIT_SAMPLES` 配置 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:534` |
| A12 | 解析器样本限额 | `libsigrok_vllogic/src/hardware/vllogic-logic/uhsif_rx.c:132` |
| A13 | 阈值 SET/范围校验 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:539` |
| A14 | 采集中调阈值 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:568` |
| A15 | 阈值实测模型 | `libsigrok_vllogic/src/hardware/vllogic-logic/protocol.c:200` |
| A16 | 链路探测入口（3×200 ms） | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:844` |
| A17 | 探测实现（COUNTER 模式） | `libsigrok_vllogic/src/hardware/vllogic-logic/vllogic_usb.c:1102` |
| A18 | 带宽严格准入 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:887` |
| A19 | `VLLOGIC_STRICT` 读取 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:347` |
| A20 | 首块头校验 | `libsigrok_vllogic/src/hardware/vllogic-logic/vllogic_usb.c:268` |
| A21 | 1 s 启动看门狗 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:764` |
| A22 | `drop_flag` 0→1 沿统计 | `libsigrok_vllogic/src/hardware/vllogic-logic/uhsif_rx.c:248` |
| A23 | 统计字段定义 | `libsigrok_vllogic/src/hardware/vllogic-logic/uhsif_rx.h:41` |
| A24 | 事件线程 | `libsigrok_vllogic/src/hardware/vllogic-logic/vllogic_usb.c:473` |
| A25 | 解析线程 | `libsigrok_vllogic/src/hardware/vllogic-logic/vllogic_usb.c:515` |
| A26 | STOP 起始 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:615` |
| A27 | 收尾/END 一次 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:685` |
| A28 | 独立自测入口 | `libsigrok_vllogic/src/hardware/vllogic-logic/selftest.c:43` |
| A29 | 自测用例集合 | `libsigrok_vllogic/src/hardware/vllogic-logic/uhsif_rx.c:1267` |
| A30 | 驱动注册/CLI 入口 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:1080` |
| A31 | 固定 `-1` source key | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:1009` |
| A32 | `config_list` 范围 | `libsigrok_vllogic/src/hardware/vllogic-logic/api.c:592` |
| A33 | URB abandon 保护 | `libsigrok_vllogic/src/hardware/vllogic-logic/vllogic_usb.c:822` |

## 附录 B：sipeed-slogic-analyzer 证据索引（完整路径）

| # | 能力/结论 | `file:line` |
|---|---|---|
| B1 | devopts 能力声明 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:37` |
| B2 | 支持的触发类型 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:48` |
| B3 | 触发映射/单阶段限制 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/protocol.c:90` |
| B4 | 主机侧触发扫描 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_data.c:304` |
| B5 | 预触发比例计算 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/protocol.c:126` |
| B6 | 预触发环形缓存 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_data.c:468` |
| B7 | trigger 包发送 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/protocol.c:53` |
| B8 | `CAPTURE_RATIO` SET | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:347` |
| B9 | `LIMIT_SAMPLES` SET | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:344` |
| B10 | `CONTINUOUS` 声明 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:38` |
| B11 | `PATTERN_MODE` SET | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:337` |
| B12 | 模式名表 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic.c:44` |
| B13 | 采样率 LIST（按链路/通道） | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:411` |
| B14 | 速率列表实现 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_data.c:138` |
| B15 | 链路速率上限 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_data.c:92` |
| B16 | 通道数 SET | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:318` |
| B17 | 动态通道使能 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:368` |
| B18 | `LA` 通道组 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:191` |
| B19 | 多型号扫描 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:142` |
| B20 | `conn=` 过滤 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:132` |
| B21 | 重插后重新查找 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:219` |
| B22 | 每设备唯一 source key | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/protocol.c:66` |
| B23 | session source 注册 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/protocol.c:160` |
| B24 | 阈值 SET | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:353` |
| B25 | 阈值只在 configure 生效 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/protocol.c:141` |
| B26 | 主机队列溢出 abort | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_usb.c:568` |
| B27 | 最小 in-flight 提交 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_usb.c:812` |
| B28 | 停滞重配 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_usb.c:1056` |
| B29 | 最小二乘速率拟合 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_data.c:603` |
| B30 | `slogic-report v1` | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic_data.c:656` |
| B31 | DFU 不处理 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/slogic/slogic.h:59` |
| B32 | `config_list` 全量键 | `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/api.c:400` |
