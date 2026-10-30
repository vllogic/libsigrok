# vllogic-logic 功能建议书

- 日期：2026-10-30
- 输入：`docs/vllogic-logic-feature-report.md`、`src/hardware/vllogic-logic/`（只读）、`libsigrok_sipeed` 同类实现（只读参考）
- 性质：**建议书**，只评估代价、风险与实施顺序；不构成源码修改，不涉及 RTL 改动
- 路径约定：`api.c`/`vllogic_usb.c`/`uhsif_rx.c` 均指 `src/hardware/vllogic-logic/` 下文件；竞品路径省略 `libsigrok_sipeed/src/hardware/sipeed-slogic-analyzer/`

## 1. 目的与范围

### 1.1 目的

把对比报告里的 P0–P7 转成**可决策、可回滚、可验收**的工程建议：每项说清用户看到什么、动哪些既有路径、最可能改坏什么、用什么测试兜底、失败后怎么退。

### 1.2 范围

| 包含 | 不包含 |
|---|---|
| 纯驱动功能：触发/预触发、限额、source key、重插、模式、速率联动、报告、校准展示 | RTL/FPGA 修改、固件上传/DFU、硬件触发状态机 |
| 配置项、数据流、线程/生命周期、内存与带宽影响 | GUI/PulseView 改动、解码器改动 |
| 无硬件自测、真机回归矩阵、阶段闸门 | 多设备硬件同步、外部时钟、真正任意码型 |
| 兼容性与回滚策略 | 本次实际执行采集/编译/烧录（明确不做） |

### 1.3 约束

- 新能力默认不改变旧行为；旧命令（不带新键）必须保持当前样本域语义。
- 任何“设置了但设备/驱动不生效”的键都不允许进入用户可见列表。
- 每项独立提交、独立可 revert；高风险项必须有运行时关闭开关。

## 2. 现状摘要

| 维度 | 现状 |
|---|---|
| 已实现 | 20 通道任意子集、23 档采样率、PC 抽稀、单端阈值（含采集中调整）、严格带宽准入、首块头校验、1 s 启动看门狗、drop/CRC/seq/mask 统计、独立 selftest |
| 已知缺口 | 无触发/预触发/`SR_DF_TRIGGER`；无 `LIMIT_MSEC`；无显式 `CONTINUOUS`；多设备 source key 固定 `-1`；无重插恢复；无 `PATTERN_MODE`；速率列表不随链路/通道裁剪；无结束报告行 |
| 验证基线 L1 | `./vllogic-selftest --quiet`，不依赖硬件/libusb/libsigrok，覆盖协议向量、LUT、CRC 重同步、sink short 与 17 个解析/抽稀/限额用例 |
| 验证基线 L2 | `--scan` + 单通道/20 通道短采集 + `--samples` 到点停止 + 阈值 GET/SET；CLI 当前仅暴露 samplerate/limit_samples/voltage_threshold/conn |
| 验证基线 L3 | 代码注释记录的实测：60 s/30 s 采集在 375–400 MB/s 下零丢块；8ch@400 MHz、20ch@150 MHz 为已验证上限 |
| 长采集 | 16×256 KiB URB、256×64 KiB chunk、4 MiB/tick 预算；本次未复测，作为回归项而非既有结论 |
| 关键事实 | 触发只能在主机侧做；设备块头没有样本索引/时间戳；逐通道阈值需多路 VBIAS，当前只有 PWM0/PWM1 两路 |

## 3. 候选功能总表

按风险从低到高排序；“代价”只含驱动与测试，不含文档与项目管理。

| ID | 功能 | 用户价值 | 代价（人日） | 风险 | 需 RTL/固件 | 建议阶段 |
|---|---|---:|---:|---|---|---|
| P2 | 每设备唯一负数 source key | ★★★★ | 0.5 | 低 | 否 | Phase 1 |
| P1 | `LIMIT_MSEC` + 显式 `CONTINUOUS` | ★★★★ | 1.0 | 低 | 否 | Phase 1 |
| P6 | 结束报告行（拟合 MB/s、冷启动、质量汇总） | ★★★ | 1.5 | 低 | 否 | Phase 1 |
| P5 | 速率列表按“链路×通道”联动 + 明确拒绝信息 | ★★★ | 1.5 | 中 | 否 | Phase 2 |
| P3 | 打开清理 + 按端口/序列号重插恢复 | ★★★★ | 2.0 | 中 | 否 | Phase 2 |
| P4 | `PATTERN_MODE`：Normal / Counter 自检 | ★★ | 1.5 | 中 | 否（RTL 已有 0x04/0x06） | Phase 2 |
| P0 | 软件触发 + `CAPTURE_RATIO` + trigger 包 | ★★★★★ | 4.5 | 高 | 否 | Phase 3 |
| P7 | 校准报告/通道组（只读）；逐通道阈值 | ★★★ | 2.0 + RTL | 高 | 是（逐通道生效） | Phase 3 |

合计：驱动约 14.5 人日；不含 RTL 的 2–3 周。

## 4. 逐项评估

### P2 每设备唯一负数 source key（低风险）

**功能描述**：同一 session 打开两台 Logic20 时，每台注册独立的负数 source key，同时采集不互相踢掉；单设备用户看不到变化。

**实现方案**：

| 触及点 | 建议 |
|---|---|
| `api.c:1009` | 用 `vllogic_source_key(sdi)` 替代常量 `-1` |
| `api.c:416-417` | 关闭时用同一 helper 计算 key，禁止字面量与派生 key 混用 |
| `api.c` 新增 helper | 建议 `-1 - (int)(((uintptr_t)sdi >> 4) & 0x3fffffff)`，与 `sipeed protocol.c:66-69` 同构 |
| `vllogic.h:72-93` | 可选：缓存 key 用于日志/一致性校验；纯计算也可放 `protocol.c` 供 selftest |

数据流不变，仅 session source 键值变化。

**代价**：0.5 人日；约 20–40 行；2–3 个文件；新增 2 个 selftest（键唯一性、负值范围）。

**风险**：① 回归点：单设备停止路径、`dev_close()` 强制移除 source；② 生命周期：key 必须在 `sdi` 全程稳定，若 scan/open 各算一次且指针变化会移除错误 source；③ 兼容性：依赖 `-1` 的旧脚本/前端假设会失效（概率低，需 release note）。

**不引入 bug 的措施**：单一 helper 为唯一事实来源；`dev_close()` 与 `acquisition_start()` 都调用它；selftest 用合成指针验证范围；多设备打印实际 key；单设备仍保留 `-1`。

**验收标准**：

```bash
sigrok-cli -d vllogic-logic:conn=<A> ... --samples 10000 -o /tmp/a.sr
sigrok-cli -d vllogic-logic:conn=<B> ... --samples 10000 -o /tmp/b.sr
```

期望：两次都成功；日志出现两个不同负 key；无 `source already exists`；两个 `.sr` 均非空。

**可回滚性**：单 commit，无运行时开关；revert 后恢复固定 `-1`。

### P1 `LIMIT_MSEC` + 显式 `CONTINUOUS`（低风险）

**功能描述**：`--time N` 或 `-c limit_msec=N` 按时间采集；未设任何限额时前端显示“连续采集”。到点后与 `--samples` 一样走 STOP/排空/END。

**实现方案**：

| 触及点 | 建议 |
|---|---|
| `api.c:99-104` | devopts 增加 `LIMIT_MSEC \| GET \| SET`、`CONTINUOUS`（能力声明，无 GET/SET） |
| `vllogic.h:77-79` | 新增 `uint64_t limit_msec`；**不**改动 `limit_samples` 字段语义 |
| `api.c:472-474` / `api.c:534-538` | GET/SET 增加 `LIMIT_MSEC`，采集中拒绝，与样本限额同策略 |
| `api.c:750-771` | 在样本限额判断旁增加单调时钟判断：`start_us != 0 && now - start_us >= limit_msec*1000` |
| `api.c:1006` | 复用 `start_us`（与 1 s 看门狗同源），不建第二套时钟 |

明确建议：Phase 1 **不**把 `LIMIT_SAMPLES` 迁移到 `sr_sw_limits`。现有“已发送 + 已生产”双条件（`api.c:759-762`）是刻意设计，迁移会改变限额语义。

**代价**：1.0 人日；约 60–80 行；2 个文件；新增 3 个 selftest（msec 到点、双限额先到、0=关闭）+ 4 个真机用例。

**风险**：① 回归点：样本限额、启动看门狗、STOP 排空、`--samples` 与 `--time` 优先级；② 时间基准：建议从 START 算（与看门狗一致），首块延迟会计入采集时长；③ 兼容性：声明 `CONTINUOUS` 后前端 UI 会变，若 `limit_msec=0` 语义不对会被判假实现。

**不引入 bug 的措施**：`limit_msec=0` 走原路径；新判断放在样本判断之后、看门狗之前；双限额取先到者；selftest 用假时钟验证等于/超过 1 ms 边界。

**验收标准**：

```bash
time sigrok-cli -d vllogic-logic -c samplerate=1000000 -C 0 -c limit_msec=1000 -o /tmp/t.sr
sigrok-cli -d vllogic-logic -c samplerate=1000000 -C 0 -c limit_samples=500 -c limit_msec=5000 --samples 500
```

期望：第一条约 1 s 结束、样本数约 1e6（±5%）、日志含时间限额到点；第二条在 500 样本处停止；`limit_msec=0` 与当前完全一致。

**可回滚性**：3 处小改，默认 0；删除 devopts 两行即恢复旧能力列表；可单独 revert。

### P6 结束报告行（低风险）

**功能描述**：每次采集结束打印一行可解析的 `vllogic-report v1 ...`，含拟合吞吐、冷启动毫秒、块/CRC/seq/drop/队列峰值；现场性能回归不用翻多行日志。

**实现方案**：

| 触及点 | 建议 |
|---|---|
| 新增 `report.c/h` | 纯函数：最小二乘拟合、冷启动、行格式化；不依赖 libusb/libsigrok，可进 selftest |
| `vllogic_usb.c:258` | parser 线程每 ~100 ms 记录 `(t_us, cumulative_bytes)` 到固定 64 项数组 |
| `vllogic_usb.c:87-137` | `vllogic_rx` 增加 `first_block_us`、采样数组、chunk 环高水位 |
| `api.c:685-724` | `vllogic_finish()` 在 `vllogic_rx_stop()`（`api.c:697`）之后读取并打印，复用 `uhsif_stats` |

**代价**：1.5 人日；约 150–200 行；3 个文件；新增 3 个 selftest（正常拟合、`n<2` 输出 `nan`、零字节）。

**风险**：① 回归点：收尾路径、`sr_info` 行数、日志解析脚本（新增而非替换）；② 并发：数组只由 parser 写、join 后 session 读，提前读会竞争；③ 精度：短采集抖动大，`fit_n<2` 或时长 <200 ms 输出 `nan`，不假装精确。

**不引入 bug 的措施**：报告模块独立、只读统计；默认开启但只加一行 `sr_info`；`VLLOGIC_REPORT=0` 可关闭；拟合失败不影响采集；selftest 覆盖除零与负斜率。

**验收标准**：

```bash
sigrok-cli -d vllogic-logic -c samplerate=100000000 -C 0-7 --samples 5000000 -o /tmp/r.sr 2>&1 | tee /tmp/r.log
grep 'vllogic-report v1 ' /tmp/r.log
```

期望：行内含 `mbps= cold_ms= blocks= drop_blocks= crc_fail= seq_jumps= q_peak_mb=`；`mbps` 与 `rate*nchan/8` 偏差 ≤15%；质量计数与既有 summary 行一致；`VLLOGIC_REPORT=0` 时该行消失且其余日志不变。

**可回滚性**：独立模块 + 一个调用点；env 开关；revert 不影响数据面。

### P5 速率列表按“链路×通道”联动（中风险）

**功能描述**：`SR_CONF_SAMPLERATE` 的 LIST 只返回当前链路和已使能通道数能承载的档位；`config_set` 仍严格拒绝超限，但错误信息给出“当前最多可到多少 Hz”。

**实现方案**：

| 触及点 | 建议 |
|---|---|
| `api.c:592-599` | `config_list(SAMPLERATE)`：`sdi` 可用时按链路静态上限 × 通道数过滤；`sdi == NULL` 返回全表 |
| `api.c:302-355` | `dev_open()` 记录 libusb 链路速度（SS 350 MB/s、HS 35 MB/s、未知 5 MB/s），不依赖探测 |
| `api.c:965-982` | 拒绝信息追加“按当前链路/通道，最高可用档位为 X Hz” |
| `api.c:47-71` | 保持 23 档表不变，只过滤，不新增/删除档位 |

明确建议：**不做自动钳位**。钳位会静默改变用户请求，违背“精确档位、越界拒绝”的产品性格；只做列表裁剪 + 明确拒绝信息。

**代价**：1.5 人日；约 100–130 行；2 个文件；新增 3 个 selftest（过滤函数、空集回退、通道数变化）。

**风险**：① 回归点：`config_list` 在 `sdi == NULL` 时行为、前端缓存、`--show` 输出；② 逻辑：过滤后可能为空（如 HS + 20 通道），必须回退全表并 `sr_warn`；③ 兼容性：前端缓存第一次列表，通道变化后不重查；静态上限可能比实测保守，但只影响可见列表。

**不引入 bug 的措施**：过滤函数纯函数化并 selftest；空集回退；`VLLOGIC_RATE_FILTER=0` 关闭；探测/准入路径完全不动。

**验收标准**：

```bash
sigrok-cli -d vllogic-logic --show | sed -n '/samplerate/,/^$/p'
sigrok-cli -d vllogic-logic -c samplerate=1200000000 -C 0-19 --samples 1000
```

期望：HS 下列表不含 1.2 GHz；SS + 2 通道含 1.2 GHz；SS + 20 通道不含；第二条仍 `SR_ERR_ARG` 且提示最高可用档位；`VLLOGIC_RATE_FILTER=0` 时列表与当前完全一致。

**可回滚性**：过滤逻辑集中在 `config_list` 一个分支；env 开关；revert 恢复全表。

### P3 打开清理 + 重插恢复（中风险）

**功能描述**：上次异常退出或 USB 重新插拔后无需重新 scan；按端口路径优先、序列号兜底重新定位同一台设备，并在打开后清掉残留采集状态。无法唯一确认时明确拒绝而不是猜。

**实现方案**：

| 触及点 | 建议 |
|---|---|
| `api.c:302-355` | `sr_usb_open()` 失败（`NO_DEVICE`）时进入恢复分支 |
| `api.c:208-239` / `api.c:137-183` | 抽出扫描期身份匹配为 `vllogic_find_by_identity()`，复用 `vllogic_match()` 校验 VID/PID/bcd/产品串 |
| `vllogic_usb.c:971-1064` | 新增 `vllogic_cmd_raw(hdl, cmd, param)`：16 字节帧、3 次重试、不等 ACK |
| `api.c:323-340` | 打开/claim 成功后先 STOP+FLUSH，再读取并丢弃 50 ms 内残留 ACK |

**代价**：2.0 人日；约 150–200 行；2–3 个文件；新增 2 个 selftest（身份匹配、歧义拒绝）+ 4 个真机用例（拔插、异常退出、双设备、错误设备）。

**风险**：① 回归点：正常打开、claim 失败分支、`dev_close()` 5 s 放弃逻辑；② 误抓设备：端口路径在 HUB/Windows 上可能复用，必须完整身份校验，多候选拒绝；③ 时序/生命周期：恢复枚举增加打开延迟（预算 ≤2 s），重新枚举后要更新 `usb->bus/address/devhdl`，旧 handle 先关闭避免泄漏。

**不引入 bug 的措施**：只在 `sr_usb_open()` 明确失败时进入；正常路径零改动；身份不唯一直接失败；`VLLOGIC_REPLUG=0` 关闭；清理命令失败只告警；所有失败路径统一 `goto` 释放。

**验收标准**：

```bash
# 采集中拔线并 Ctrl-C，插回后不重新 scan，直接用旧 conn 打开
sigrok-cli -d vllogic-logic:conn=<old-bus>.<old-addr> ... --samples 10000 -o /tmp/replug.sr
```

期望：日志出现“recovered via port path/serial”，采集成功；双设备无法唯一匹配时报“ambiguous device”并拒绝；`VLLOGIC_REPLUG=0` 时恢复原 `Unable to open` 错误。

**可回滚性**：恢复逻辑封装在独立 helper，正常路径不受影响；env 开关；可单独 revert。

### P4 `PATTERN_MODE`：Normal / Counter 自检（中风险）

**功能描述**：用户可选 `Normal` 或 `Counter`。`Counter` 不是正常波形，而是确定性链路自检：驱动只校验计数器单调性/速率并打印结果，不把计数器字当通道快照。列表里**不出现** WAVE。

**实现方案**：

| 触及点 | 建议 |
|---|---|
| `api.c:99-104` / `api.c:592-609` | 增加 `PATTERN_MODE \| GET \| SET \| LIST`；LIST 返回 `{"Normal","Counter"}` |
| `api.c:494-590` | SET 存索引；采集中拒绝 |
| `vllogic_usb.c:1182-1217` | 按模式发 `MODE_NORMAL`(0x04) 或 `MODE_COUNTER`(0x06) |
| `vllogic_usb.c:268-285` | 首块校验 `mode == 0` 改为 `mode == expected_mode`（Counter 期望 2） |
| `vllogic_usb.c:258` / `uhsif_rx.c:80` | Counter 分支不经反交织/`emit_snapshot`，改走计数器完整性检查与汇总 |

明确建议：Counter 建议**不产出 `SR_DF_LOGIC`**，只发 header + 一行自检汇总 + END；否则会产出无意义波形，属于“设了没效果/误导”。若前端不能接受空采集，则降级为 env-only 内部自检，不暴露 config key。

**代价**：1.5 人日；约 100–150 行；3 个文件；新增 3 个 selftest（模式映射、首块期望模式、计数器解析）+ 3 个真机用例。

**风险**：① 回归点：Normal 首块校验、`vllogic_probe_link()` 内部 COUNTER 探测（`vllogic_usb.c:1102-1180`）、配置顺序；② 语义：Counter payload 是内部计数器，误走现有 parser 会产出看似有效实则无意义的波形；③ 假实现：WAVE（0x05）只是 `virtual_wave` 计数器，绝不能作为“任意码型”暴露。

**不引入 bug 的措施**：Normal 路径逐字节保持；Counter 走独立分支且默认不选；首块校验显式区分期望模式；`VLLOGIC_PATTERN=0` 隐藏该键；selftest 验证 Counter 数据不进入反交织。

**验收标准**：

```bash
sigrok-cli -d vllogic-logic -c pattern_mode=Counter -c samplerate=1000000 -C 0 --samples 0 -o /tmp/counter.sr
sigrok-cli -d vllogic-logic -c pattern_mode=Normal -c samplerate=1000000 -C 0 --samples 10000 -o /tmp/normal.sr
```

期望：Counter 日志含 `counter-self-test: words=N monotonic=1 rate=...`，无 `SR_DF_LOGIC`；Normal 与当前一致；`pattern_mode=WAVE` 被拒绝并列出合法值。

**可回滚性**：新增键可 env 隐藏；Normal 路径不变；revert 后仅失去 Counter 自检。

### P0 软件触发 + `CAPTURE_RATIO` + trigger 包（高风险）

**功能描述**：`-t 0=r -t 1=f` 配置单阶段触发，`-c capture_ratio=50` 保留触发前一半样本；采集在匹配点切分，前端看到触发标记，触发前波形完整可见。多阶段明确拒绝，不假装支持。

**实现方案**：

| 模块 | 建议 |
|---|---|
| 新增 `trigger.c/h` | 纯匹配器：zero/one/rising/falling/edge；输出样本域（抽稀后），不依赖 libsigrok；参考 `slogic_data.c:280-310`，按本驱动 `unitsize` 重写 |
| `api.c:99-104` / `api.c:592-609` | 增加 `TRIGGER_MATCH \| LIST`、`CAPTURE_RATIO \| GET \| SET`；ratio 0–100，采集中拒绝 |
| `api.c:783-838` | 调 `sr_session_trigger_get()`，校验单 stage/通道已使能，编译为纯结构体 |
| `uhsif_rx.h:72-113` / `uhsif_rx.c:80-176` | parser 增加触发规格、前一采样、`triggered`、预触发环、`trig_index`；在 `emit_snapshot()` 输出域逐点匹配，未触发写环，触发后先 flush 环 |
| `vllogic_usb.c:61-64` / `258-352` | `vllogic_chunk` 增加 `first_sample`、`trig_offset`；合并 chunk 时维护，触发点所在 chunk 打标 |
| `api.c:637-659` | 触发 chunk 切两段：前半段、`std_session_send_df_trigger()`、后半段 |
| `api.c:750-771` | 触发后剩余样本计入 `limit_samples`；未触发时不因限额提前 STOP 而丢预触发环 |

**预触发内存策略（建议）**：

| 场景 | 建议 |
|---|---|
| `limit_samples > 0` 且 `capture_ratio > 0` | 预触发样本 = `limit_samples * ratio / 100`，启动前分配，失败明确报错 |
| `limit_samples == 0` | 忽略 `capture_ratio`（与 sipeed 语义一致），只做触发后持续采集，不分配无界环 |
| 上限 | 单次预触发环硬上限 1 GiB；超过则拒绝启动并提示降低 `--samples` 或 ratio |
| 触发等待 | 不设自动失败超时；每秒打印 waiting 统计，用户可 Ctrl-C；1 s 无块看门狗仍负责链路故障 |

**代价**：4.0–5.0 人日；约 600–800 行；5 个文件；新增 10–12 个 selftest（各 match、首样本无边沿、跨 snapshot/chunk、ratio 0/100、limit 交互、环回绕、flush 顺序）+ 6 个真机用例。

**风险**：① 回归点：`emit_snapshot()` 是数据面核心，多余分支可能改变 Normal 输出；chunk 切分可能破坏 `len % unitsize == 0`；`samples_sent` 与 END 时机。② 并发/生命周期：触发状态只能由 parser 写、session 只读 chunk 元数据；从未触发时仍要 flush 或明确丢弃并只发一次 END；`dev_close()` 5 s 放弃路径要释放预触发环。③ 内存/带宽：1 GiB 环 + 16 MiB chunk 环，高 rate 下填充极快，OOM 是真实风险。④ 索引：触发索引必须在抽稀后的输出域，跨 chunk 对齐，`SR_DF_TRIGGER` 只发一次。⑤ 语义：`limit_samples` 建议定义为“触发前 + 触发后”总输出样本，必须写入文档。

**不引入 bug 的措施**：① 无 trigger 时 `emit_snapshot()` 走完全相同的分支；② 匹配器独立纯模块，selftest 覆盖边界；③ 预触发环独立分配/释放，失败立即 `goto err_free`；④ chunk 只增字段，不改 `len/data` 语义，切分只在发送层；⑤ `VLLOGIC_TRIGGER=0` 隐藏键并强制旧路径；⑥ 真机先跑无 trigger 基线，再逐项对比质量计数。

**验收标准**：

```bash
# 1 kHz 方波接 ch0，上升沿触发，预触发 50%
sigrok-cli -d vllogic-logic -c samplerate=1000000 -C 0 -t 0=r -c capture_ratio=50 --samples 100000 -o /tmp/trig.sr
sigrok-cli -d vllogic-logic -c samplerate=1000000 -C 0 --samples 100000 -o /tmp/base.sr
```

期望：`trig.sr` 含触发包，触发点约第 50000 样本（±1）；触发前至少 1 个完整周期；`base.sr` 与当前逐样本一致；两个 stage 明确报“single stage only”；ratio 越界报错；从未触发时 Ctrl-C 正常 END、无挂起、10 次重复 RSS 稳定。

**可回滚性**：独立 `trigger.c/h` + 发送层切分；`VLLOGIC_TRIGGER=0` 运行时关闭；可整组 revert，Normal 路径不受影响。

### P7 校准报告/通道组（只读）；逐通道阈值（高风险）

**功能描述**：提供**只读**校准报告：按版本化实测表给出各通道 duty 偏差与建议全局阈值，并把 20 通道分成展示组。逐通道阈值在 RTL 支持多路 VBIAS 前**不提供 SET**。

**实现方案**：

| 触及点 | 建议 |
|---|---|
| 新增 `calib.c/h` | 版本化表（表版本、日期、来源），纯查表/插值，可 selftest |
| `api.c:185-295` | scan 时用 `sr_channel_group_new()` 建 2–4 个展示组（纯元数据） |
| `api.c:703-724` | 结束报告追加 `calib v1 table=... ch=<n> suggested_vth=...` |
| `api.c:539-583` | 阈值 SET 仍只写 PWM0/PWM1；逐通道请求明确报“not supported by RTL” |
| 数据来源 | `logic_analyzer/docs/前端改良建议.20261029.md` 的实测表；必须版本化，不能散落硬编码 |

**代价**：驱动 2.0 人日；约 200–250 行（表占大头）；2–3 个文件；新增 3 个 selftest（表版本、插值边界、缺数据回退）；RTL 逐通道生效另需 2–3 周。

**风险**：① 回归点：通道组元数据可能改变前端通道树，阈值 GET/SET 语义不能变；② 假实现：当前只有 PWM0/PWM1 两路全局 DAC，暴露“每通道阈值”就是欺骗；③ 数据时效：校准表依赖硬件批次/温度，过期会给出错误建议，必须带版本与日期。

**不引入 bug 的措施**：只读、只打印，不参与采样/阈值计算；`VLLOGIC_CALIB=0` 关闭；无逐通道 SET 路径；表缺失输出 `calib=unavailable`；不改变 `VOLTAGE_THRESHOLD` GET 结构。

**验收标准**：

```bash
VLLOGIC_CALIB=1 sigrok-cli -d vllogic-logic -c samplerate=1000000 -C 0-3 --samples 10000 -o /tmp/cal.sr 2>&1 | grep 'calib v1'
sigrok-cli -d vllogic-logic -c voltage_threshold=1.7
```

期望：报告行含 `table= date= source=` 与各通道建议值；阈值 GET 仍返回 `(vth,vth)` 单值；不存在“逐通道阈值”可写键；`VLLOGIC_CALIB=0` 时报告行消失。

**可回滚性**：纯展示模块，env 开关；可单独 revert；逐通道阈值在 RTL 就绪前不进入代码路径。

## 5. 实施路线

### Phase 1：低风险、可快速交付（约 3.0 人日）

| 项 | 人日 | 依赖 | 说明 |
|---|---:|---|---|
| P2 source key | 0.5 | 无 | 最先做，为 P3 多设备/重插打基础 |
| P1 `LIMIT_MSEC`/`CONTINUOUS` | 1.0 | 无 | 不迁移 `limit_samples`，只加时间限额 |
| P6 报告行 | 1.5 | 无 | 为后续阶段提供性能基线 |

**回归范围**：① L1 `./vllogic-selftest --quiet` 全通过（含新增用例）；② L2 `--scan`、单通道 1 MHz、20 通道 100 MHz、阈值 GET/SET、`--samples` 到点；③ L3 8ch@400 MHz、20ch@150 MHz 各 60 s，质量计数不得新增非零；④ 停止路径 Ctrl-C/`--samples`/`--time`/`dev_close()`，END 只发一次；⑤ 1ch@1 MHz 连续 10 分钟，RSS 增长 <10%，无线程/fd 泄漏；⑥ scan/定长/任意子集/严格准入拒绝四类 CLI。

**阶段闸门**：L1 全绿；L2/L3 无质量计数退化；同配置单设备输出与改动前逐样本一致；报告行可解析；任一失败即回滚对应 commit，不进入 Phase 2。

### Phase 2：中风险、需要真机拔插与多设备（约 5.0 人日）

| 项 | 人日 | 依赖 | 说明 |
|---|---:|---|---|
| P3 重插恢复/打开清理 | 2.0 | P2 | 身份匹配复用稳定标识 |
| P5 速率列表联动 | 1.5 | 无 | 只裁剪与提示，不钳位 |
| P4 `PATTERN_MODE` | 1.5 | 无 | 先确认 Counter 输出语义；否则降级 env-only |

**回归范围**：Phase 1 全部 + 拔插 3 次、异常退出后重开、双设备同 session、HS/SS 两种链路、Counter/Normal 切换；每次拔插后检查 EP1 残留与 claim 状态。

**阶段闸门**：30 分钟含 3 次拔插的 soak 无挂起/泄漏；双设备无 key 冲突；错误/歧义设备必须拒绝；`sdi == NULL` 时列表仍全量；P4 若无法定义输出语义则只保留 env-only，不阻塞闸门。

### Phase 3：高风险、需要设计与较长验证（约 6.5 人日 + RTL 决策）

| 项 | 人日 | 依赖 | 说明 |
|---|---:|---|---|
| P0 软件触发 + ratio + trigger 包 | 4.5 | P1、P6、P2 | 需要预触发环与跨 chunk 切分设计 |
| P7 校准报告/通道组（只读） | 2.0 | P6 | 逐通道阈值仅做 RTL 评估，不落地 |

**回归范围**：Phase 1/2 全部 + 触发矩阵（5 种 match × 3 种 rate × 1/20 通道）、ratio 0/50/100、跨 chunk 触发、从未触发、触发后立即停止、预触发环分配失败、60 s 触发采集零丢块。

**阶段闸门**：触发 selftest 100%；20 次重复触发无漏触发/重复 trigger 包；从未触发可正常停止且 END 一次；预触发内存不超上限且失败路径干净；L3 基线无退化；P7 只读报告不产生“逐通道可调”的误解。

## 6. 质量保障策略

### 6.1 变更隔离

| 手段 | 具体要求 |
|---|---|
| 独立模块 | 触发器、报告拟合、校准表各自 `*.c/h`，不把逻辑塞进 `emit_snapshot()` 或 `receive_data()` 主干 |
| 默认关闭 | 新配置键默认值等于旧行为；实验能力用 `VLLOGIC_*` env 控制 |
| 单一路径 | 无 trigger / 无 msec / Normal 模式必须走与当前完全相同的分支，禁止“顺便重构” |
| 增量提交 | 每项一个 commit；P0 拆成“匹配器→预触发环→chunk 切分→配置层”四个可独立回滚的提交 |

### 6.2 测试分层

| 层级 | 内容 | 频率 | 失败处理 |
|---|---|---|---|
| L0 selftest | 纯 C、无硬件：协议、LUT、CRC、抽稀、限额、触发匹配、拟合、校准表 | 每次提交 | 阻断合并 |
| L1 单通道真机 | 1 MHz/100 MHz，1 通道，短采集，阈值 | 每次提交 | 阻断合并 |
| L2 多通道 | 8ch@400 MHz、20ch@150 MHz，60 s | 每阶段 | 阻断进入下一阶段 |
| L3 长采集 | 1ch@1 MHz 10 分钟；可选 20ch@100 MHz 60 s | 每阶段 | 查泄漏/丢块 |
| 停止路径 | Ctrl-C、`--samples`、`--time`、`dev_close()`、拔线 | 每项 | 阻断发布 |
| 兼容性 | 旧命令不带新键；旧 `.sr` 可读；`VLLOGIC_STRICT=0/1` | 每阶段 | 阻断发布 |

### 6.3 每项必须重跑的现有测试

| 项 | 必跑 |
|---|---|
| P2 | 单设备短采集、停止路径、双设备、`--scan` |
| P1 | `--samples` 到点、Ctrl-C、启动看门狗、`limit_msec=0` 回归 |
| P6 | 全部 L2/L3（报告不能改变数据面）、短采集 `nan` 分支 |
| P5 | `config_list` 在 `sdi == NULL`/已打开两种状态、严格拒绝、`--show` |
| P3 | 正常打开、claim 失败、拔插、异常退出、双设备歧义 |
| P4 | Normal 首块校验、链路探测（内部 Counter）、配置顺序 |
| P0 | 无 trigger 基线逐样本对比、5 种 match、ratio 边界、停止/END、预触发环失败 |
| P7 | 阈值 GET/SET 不变、通道组展示、校准表缺失回退 |

### 6.4 代码评审要点

1. **并发**：parser 写、session 读的字段是否在 join 后访问；SPSC 环生产者/消费者是否唯一；原子变量 memory order 是否正确。
2. **生命周期**：`devc->rx` 是否只 free 一次；失败 `goto` 是否覆盖所有已分配资源；`dev_close()` 5 s 放弃路径是否仍安全。
3. **错误路径**：分配失败、首块不匹配、USB fatal、从未触发、ratio 越界是否都有明确错误且不产出半截数据。
4. **数据面**：chunk 切分是否保持 `len % unitsize == 0`；`samples_sent`/`samples_out`/`limit_samples` 口径是否一致；`SR_DF_END` 是否只发一次。
5. **兼容性**：旧命令不带新键时路径是否零变化；新增日志行是否会被现有脚本误判。
6. **假实现**：每个新键是否真的改变设备/驱动行为；若无效果，必须从列表移除。

### 6.5 灰度与开关

| 开关 | 作用 | 默认 |
|---|---|---|
| `VLLOGIC_TRIGGER=0` | 隐藏 trigger/ratio 键并走旧路径 | 开启 |
| `VLLOGIC_REPORT=0` | 关闭结束报告行 | 开启 |
| `VLLOGIC_RATE_FILTER=0` | 关闭速率列表裁剪 | 开启 |
| `VLLOGIC_REPLUG=0` | 关闭重插恢复 | 开启 |
| `VLLOGIC_PATTERN=0` | 隐藏 `PATTERN_MODE` | 开启 |
| `VLLOGIC_CALIB=0` | 关闭校准报告 | 关闭（需显式开启） |

开关只影响“新能力是否出现”，不影响旧数据路径；读取集中在 `dev_open()` 或 `config_list()`，避免散落。

### 6.6 失败处理

- 任一项导致 L1 失败、L2 样本数偏差 >1%、L3 新增 `crc_fail/bad_len/seq_jumps/drop_blocks`，立即回滚该项 commit，不带病进入下一阶段。
- 不以“日志没有 error 关键字”作为通过标准；以样本数、质量计数、END 次数、RSS/线程数四项硬指标为准。
- 回滚后保留失败日志与复现命令，作为下一轮 selftest 用例。

## 7. 不建议现在做的事

| 不做项 | 原因 |
|---|---|
| 硬件触发/预触发 FIFO | 当前 RTL 只有采样节拍同步，没有触发比较器与预触发缓存 |
| 外部时钟/时钟沿 | RTL 只有内部 PLL，没有时钟输入 MUX、边沿极性、丢失检测 |
| 真正的 WAVE/任意码型 | `MODE_WAVE`(0x05) 只是 `virtual_wave` 计数器，不是码型 RAM/播放逻辑 |
| 精确丢块位置/时间戳 | 块头只有锁存 `drop_flag`、seq、div、mask，只能统计不能定位 |
| 逐通道阈值校准 | 只有 PWM0/PWM1 两路全局 DAC；缺多批次实测数据前不做 |
| 任何“设了没效果”的假实现 | 会破坏“严格准入 + 明确失败”的产品性格；宁可不暴露键 |
| 自动降速/停滞重配（本期） | 需重设 RUN/重配状态机，收益后置；先用 P6 观察真实瓶颈 |
| 固件上传/DFU | 与 libsigrok 驱动职责不符，需要独立工具与固件包管理 |
| 多设备硬件同步采样 | 无同步触发线/共享时钟，软件只能“先后 START”，不能保证同拍 |

## 8. 决策点

| # | 问题 | 建议默认 |
|---|---|---|
| 1 | Phase 1（P2/P1/P6，约 3 人日）是否立即启动？ | 建议立即启动；不含高风险数据面改动，且为后续建立报告基线 |
| 2 | P0 预触发内存：强制 `limit_samples > 0` 才允许 ratio，还是无 limit 时默认 1 GiB 环？ | 建议强制要求 limit；无 limit 时忽略 ratio，避免无界内存与 OOM |
| 3 | 是否允许新增 `VLLOGIC_*` 环境变量与实验性 config key？命名沿用 `VLLOGIC_STRICT` 风格？ | 建议允许，仅用于灰度/关闭，不替代正式配置键；默认值必须等于旧行为 |
| 4 | P4 的 Counter 是否对用户可见？若不可见，是否只保留 env-only 自检？ | 建议先 env-only；确认前端能接受“无波形、只有自检汇总”后再暴露 |
| 5 | P7 本期只做“只读校准报告 + 通道组”，还是等 RTL 后一次性做逐通道阈值？ | 建议本期只读；逐通道阈值明确推迟到 RTL 就绪，避免假实现 |
| 6 | 是否每个 Phase 结束同步更新 README/`docs/` 的配置键与版本号？ | 建议同步，至少记录新增键、默认值、env 开关与回滚方法 |
