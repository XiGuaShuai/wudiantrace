# Taint Semantics Roadmap — Phase 1 / 2 / 3

> 本文档记录"语义化污点追踪"三阶段的完整设计、已落地内容、剩余工作以及 UI
> 交互的影响范围,供后续 session 延续时参考。

## 指导原则

1. **锁输入,追输出,中间让它黑**。VMP dispatch loop 的具体 opcode 不识别 ——
   只在"输入端"(JNI 返回值、libc、rodata、payload 字符串)和"输出端"
   (签名缓冲区每字节)之间建立 tag 链路。
2. **渐进增强**。Phase 1 → 2 → 3 每阶段独立可交付、可单独回滚,不破坏现有
   bool taint 路径。
3. **零热路径开销**。额外元数据全部走 sidecar (`TagTable`),不膨胀
   `TraceLine` 的 ~88 字节热结构。
4. **语义单向**。标签只向下游传播,不做反向推断。

---

## Phase 1 — 输入端语义化 ✅ 已交付

### 落地内容

| 模块 | 改动 |
|---|---|
| **新建 `tag.rs`** | `TagId(u16)` / `TaintOrigin` enum(`ExternalCallRet` / `ConstMem` / `PayloadByte` / `UserSeed`)/ `TagTable`(intern、mem 区间索引、ExternalCall 行索引)/ `merge_tags` 优先级合并 |
| **`parser.rs`** | `TraceParser::build_tag_table(&self, bytes)` 三通扫描:<br>① reads − writes 得 ConstMem,64 B gap 合并为区间<br>② 每条 ExternalCall 回读原始字节,解析 `callee(args) ret: 0xV`<br>③ `0xADDR="..."`(可跨行)提取为 PayloadByte,覆盖同区间的 ConstMem |
| **`engine.rs`** | `TaintEngine` 持 `Option<Arc<TagTable>>`;`reg_tag[256]` 与 `reg_taint[256]` 并列;`tainted_mem` 值改为 `MemTaint { expected_val, tag }`;所有 `taint_reg` 有 `_with_tag` 变体;`src_taint_with_tag` 合并上游 tag;**ExternalCall 若有上游污染流入,清 caller-saved 后把 x0 重新污染并打 `ExternalCallRet` tag**(这是最关键的语义改进 —— 污染不再"断"在外部调用)|
| **`ResultEntry`** | 新增 `reg_tags: [TagId; 256]` 与 `mem_tags: Vec<(u64, TagId)>` |
| **`RemainingTaint`** | 新增 `reg_tags` / `mem_tags` 边界报告 |
| **`format_result`** | tainted 集合每项带 `[short_label]` 后缀;边界段末尾列出 "已知来源:" 摘要 |
| **`src/taint.rs`** | UI worker 在 `engine.run` 前调 `parser.build_tag_table(bytes)` 并 `set_tag_table` |
| **测试** | 5 个 regression + 3 个 tag.rs unit;合计 workspace 52 tests 全绿 |

### 实测效果(真实 trace,line 7658469)

```
tag table: 1613 origins, 716 ext-call tags, 872 mem ranges (built in 0.09s)
[Mode A — data] run 0.22s, 1 hits, stop=EndOfTrace
  START-LINE snapshot: {x8}
  boundary taint mems: ["0x76ff3bc010[rodata@0x76ff3bc010]"]
```

- Mode A 的边界 mem 从裸地址升级为 `rodata@0x...` 语义标签
- TagTable 构建 90 ms(相对于 1.5 s parser 全量 parse 可忽略)
- 内存增量约 50 MB(1613 origins × 平均字段)

### Phase 1 的能力边界

Phase 1 是 **reg 级** 的 tag 传播,能回答:
- "这条追踪链路里涉及了哪些 origin"(边界 + 每行 hit)
- "x0 当前污染来源于 rand() @ line N"

**不能**回答:
- "最终 32 字节签名的第 5 byte 来源于 payload 的第 12 byte"
  —— 需要 Phase 2 的 byte-level 粒度
- "某 reg 的高 4 字节和低 4 字节来自不同 origin"
  —— 同上

---

## Phase 1.5(可选)— UI 交互增强

Phase 1 的 `format_result` 文本输出已经自然变得信息更多,但当前 SidePanel 只
是 plain-text 渲染。以下增强不影响 engine,**纯 UI 层改动**。按 ROI 排序:

### (a) "污点来源" 侧边摘要 ✨ 强烈推荐

**触发**:每次 run 完成后自动填充。

**UI**:在现有 taint 面板顶部加一块折叠区,展示本次追踪触及的所有 origin,
按类别分组:

```
📍 追踪来源 (6)
├─ 🔵 外部调用 (3)
│   ├─ libc.so!rand()  @ line 3195102   [ret=0x41b8855d]
│   ├─ _JNIEnv::GetStringUTFChars(..., "phone")  @ line 7142058
│   └─ libc.so!free(…"GET\n/api/...")  @ line 3194844
├─ 📄 只读区 (2)
│   ├─ rodata @ 0x76ff3bc010..0x76ff3bc020
│   └─ rodata @ 0x76ff3e0000..0x76ff3e1200
└─ 📜 payload (1)
    └─ payload#12 @ 0x78e72b8e30 (632 B): "GET\n/api/sns/v1/system_service/check_code..."
```

**交互**:
- 点击某条 → 主视图跳转到对应行
- 悬停 → 浮窗显示 `long_label` 全文(特别是 payload 内容预览)
- 右键 origin → "只看涉及此来源的 hits"(过滤 ResultList)

**数据源**:遍历 `engine.results()` 中每个 entry 的 `reg_tags` + `mem_tags`
收集所有 TagId(去重),再从 `engine.tag_table()` 取 origin。

**实现量**:~150 行 `taint.rs`,新增 `OriginsSummary` struct + `show_origins_summary(ui, ...)` 函数。

---

### (b) Tag 作为 UI badge / 颜色

**当前**:tag 以 `[短标签]` 文本后缀形式混在 tainted 集合里(例如
`{x0[rand()→0xdead], mem:0x...[payload#3]}`),信息密但视觉嘈杂。

**增强**:Tainted 列表用 LayoutJob 渲染,reg 名按原样,tag 放在**小色块 badge**
里:
- ExternalCall tag → 蓝色 badge
- ConstMem tag → 灰色 badge
- PayloadByte tag → 橙色 badge
- UserSeed tag → 绿色 badge

**实现量**:~60 行,替换当前 `format_result` 纯文本输出那段,改用 `egui::RichText`
或 LayoutJob 着色。

---

### (c) 菜单:选一条 ExternalCall 行作为 UserSeed

**场景**:用户看到 `_JNIEnv::GetStringUTFChars(..., "session_id")` 那一行,希望
把 "session_id 的返回值"作为污点起点追下去。

**UI**:右键 ExternalCall 行 → "以此 ExternalCall 的返回值作为追踪起点"。

**引擎**:使用 **TaintSource::from_reg(x0) + set_source_tag(UserSeed 或对应
ExternalCallRet)**,start_index 设为 ExternalCall 的下一行。

**实现量**:~30 行,在 `collect_targets` 里增加一种 source。

---

### Phase 1.5 总工作量:约 240 行 UI-only。不改 engine。

---

## Phase 2 — Byte-Level Taint 🚧 待实施

### 动机

对 `mov w0, w1`、`ldrb w8, [x24]`、`shift`、`sha256` 等指令,reg 内部不同字节
的数据来源可能不同。Phase 1 把一整个 reg 的 tag 合并成一个,无法区分"x0 的
低 4 byte 来自 phone payload,高 4 byte 来自 rand()"。

Phase 2 将 tag 精细到 **byte 粒度**:每 reg 8 个独立 tag 槽 + 每字节 mem 一个
独立 tag。

### 数据模型

```rust
/// 新增:按字节的污染态 + tag
pub struct ByteTaint {
    /// reg 内 8 个字节各自的状态。`regs[r][i]` = 第 r 号 reg 的第 i 字节
    /// 的 (tainted, tag);用 u16 编码,高位 1 bit 表示污染,低 15 bit 是
    /// TagId(TagId 最大 32K,足够)。
    regs: [[u16; 8]; 256],   // 4 KB
    /// 每字节地址 → tag。bit0 永远是 tainted(按 HashMap 存在即为 1)。
    mems: FxHashMap<u64, TagId>,
}
```

`TaintEngine` 加:
```rust
byte_level: bool,
byte_taint: ByteTaint,
```

默认 `byte_level = false`;开关由 UI / API 打开。关闭时完全走 Phase 1 reg-level
路径(零性能代价)。

### TraceLine 必须知道访问宽度

Load / Store 需要知道本条指令访问了几字节:

```rust
// trace.rs: 新增字段
pub mem_access_size: u8,   // 0 when no memory access
```

Parser 按 mnemonic 推断:
- `ldrb`/`strb` = 1;`ldrh`/`strh` = 2
- `ldr w`/`str w`/`ldur w` 以及 `ldrsh`/`ldrsw` = 4
- `ldr x`/`str x`/`ldur x` = 8
- `ldp w`/`stp w` = 4(双端点各 4)
- `ldp x`/`stp x` = 8(双端点各 8)
- `ldr q`/`str q` = 16(SIMD,跨两 "reg" 或扩展到 16)

### 传播规则

所有在 `byte_level=true` 下生效:

| 指令 | 规则 |
|---|---|
| `mov x0, x1` | `regs[x0][0..8] ← regs[x1][0..8]` 逐字节复制 |
| `mov w0, w1` | `regs[x0][0..4] ← regs[x1][0..4]`;`regs[x0][4..8]` 全清(w 写清高 32 bit)|
| `ldrb w0, [x1]` | `regs[x0][0] ← mem_tag_of(addr)`;`regs[x0][1..8]` 全清 |
| `ldrh w0, [x1]` | `regs[x0][0..2] ← mem[addr..addr+2]`;`regs[x0][2..8]` 全清 |
| `ldr x0, [x1]` | `regs[x0][0..8] ← mem[addr..addr+8]` |
| `str x0, [x1]` | `mem[addr..addr+8] ← regs[x0][0..8]` |
| `strb w0, [x1]` | `mem[addr] ← regs[x0][0]` |
| `add x0, x1, x2` | `regs[x0][i] ← merge(regs[x1][i], regs[x2][i])` for i in 0..8 |
| `and/or/eor x0, x1, x2` | 同上(按位操作,逐字节 merge 是合理近似)|
| `lsl/lsr/asr x0, x1, #N` | 按 `N/8` 整字节移位后 merge;非 8 倍数的 N 走"模糊合并":结果每字节 = src 对应段的 merged tag |
| `mul/umulh/smulh` | 所有输入字节 merge 成一个 tag,填 dst 8 个字节(mul 是"全合并"半 black-box) |
| `sha256/aes` SIMD | 所有输入字节 merge,填所有输出字节(完全黑箱)|
| `csel x0, x1, x2, <cond>` | `regs[x0][i] ← merge(regs[x1][i], regs[x2][i], regs[NZCV][0])` |
| `bl foo` (ExternalCall) | 按 Phase 1 规则;x0 的 8 字节全部设为 ExternalCallRet tag(upstream 合并)|

`merge(a, b)`:
- 两者都 untainted → untainted
- 一个 tainted → 传那个
- 两者 tagged 且相同 → 保留
- 两者 tagged 且不同 → 按 Phase 1 `merge_tags` 优先级挑一个 **或** 生成
  `Combined(Vec<TagId>)` tag(后者更精准,但 origin 表会膨胀 —— 可以做 LRU 去重)

### 精度权衡

- **shift 非 8 倍数**:按字节传播会漏精度(例如 `lsl #4` 让 tag 边界横跨
  字节)。Phase 2 初版用"模糊合并"(把跨字节的 tag 都合并到结果字节),
  可接受;若后续需要 bit-level,再延到 Phase 4。
- **乘法 / 哈希类**:完全 black box,所有字节都 merge 到同一个 tag 集。
- **地址计算**:按 Phase 1 的"只追数据流"设计,`ldr` 的**地址**寄存器的
  tag **不**注入结果。

### 性能预算

| 项目 | Phase 1 | Phase 2 预估 |
|---|---|---|
| 每 ResultEntry 大小 | 0.5 KB(bool 256 + tag u16 × 256) | 4 KB(byte tag u16 × 256 × 8)|
| 典型 visited=1 万行时总快照 | 5 MB | 40 MB |
| 14M trace 全 forward | ~3 s | ~10 s(×3 慢) |
| 14M trace backward dep-graph | ~2 s | 不变(byte 态不参与 dep-graph) |

**缓解**:
1. **Delta snapshot**:entry 只记 diff(哪些 reg 字节变了 + 新 tag),展示时
   从头 replay 累加。Phase 2 强烈建议同步实施。
2. **Sparse byte 态**:用 `FxHashMap<(u8 reg_id, u8 byte_offset), TagId>`
   替代 `[[u16; 8]; 256]`,仅存 tainted 的字节。大多数追踪里同时 tainted
   的 byte 数远 < 2048,省内存。

### Phase 2 UI 影响

#### 显式开关

主视图工具栏或 Taint 对话框加 checkbox:
```
☐ 启用字节级污点追踪(精确但慢)
```

默认关闭;打开后 engine `set_byte_level(true)`。

#### Tainted 集合展示变化

当前 `format_result` 显示 `{x0[rand→0xdead]}`,byte-level 下:
- **一体**:`{x0: [rand,rand,rand,rand,phone@4,phone@5,phone@6,phone@7]}`
- **精简**:`{x0[rand×4 | phone×4]}`(相邻相同 tag 合并)

UI 实现:用 egui 的 LayoutJob 画 8 个小彩色块,每块带 tag 名悬浮提示。

#### 新面板:Origin Heatmap

可选面板,按 tag 组织:
```
📊 Origin 贡献统计(本次追踪)
─ phone payload        占污染 byte 总数的 48%
─ libc.so!rand()       占 22%
─ rodata               占 18%
─ session_id token     占 12%
```

### Phase 2 测试清单

```rust
fn byte_level_mov_w_clears_upper_half()
fn byte_level_ldrb_isolates_single_byte()
fn byte_level_str_writes_exact_size()
fn byte_level_add_merges_by_byte()
fn byte_level_shift_non_8_boundary_fuzzes_merge()
fn byte_level_sha256_fans_all_inputs_to_all_outputs()
fn byte_level_external_call_fills_x0_with_ret_tag()
fn byte_level_preserves_phase1_bool_state()
fn byte_level_off_matches_phase1_exactly()  // 语义回归保护
```

### Phase 2 工作量估计

- trace.rs + parser.rs(mem_access_size 推断) ~ 50 行
- engine.rs 新增 ByteTaint + helpers ~ 200 行
- propagate_forward 分支逐条字节级实现 ~ 300 行
- rebuild_snapshots 同步 ~ 80 行
- delta snapshot(可选优化) ~ 150 行
- UI 开关 + 字节视图 ~ 120 行
- 测试 ~ 250 行
- **合计 ~ 1 150 行(含优化)或 ~ 900 行(不含 delta snapshot)**

---

## Phase 3 — Per-Byte Attribution Report 🎯 终极产出

### 用户故事

> 用户在结果面板(或主视图)选中"最终签名缓冲区"的 32 字节(右键菜单 →
> "反向归因此区域每字节"),系统返回一张表:
> 
> ```
> output[0x7a802a181d..+32] attribution:
>   byte  tag                                                 ASCII
>    0    PayloadByte(id=1, offset=4)   "T" of "GET\n..."    'T'
>    1    Combined(PayloadByte#1@5, rand#3)                  ' '
>    2    ExternalCallRet(GetStringUTFChars("session_id"))   0xa3
>    ...
>   31    ConstMem(libtiny.so rodata @+0x12a8)               0xff
> ```

这是**签名逆向的终极可视化**:每 byte 说清楚从输入到输出的"语义血缘"。

### 依赖

Phase 2 必须落地 —— attribution 要按字节读 tag。

### 算法

1. 用户提供 `(addr, size)` 作为归因目标。
2. 找到**最近一次写入这块内存**的 Store 序列(可能是单条 `str` 或多条细粒
   度写)。用 `reg_last_def` 的 mem 版本 backward-walk。
3. 对每字节 `addr + i`:
   - 查 `ByteTaint.mems[addr + i]` 得到 TagId
   - 若 TagId = `Combined(...)`,展开成 list 显示
4. 生成表格,每行 = 一个 byte 的 (byte_offset, tag, ascii_preview)

### UI 新面板

独立窗口或 SidePanel tab,表格 + 右侧 origin 详情:

```
[Byte Attribution] — output at 0x7a802a181d..+32

  Offset  Tag                              Byte  |  [right: Origin Details]
  ─────────────────────────────────────────────  |  ┌──────────────────────
  0x00    payload#1 @ offset 4             0x54  |  │ PayloadByte #1
  0x01    payload#1 @ offset 5             0x20  |  │ Address: 0x78e72b8e30
  0x02    rand #3                          0xd7  |  │ Source: free arg
  0x03    Combined (payload#1@7, rand#3)   0xf6  |  │ Length: 632 B
  ...                                             |  │ Content preview:
                                                   |  │ "GET\n/api/sns/v1..."
```

**交互**:
- 点击 Tag 列 → 右栏展开 origin 详情(复用 Phase 1.5 的 origin 摘要组件)
- 双击某字节行 → 主视图跳到**写该字节的 Store 指令**那一行
- 过滤:只看 PayloadByte / 只看 ExternalCallRet

### 实现量

- 后端算法 ~ 150 行
- UI 面板 ~ 250 行
- 菜单集成 ~ 30 行
- 测试 ~ 100 行(单元 + 端到端)
- **合计 ~ 530 行**

---

## 技术风险与对策

| 风险 | 概率 | 对策 |
|---|---|---|
| Phase 2 内存爆炸 | 高 | 一上来就做 delta snapshot(Phase 2 必做部分) |
| Byte-level 传播 bug 污染 Phase 1 | 中 | `byte_level=false` 是默认,保留 Phase 1 精确快路径;回归测试 `byte_level_off_matches_phase1_exactly` 保护语义 |
| Shift 按 8 倍数近似失准 | 低 | 文档声明;需要 bit 级时再做 Phase 4 |
| Combined tag 膨胀到数万 | 中 | 用 LRU 去重池 + 按"参与的 base tag set"规范化(相同集合共享同一 Combined id) |
| Parser `build_tag_table` 对罕见 ExternalCall 格式失败 | 低 | Fallback:失败时退化为无 `ExternalCallRet` tag,不阻塞其他阶段 |

---

## 各阶段是否需要改 UI

| 阶段 | 引擎 | UI 文本 | UI 结构 |
|---|---|---|---|
| **Phase 1** ✅ 已交付 | 改 | `format_result` 自动带 `[tag]` 后缀 | **不需要改结构** |
| **Phase 1.5** 可选 | 不改 | — | 加 "污点来源" 侧边摘要 + badge 着色 + ExternalCall 作为 source 菜单 |
| **Phase 2** | 改 | tainted 集合改为字节视图 | 加 byte-level 开关 checkbox,加 Origin Heatmap 面板(可选) |
| **Phase 3** | 改 | — | **加独立的 Byte Attribution 窗口/Tab**,右键菜单新增"反向归因此区域每字节" |

**结论**:
- Phase 1 的 UI 自然变得更有信息,不需要改动任何 widget 结构
- Phase 1.5 是纯 UI 收益,**强烈推荐在 Phase 2 之前做**
- Phase 2 需要轻量 UI 改动(开关 + 展示)
- Phase 3 才是真正的新面板

---

## 推进建议

1. **先 commit Phase 1**(已完成,测试全绿)
2. **Phase 1.5 快速上**(~240 行 UI):这是 Phase 1 价值的放大器,用户收益明显
3. **Phase 1.5 验证一周后**:评估 byte-level 是否仍有刚需
4. **Phase 2 + Phase 3 按需推进**:每阶段独立一轮实施,每轮含 delta snapshot
   优化 + 全新测试 + UI 联动

## 附录:相关提交

- `1789d29` — 修复污点追踪多项正确性问题
- `789dcd1` — 修复双击词高亮两处问题
- (待提交) — Phase 1 语义标签系统
