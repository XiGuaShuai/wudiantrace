# wudiantrace

ARM64 xgtrace 污点追踪器 + 大文本查看器 GUI,纯 Rust / egui。

面向逆向分析场景 —— 打开几 GB 的汇编 trace 日志时不卡,右键某条指令直接对寄存器或内存地址做前向/后向污点追踪,结果以表格展示并可跳回原行。

## 功能

- **大文件瞬时打开**:memmap2 + 稀疏行索引,>4GB 的 trace 秒开,常驻内存 < 100MB
- **虚拟滚动**:只渲染视口内的行,60 FPS 流畅
- **后台并行搜索 / 替换**:字面量与正则,实时进度
- **污点追踪(新)**:
  - 右键指令行 → 菜单直接列出该行所有寄存器和内存地址 → 一键跑 forward / backward
  - 后台线程执行,mpsc 汇报进度,UI 不阻塞
  - 结果以五列表格显示(Line / Module!Offset / Addr / ASM / Tainted),支持过滤
  - 双击表格行跳回原 trace 对应位置
  - 主视图对所有命中行背景高亮
  - 同时支持两种 trace 格式(逐行自动识别):
    - xgtrace (QBDI) — `libtiny.so!offset 0xabs: "asm" snap` + 独立 `MEM R/W` 行
    - GumTrace 原生 — `[module] 0xabs!0xrel mnem ops ; mem_r=... mem_w=...`
  - STP / LDP 双地址推断 fallback(单次 MEM 观测时自动补第二个地址,避免污点链断裂)

## 架构

三个 crate 的 workspace:

| Crate | 作用 |
|---|---|
| `large-text-core` | `FileReader`(mmap)/ `LineIndexer`(稀疏索引)/ `SearchEngine`(并行块扫描)/ `Replacer`(CoW 替换) |
| `large-text-taint` | `TraceParser`(xgtrace + GumTrace 双格式)/ `TaintEngine`(前向/后向传播),纯 stdlib 实现 |
| `large-text-viewer` | egui GUI,组合上述两个 crate |

详见 [CLAUDE.md](CLAUDE.md)。

## 构建

```bash
cargo build --release
cargo run --release
```

测试:

```bash
cargo test --workspace
```

## 上游项目

本项目由以下开源项目移植 / 整合:

- [acejarvis/large-text-viewer](https://github.com/acejarvis/large-text-viewer) — 大文件查看器底座(MIT)
- [lidongyooo/GumTrace](https://github.com/lidongyooo/GumTrace) — ARM64 污点追踪引擎(C++ 原版,本仓库完整 Rust 移植)

## Roadmap(未来规划)

### attd —— 基于 trace log 的回放式调试器(**暂不实现**)

设想中的下一阶段能力(不在当前 scope 内,列在这里只为提醒自己 + 避免别人手滑加代码):

- 以 trace log 的任意一条指令作为"当前时刻",查看那一刻 ARM64 所有寄存器 + 相关内存的重建快照
- 前进 / 后退单步,跨指令跳转(按地址、按行号、按条件)
- 反向推因:选一个寄存器/内存值,自动回答"谁在什么时刻把它写成这个值的"(现有的 backward taint 可视为这个能力的前身)
- 复用现有 `large-text-taint::parser` 产出的 `Vec<TraceLine>`,在上面做虚拟机状态模拟

预计落地方式:新增 `crates/large-text-replay`,与现有 taint 引擎并列,对外再加一个停靠面板。**在用户明确要开始做之前,不加任何 attd 相关的代码或预留接口** —— 避免过早抽象。

## License

MIT
