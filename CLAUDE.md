# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## egui 交互:不要给普通 Label / RichText 加 `Sense::click` 或 `Sense::click_and_drag`

任何带 interactive sense 的 widget(尤其是覆盖较大区域的 Label)会**在用户点击它时抢走当前 TextEdit 的焦点** —— 典型症状:"Ctrl+F 搜索框输入不了文字"、"输入法切出来但按键无反应"。这个问题在本项目反复出现过至少两次,每次都是手滑给 Label 加 `.sense(Sense::click())` 起的。

正确做法:

- **表格行点击**:用 `egui_extras::TableBuilder::sense(Sense::click())` 给整行一个 interact rect,然后 `row.response().clicked()` / `double_clicked()`。cell 里的 Label **不要**再加任何 sense。
- **右键菜单**:直接挂在 `Response::context_menu` 上。Label 默认的 `selectable` 就包含 click sense 了,不需要再 `.sense(click)`。只在 `selectable_labels` 被禁用且确实需要 context menu 时,才考虑 `.interact(Sense::click())` 在外层容器的 response 上转一层。
- **主视图每行**:保持 Label 无显式 sense(默认 selectable 足够做文本拖选 + 右键菜单)。

写新 panel 前自测清单:
1. 放一个 TextEdit,聚焦后打字正常
2. 在其他 Panel/Window 里随便点一下后,回到 TextEdit,继续打字仍然正常
任何一个失败 = 有 widget 抢焦点了,找那个 widget 去 sense。

## Non-Goals (currently)

**attd** — a trace-log-based replay debugger (time-travel style: pick any instruction as "now", reconstruct registers + memory at that moment, step forward/back, reverse-cause a value). This is the planned next phase but is **explicitly out of scope today**. Do not:

- add stub crates / modules for it (`large-text-replay` etc.)
- extend `TraceLine` with "replay-friendly" fields that nothing reads
- introduce "virtual machine state" / "register snapshot" abstractions for future use
- carve out UI slots (empty panels / menu items) for it

When the user explicitly starts the attd work, add it as a new sibling crate next to `large-text-taint`, consuming the same `Vec<TraceLine>` parser output. Until then, avoid premature abstraction — current code stays lean.

## Commands

Workspace with three crates: root `large-text-viewer` (GUI binary), `crates/large-text-core` (viewer backend), and `crates/large-text-taint` (ARM64 xgtrace taint tracking, ported from the C++ `gumtrace_src` project).

- Build (release, optimal for perf testing): `cargo build --release`
- Run the GUI: `cargo run --release`
- Run all tests across workspace: `cargo test --workspace`
- Run a single test by name: `cargo test --workspace <test_name>` (add `-- --nocapture` to see println output)
- Run tests for just the core crate: `cargo test -p large-text-core`
- Lint (must pass with `-D warnings`; CI gate): `cargo clippy --release -- -D warnings`
- Generate large test fixtures (bash, creates `test_files/`): `./scripts/generate_test_files.sh`

CI (`.github/workflows/build.yml`) runs clippy with `-D warnings` on Windows only, then `cargo build --release` and `cargo test --release` on Windows/macOS/Ubuntu. Keep clippy clean.

## Architecture

Two-layer design that separates file processing from rendering so the core can be reused (e.g. future Zed extension).

### `large-text-core` (crates/large-text-core/src/)

Backend for memory-mapped access to files larger than RAM. Four modules exposed from `lib.rs`:

- **`file_reader`** — Wraps `memmap2::Mmap`. Handles encoding detection/decoding (UTF-8, UTF-16 LE/BE, Windows-1252 via `encoding_rs`). The entire stack below treats the file as raw bytes; decoding only happens for bytes about to be displayed. `FileReader` is shared across threads as `Arc<FileReader>`.
- **`line_indexer`** — Hybrid strategy, switched by file size:
  - Full index (<10MB): exact line→byte map.
  - Sparse index (large files): checkpoint-based, keeps index <1MB for 100GB files. Exact line counts are deliberately approximated (UI shows "~N lines"). When adding features that need exact line positions in sparse mode, expect to walk from the nearest checkpoint.
- **`search_engine`** — Parallel chunked search over the mmap. Literal and regex. Communicates with callers via `std::sync::mpsc` using `SearchMessage::{CountResult, ChunkResult}`, driven by an `Arc<AtomicBool>` cancellation token. `count_matches` and `fetch_matches` are separate passes — counts stream in first, then pages of matches are fetched on demand.
- **`replacer`** — Two code paths depending on length:
  - In-place when replacement length == match length (writes directly into mmap region).
  - Copy-on-write via temp file + atomic rename when lengths differ. Never mutates the original file until the final rename succeeds.
  Progress is streamed through `ReplaceMessage`.

### `large-text-taint` (crates/large-text-taint/src/)

Rust port of the C++ `gumtrace_src` project (`TraceParser` + `TaintEngine`). Reads xgtrace-format logs like `libtiny.so!17c090 0x76feda3090: "ldr x1, [x8]" ...` and runs forward/backward taint propagation over ARM64 register + memory state.

- **`reg`** — RegId constants, `parse_reg_name`, `normalize` (w→x, fp→x29, lr→x30, d/s→q aliases collapsed).
- **`trace`** — `TraceLine` (compact, ~80 bytes) and `classify_mnemonic` for instruction category.
- **`parser`** — `TraceParser` operates on a borrowed `&[u8]` slice (no internal copy) so the caller's mmap stays the single source of truth. `load_range(bytes, max_line, max_offset)` supports the same windowed-loading strategies as the C++ version (backward: up to `start_line`; forward: up to `start_offset + window_bytes`). Raw-line lookup is a free function `read_raw_line(bytes, &tl)` keyed on `file_offset` / `line_len`.
- **`engine`** — `TaintEngine::run(&[TraceLine], start_index)` returns structured `Vec<ResultEntry>` (register bitmap + tainted mem set per hit). Supports an `Arc<AtomicBool>` cancel token; the only difference from the C++ version is `StopReason::Cancelled` was added. `format_result(lines, bytes)` produces the same text output format as `taint_tracker.exe`.

### `large-text-viewer` (src/)

`egui`/`eframe` immediate-mode GUI. Two files:

- `main.rs` — eframe entrypoint; declares `app` and `taint` modules.
- `taint.rs` — UI + background-thread driver for `large-text-taint`. Owns the taint dialog state, a right-side `SidePanel` showing hits, and an `mpsc`-based worker that parses the current mmap and runs the engine. Hit rows are also surfaced as a `HashSet<usize>` consumed by `app.rs` to background-highlight matching lines in the central viewport.
- `app.rs` — `TextViewerApp` holds all UI state and owns the core components (`Arc<FileReader>`, `LineIndexer`, `SearchEngine`, plus a `TaintState`). Key design points:
  - **Virtual scrolling**: only the visible viewport is decoded each frame. `scroll_line`, `visible_lines`, `scroll_to_row`, `scroll_correction`, `pending_scroll_target` together cope with `f32` scrollbar precision loss on multi-GB files — if you touch scrolling, preserve the correction logic.
  - **Async pattern**: every long-running op (search count, search fetch, replace, file-change tail) owns an `mpsc::Receiver` field on `TextViewerApp` plus an `Arc<AtomicBool>` cancellation token. The `update()` loop drains these receivers non-blockingly each frame. Do not block the UI thread — spawn a worker and stream messages back.
  - **Pending replacements**: single replaces are queued in memory (shown by `*` in the title) and only flushed on Save, which may call `Replacer` to rewrite the file.
  - **Tail mode**: uses `notify` crate with a `RecursiveMode` watcher; file-change notifications arrive via `file_change_rx`.

### Data-flow invariants

- Bytes flow `FileReader` → `LineIndexer`/`SearchEngine` → UI; the UI never reads the mmap directly.
- `FileReader` is `Arc`-shared; treat it as immutable while search/replace threads may hold references.
- When adding new background work, follow the existing channel + cancellation-token pattern rather than introducing a new async runtime — the project is deliberately runtime-free (no tokio).
