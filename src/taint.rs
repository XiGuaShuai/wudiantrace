//! Taint-tracking integration for the viewer.
//!
//! Holds the dialog/panel state, runs `TraceParser` + `TaintEngine` on the
//! currently loaded mmap in a background thread, and reports results back via
//! mpsc channels following the same pattern as `SearchEngine`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use eframe::egui;
use large_text_core::file_reader::FileReader;
use large_text_taint::engine::{ResultEntry, StopReason, TaintEngine, TaintSource, TrackMode};
use large_text_taint::parser::{read_raw_line, TraceParser};
use large_text_taint::reg::{parse_reg_name, reg_name, REG_INVALID};
use large_text_taint::trace::TraceLine;

/// Hit row info kept for fast highlight lookup + jump.
#[derive(Clone, Debug)]
pub struct TaintHit {
    /// Byte offset of the start of this line in the mmap. The *authoritative*
    /// coordinate used for both jump + main-view highlight, because the
    /// viewer's sparse line index converts byte offsets to rows with enough
    /// precision for scrolling, while row numbers themselves are only
    /// approximate in sparse mode.
    pub file_offset: u64,
    pub line_number: u32,      // 1-based precise file line (for display)
    pub raw_line: String,      // full original trace line, shown as tooltip
    pub module_offset: String, // e.g. "libtiny.so!178dc8"
    pub addr: String,          // e.g. "0x76fed9fdc8"
    pub asm: String,           // contents of the double-quoted asm string (tabs normalised to spaces)
    pub tainted_text: String,  // "x0, x8, mem:0x1234" for table column + regex filter
    pub tainted_regs: Vec<String>,
    pub tainted_mems: Vec<u64>,
}

pub struct TaintCompleted {
    pub hits: Vec<TaintHit>,
    pub stop_reason: StopReason,
    pub mode: TrackMode,
    pub source_label: String,
    pub instructions_parsed: usize,
    pub formatted: String, // ready to be saved with "Save results"
}

pub enum TaintMessage {
    Status(String),
    Done(Box<TaintCompleted>),
    Error(String),
}

/// Where a side panel should dock relative to the central text area.
/// Panels never overlap the editor — the editor always occupies whatever the
/// docked panels don't.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DockSide {
    Right,
    Left,
    Bottom,
}

pub struct TaintState {
    // Dialog open/close
    pub show_dialog: bool,
    pub show_panel: bool,

    // Dialog inputs
    pub mode: TrackMode,
    pub source_text: String, // e.g. "x0", "w12", "sp", "mem:0x12345"
    pub start_line_text: String,
    pub scan_limit_text: String,
    pub max_depth_text: String,
    pub forward_window_mb_text: String,

    // Background job
    pub running: bool,
    pub status_text: String,
    pub cancel: Option<Arc<AtomicBool>>,
    pub rx: Option<Receiver<TaintMessage>>,

    // Last completed result
    pub completed: Option<TaintCompleted>,
    /// All hit byte offsets (start-of-line) for O(1) highlight lookup during
    /// main-view rendering. Offsets come straight from parser.file_offset and
    /// are therefore exact regardless of sparse-index row estimation.
    pub hit_offsets: HashSet<u64>,
    pub selected_hit: Option<usize>,
    /// Byte offset of the line the user has selected in the panel. Main view
    /// uses this to paint the distinct "active" colour.
    pub selected_offset: Option<u64>,

    // Table filter
    pub filter_text: String,
    pub filter_dirty: bool,
    pub filtered_indices: Vec<usize>, // indices into completed.hits that match filter

    // Docking side
    pub dock_side: DockSide,
}

impl Default for TaintState {
    fn default() -> Self {
        Self {
            show_dialog: false,
            show_panel: true,
            mode: TrackMode::Backward,
            source_text: String::new(),
            start_line_text: String::new(),
            scan_limit_text: "50000".to_string(),
            max_depth_text: "64".to_string(),
            forward_window_mb_text: "200".to_string(),
            running: false,
            status_text: String::new(),
            cancel: None,
            rx: None,
            completed: None,
            hit_offsets: HashSet::new(),
            selected_hit: None,
            selected_offset: None,
            filter_text: String::new(),
            filter_dirty: false,
            filtered_indices: Vec::new(),
            dock_side: DockSide::Right,
        }
    }
}

impl TaintState {
    /// Open the dialog, pre-filling start_line with `current_row + 1` (1-based).
    pub fn open_dialog(&mut self, current_row: usize) {
        self.show_dialog = true;
        if self.start_line_text.is_empty() {
            self.start_line_text = (current_row + 1).to_string();
        }
    }

    /// Cancel any in-flight job and clear the result set.
    pub fn clear_results(&mut self) {
        if let Some(c) = &self.cancel {
            c.store(true, Ordering::Relaxed);
        }
        self.cancel = None;
        self.rx = None;
        self.running = false;
        self.completed = None;
        self.hit_offsets.clear();
        self.selected_hit = None;
        self.selected_offset = None;
        self.filter_text.clear();
        self.filter_dirty = false;
        self.filtered_indices.clear();
        self.status_text.clear();
    }

    /// Kick off a job without going through the dialog — called by the
    /// right-click quick-start menu. `start_offset` is the exact byte offset
    /// of the instruction line the user clicked on; `start_line_hint` is the
    /// viewer-side 1-based line number (shown in status/UI only — sparse-index
    /// approximations here are harmless because the engine locates the
    /// instruction by its precise byte offset).
    pub fn quick_start(
        &mut self,
        reader: Arc<FileReader>,
        mode: TrackMode,
        source: TaintSource,
        start_offset: u64,
        start_line_hint: u32,
    ) -> Result<(), String> {
        // sync dialog state so the UI reflects the job parameters
        self.mode = mode;
        self.source_text = format_source_label(&source);
        self.start_line_text = start_line_hint.to_string();
        self.start_job_with(reader, mode, source, Some(start_offset), start_line_hint)
    }

    /// Kick off a tracking job in a background thread using the dialog inputs.
    pub fn start_job(&mut self, reader: Arc<FileReader>) -> Result<(), String> {
        let source = parse_source(&self.source_text)
            .map_err(|e| format!("起点格式无效: {}", e))?;
        let start_line: u32 = self
            .start_line_text
            .trim()
            .parse()
            .map_err(|_| "起始行必须是正整数".to_string())?;
        if start_line == 0 {
            return Err("起始行必须 >= 1".to_string());
        }
        // Dialog entry point: we only have a line number typed by the user,
        // so we let the backend resolve it via `find_by_line`.
        self.start_job_with(reader, self.mode, source, None, start_line)
    }

    fn start_job_with(
        &mut self,
        reader: Arc<FileReader>,
        mode: TrackMode,
        source: TaintSource,
        start_offset: Option<u64>,
        start_line: u32,
    ) -> Result<(), String> {
        let scan_limit: u32 = self
            .scan_limit_text
            .trim()
            .parse()
            .map_err(|_| "扫描上限必须是非负整数".to_string())?;
        let max_depth: u32 = self
            .max_depth_text
            .trim()
            .parse()
            .map_err(|_| "追踪深度必须是正整数".to_string())?;
        let window_mb: u64 = self
            .forward_window_mb_text
            .trim()
            .parse()
            .map_err(|_| "向前窗口必须是整数 (MB)".to_string())?;

        if let Some(c) = self.cancel.take() {
            c.store(true, Ordering::Relaxed);
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx): (Sender<TaintMessage>, Receiver<TaintMessage>) = channel();

        self.cancel = Some(cancel.clone());
        self.rx = Some(rx);
        self.running = true;
        // Make sure the panel is visible so the user sees the running banner
        // immediately — otherwise a closed panel + backgrounded job looks
        // exactly like "clicked, nothing happened".
        self.show_panel = true;
        self.status_text = format!(
            "{} 从行 {} ({}) — 加载 trace 中...",
            match mode {
                TrackMode::Forward => "向前",
                TrackMode::Backward => "向后",
            },
            start_line,
            format_source_label(&source),
        );
        // NOTE: keep the previous completed result + highlights visible while
        // the new job runs. They will be swapped out atomically on the next
        // `TaintMessage::Done`, so the user never sees a flicker of empty
        // state on the central text area.

        let job = JobConfig {
            reader,
            mode,
            source,
            source_label: format_source_label(&source),
            start_offset,
            start_line,
            scan_limit,
            max_depth,
            forward_window_bytes: window_mb.saturating_mul(1024 * 1024),
            cancel: cancel.clone(),
            tx,
        };

        thread::spawn(move || run_job(job));
        Ok(())
    }

    /// Drain the channel each frame; populates `completed` / clears `running`.
    pub fn poll(&mut self) -> bool {
        let mut changed = false;
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                changed = true;
                match msg {
                    TaintMessage::Status(s) => self.status_text = s,
                    TaintMessage::Done(boxed) => {
                        // atomic swap: replace highlights + panel data together
                        self.hit_offsets = boxed.hits.iter().map(|h| h.file_offset).collect();
                        self.status_text = format!(
                            "完成。命中 {} 条,已解析 {} 条,停止原因: {}",
                            boxed.hits.len(),
                            boxed.instructions_parsed,
                            stop_reason_label(boxed.stop_reason)
                        );
                        self.filtered_indices = (0..boxed.hits.len()).collect();
                        self.filter_dirty = false;
                        self.filter_text.clear();
                        self.selected_hit = None;
                        self.selected_offset = None;
                        self.completed = Some(*boxed);
                        self.show_panel = true;
                        self.running = false;
                    }
                    TaintMessage::Error(e) => {
                        // Clear stale result so the panel foregrounds the
                        // error banner instead of still-showing previous hits.
                        self.status_text = format!("错误: {}", e);
                        self.completed = None;
                        self.hit_offsets.clear();
                        self.filtered_indices.clear();
                        self.selected_hit = None;
                        self.selected_offset = None;
                        self.running = false;
                        self.show_panel = true;
                    }
                }
            }
        }
        if !self.running {
            self.rx = None;
            self.cancel = None;
        }
        changed
    }
}

struct JobConfig {
    reader: Arc<FileReader>,
    mode: TrackMode,
    source: TaintSource,
    source_label: String,
    /// Exact byte offset of the instruction line to start at. When `Some`,
    /// it takes priority over `start_line` (used for right-click entries).
    /// When `None` the backend falls back to `parser.find_by_line(start_line)`.
    start_offset: Option<u64>,
    start_line: u32,
    scan_limit: u32,
    max_depth: u32,
    forward_window_bytes: u64,
    cancel: Arc<AtomicBool>,
    tx: Sender<TaintMessage>,
}

fn run_job(job: JobConfig) {
    let JobConfig {
        reader,
        mode,
        source,
        source_label,
        start_offset,
        start_line,
        scan_limit,
        max_depth,
        forward_window_bytes,
        cancel,
        tx,
    } = job;
    let bytes = reader.all_data();

    // Resolve the exact byte offset of the start line. When the caller already
    // has an offset (right-click path) we trust it; otherwise count newlines
    // forwards from the start of the file.
    let start_off = match start_offset {
        Some(off) => off,
        None => {
            let _ = tx.send(TaintMessage::Status(
                "定位起始行...".to_string(),
            ));
            match offset_of_line(bytes, start_line) {
                Some(o) => o,
                None => {
                    let _ = tx.send(TaintMessage::Error(format!(
                        "未找到起始行 {}",
                        start_line
                    )));
                    return;
                }
            }
        }
    };

    // Load enough of the trace into memory to cover the tracking range.
    let mut parser = TraceParser::new();
    match mode {
        TrackMode::Backward => {
            let _ = tx.send(TaintMessage::Status(format!(
                "解析 trace [0..字节 {}] ...",
                start_off
            )));
            // `max_offset = start_off` loads every instruction up to and
            // including the one whose line starts at `start_off`.
            parser.load_range(bytes, u32::MAX, start_off);
        }
        TrackMode::Forward => {
            let max_off = start_off.saturating_add(forward_window_bytes);
            let _ = tx.send(TaintMessage::Status(format!(
                "解析 trace [0..字节 {}] (~{} MB) ...",
                max_off,
                max_off / (1024 * 1024)
            )));
            parser.load_range(bytes, u32::MAX, max_off);
        }
    }
    if cancel.load(Ordering::Relaxed) {
        let _ = tx.send(TaintMessage::Error("已取消".to_string()));
        return;
    }
    if parser.is_empty() {
        let _ = tx.send(TaintMessage::Error(
            "解析范围内未找到任何指令行".to_string(),
        ));
        return;
    }

    // Prefer offset-based lookup (exact) over line-number lookup (which is
    // affected by whether the clicked line is an instruction or a MEM line).
    let start_index = match parser.find_by_offset(start_off) {
        Some(i) if parser.lines()[i].file_offset == start_off => i,
        Some(i) => {
            // Clicked line itself wasn't an instruction (e.g. a `MEM W` line);
            // fall through to the nearest following instruction and tell the
            // user via status so "I clicked 47 but got 48" is not a surprise.
            let landed = parser.lines()[i].line_number;
            let _ = tx.send(TaintMessage::Status(format!(
                "起点第 {} 行不是指令行,已跳到下一条指令(第 {} 行)",
                start_line, landed
            )));
            i
        }
        None => {
            let _ = tx.send(TaintMessage::Error(format!(
                "起始行 {} 不是可解析的指令行",
                start_line
            )));
            return;
        }
    };

    let _ = tx.send(TaintMessage::Status(format!(
        "追踪中({})— 起点索引 {} (行 {}) ...",
        match mode {
            TrackMode::Forward => "向前",
            TrackMode::Backward => "向后",
        },
        start_index,
        parser.lines()[start_index].line_number
    )));

    let mut engine = TaintEngine::new();
    engine.set_mode(mode);
    engine.set_source(source);
    engine.set_max_scan_distance(scan_limit);
    engine.set_max_depth(max_depth);
    engine.set_cancel_token(cancel.clone());
    engine.run_with_bytes(parser.lines(), start_index, bytes);

    if cancel.load(Ordering::Relaxed) && engine.stop_reason() == StopReason::Cancelled {
        let _ = tx.send(TaintMessage::Error("已取消".to_string()));
        return;
    }

    let formatted = engine.format_result(parser.lines(), bytes);
    let stop_reason = engine.stop_reason();
    let lines = parser.lines();
    let hits = engine
        .results()
        .iter()
        .map(|r| build_hit(r, lines, bytes))
        .collect::<Vec<_>>();

    let completed = TaintCompleted {
        hits,
        stop_reason,
        mode,
        source_label,
        instructions_parsed: parser.len(),
        formatted,
    };
    let _ = tx.send(TaintMessage::Done(Box::new(completed)));
}

fn build_hit(entry: &ResultEntry, lines: &[TraceLine], bytes: &[u8]) -> TaintHit {
    let tl = &lines[entry.index];
    let raw = read_raw_line(bytes, tl);
    let raw = raw.trim_end_matches(['\n', '\r']).to_string();

    let mut regs: Vec<String> = Vec::new();
    for i in 0..256u16 {
        if entry.reg_snapshot[i as usize] {
            regs.push(reg_name(i as u8).to_string());
        }
    }
    let mut mems = entry.mem_snapshot.clone();
    mems.sort_unstable();

    // ExternalCall(-> libc.so!malloc(48) ret: ...)的显示策略:
    //   行号/模块/地址/汇编 → 显示**前一条指令**(br x17 / blr xN),
    //     因为那才是用户在 trace 里能看到的"发起调用"的指令。
    //   污点集 → 显示外部函数名(libc.so!malloc(48)),一目了然
    //     "x0 来自这个外部调用的返回值"。
    let is_ext = tl.category == large_text_taint::trace::InsnCategory::ExternalCall;

    // 对 ExternalCall,找前一条指令(br/blr)来展示
    let (hit_line_number, hit_file_offset, hit_raw, module_offset, addr, asm) = if is_ext
        && entry.index > 0
    {
        let prev_tl = &lines[entry.index - 1];
        let prev_raw = read_raw_line(bytes, prev_tl);
        let prev_raw = prev_raw.trim_end_matches(['\n', '\r']).to_string();
        let (mo, ad, as_) = split_trace_line(&prev_raw);
        (prev_tl.line_number, prev_tl.file_offset, prev_raw, mo, ad, as_)
    } else if is_ext {
        // ExternalCall 在第一条位置(没有前一条),退化显示
        let func_name = extract_external_call_name(&raw);
        (tl.line_number, tl.file_offset, raw.clone(),
         "外部调用".to_string(), String::new(), func_name)
    } else {
        let (mo, ad, as_) = split_trace_line(&raw);
        (tl.line_number, tl.file_offset, raw.clone(), mo, ad, as_)
    };

    // 污点集:ExternalCall 显示函数名,普通指令显示 tainted regs/mems
    let mut tainted_text = if is_ext {
        extract_external_call_name(&raw)
    } else {
        regs.join(", ")
    };
    if !is_ext {
        // 普通指令才把 mems 追加到 regs 后面
        for m in &mems {
            if !tainted_text.is_empty() {
                tainted_text.push_str(", ");
            }
            tainted_text.push_str(&format!("mem:0x{:x}", m));
        }
    }

    TaintHit {
        file_offset: hit_file_offset,
        line_number: hit_line_number,
        raw_line: hit_raw,
        module_offset,
        addr,
        asm,
        tainted_text,
        tainted_regs: regs,
        tainted_mems: mems,
    }
}

/// 从 `-> libc.so!malloc(1440) ret: 0x78d7d22d20` 提取 `libc.so!malloc(1440)`。
fn extract_external_call_name(raw: &str) -> String {
    let trimmed = raw.trim();
    let rest = trimmed.strip_prefix("-> ").unwrap_or(trimmed);
    // 取到 " ret:" 之前,或整行
    match rest.find(" ret:") {
        Some(pos) => rest[..pos].trim().to_string(),
        None => rest.trim().to_string(),
    }
}

/// Split an xgtrace line into (module_offset, addr, asm). `asm` is exactly the
/// string that appeared between the double quotes, with tabs normalised to
/// single spaces and leading whitespace trimmed — no other formatting applied,
/// so what you see in the table column matches the disassembler output.
///
/// Format:
///   `libtiny.so!178dc8 0x76fed9fdc8: "\tstp\tx29, x30, [sp, #-0x60]!" FP=..., ...`
fn split_trace_line(raw: &str) -> (String, String, String) {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b' ' {
        i += 1;
    }
    let module_offset = raw[..i].to_string();
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    let addr_start = i;
    while i < bytes.len() && bytes[i] != b':' && bytes[i] != b' ' {
        i += 1;
    }
    let addr = raw[addr_start..i].to_string();
    let asm = if let Some(qs) = raw[i..].find('"') {
        let qs = i + qs + 1;
        if let Some(qe) = raw[qs..].find('"') {
            clean_asm(&raw[qs..qs + qe])
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    (module_offset, addr, asm)
}

/// Turn a raw disassembler snippet like `"\tstp\tx29, x30, [sp, #-0x60]!"` into
/// `"stp x29, x30, [sp, #-0x60]!"` — tabs → single space, then leading
/// whitespace trimmed. No mnemonic padding: the rendered asm stays as close
/// as possible to what the original tool emitted.
fn clean_asm(raw_asm: &str) -> String {
    let mut s = String::with_capacity(raw_asm.len());
    let mut last_space = false;
    for ch in raw_asm.chars() {
        let c = if ch == '\t' { ' ' } else { ch };
        if c == ' ' {
            if !last_space {
                s.push(' ');
            }
            last_space = true;
        } else {
            s.push(c);
            last_space = false;
        }
    }
    s.trim().to_string()
}

/// Count newlines until reaching the start of `line_number` (1-based).
/// Returns the byte offset of that line's first character, or None if the file
/// has fewer lines.
fn offset_of_line(bytes: &[u8], line_number: u32) -> Option<u64> {
    if line_number <= 1 {
        return Some(0);
    }
    let want_prev_nl = line_number - 1; // we need to skip this many '\n'
    let mut seen = 0u32;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            seen += 1;
            if seen == want_prev_nl {
                return Some((i + 1) as u64);
            }
        }
    }
    None
}

/// Enumerate distinct register + memory targets referenced by a single parsed
/// trace line, preserving insertion order. Used by the right-click menu to
/// offer one-click "forward/backward from <reg>" entries.
pub fn collect_targets(tl: &TraceLine, raw_line: &[u8]) -> Vec<TaintSource> {
    let mut out: Vec<TaintSource> = Vec::new();
    let mut seen_reg: [bool; 256] = [false; 256];
    // For dst registers: use the OUTPUT value (after =>) for value-sensitive tracking
    for i in 0..tl.num_dst as usize {
        let id = tl.dst_regs[i];
        if id == REG_INVALID {
            continue;
        }
        let n = large_text_taint::reg::normalize(id) as usize;
        if !seen_reg[n] {
            seen_reg[n] = true;
            let val = large_text_taint::parser::parse_output_reg_val(raw_line, id);
            let mut src = TaintSource::from_reg(id);
            src.expected_val = val;
            out.push(src);
        }
    }
    // For src registers: use the INPUT value (before =>) for value-sensitive tracking
    for i in 0..tl.num_src as usize {
        let id = tl.src_regs[i];
        if id == REG_INVALID {
            continue;
        }
        let n = large_text_taint::reg::normalize(id) as usize;
        if !seen_reg[n] {
            seen_reg[n] = true;
            let val = large_text_taint::parser::parse_input_reg_val(raw_line, id);
            let mut src = TaintSource::from_reg(id);
            src.expected_val = val;
            out.push(src);
        }
    }
    if tl.has_mem_read {
        out.push(TaintSource::from_mem(tl.mem_read_addr));
    }
    if tl.has_mem_read2 {
        out.push(TaintSource::from_mem(tl.mem_read_addr2));
    }
    if tl.has_mem_write {
        out.push(TaintSource::from_mem(tl.mem_write_addr));
    }
    if tl.has_mem_write2 {
        out.push(TaintSource::from_mem(tl.mem_write_addr2));
    }
    out
}

/// For Load/Store instructions, collect address-source registers that the
/// user might want to track independently. Returns sources with
/// `skip_start_propagation = true` so the engine tracks the register
/// directly without redirecting taint through the Load/Store propagation.
///
/// Example: `ldr x8, [x27, x8]` → returns [x27, x8] as address sources.
/// The user can pick x8 here to track *where the address offset came from*,
/// separate from tracking *what value was loaded*.
pub fn collect_addr_source_targets(tl: &TraceLine, raw_line: &[u8]) -> Vec<TaintSource> {
    use large_text_taint::trace::InsnCategory;
    if !matches!(tl.category, InsnCategory::Load | InsnCategory::Store) {
        return Vec::new();
    }
    let mut out: Vec<TaintSource> = Vec::new();
    let mut seen_reg: [bool; 256] = [false; 256];
    for i in 0..tl.num_src as usize {
        let id = tl.src_regs[i];
        if id == REG_INVALID {
            continue;
        }
        let n = large_text_taint::reg::normalize(id) as usize;
        if !seen_reg[n] {
            seen_reg[n] = true;
            let val = large_text_taint::parser::parse_input_reg_val(raw_line, id);
            let mut src = TaintSource::from_reg_as_source(id);
            src.expected_val = val;
            out.push(src);
        }
    }
    out
}

pub fn source_display(src: &TaintSource) -> String {
    format_source_label(src)
}

fn parse_source(s: &str) -> Result<TaintSource, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("起点不能为空".to_string());
    }
    if let Some(rest) = s.strip_prefix("mem:").or_else(|| s.strip_prefix("MEM:")) {
        let hex = rest
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        let addr = u64::from_str_radix(hex, 16).map_err(|e| format!("内存地址格式错误: {}", e))?;
        return Ok(TaintSource::from_mem(addr));
    }
    let id = parse_reg_name(s.as_bytes());
    if id == REG_INVALID {
        return Err(format!("未知寄存器 '{}'", s));
    }
    Ok(TaintSource::from_reg(id))
}

fn format_source_label(src: &TaintSource) -> String {
    if src.is_mem {
        format!("mem:0x{:x}", src.mem_addr)
    } else if let Some(val) = src.expected_val {
        format!("{}=0x{:x}", reg_name(src.reg), val)
    } else {
        reg_name(src.reg).to_string()
    }
}

fn stop_reason_label(r: StopReason) -> &'static str {
    match r {
        StopReason::AllTaintCleared => "污点全部清除",
        StopReason::EndOfTrace => "到达 trace 末尾",
        StopReason::ScanLimitReached => "达到扫描上限",
        StopReason::Cancelled => "已取消",
    }
}

// =========================================================================
// UI
// =========================================================================

/// Modal-ish dialog for configuring a new taint job.
/// Returns Some(jump_target_row) if the user clicked an existing hit (not used here).
pub fn render_dialog(
    ctx: &egui::Context,
    state: &mut TaintState,
    reader: Option<&Arc<FileReader>>,
) -> Option<String> {
    if !state.show_dialog {
        return None;
    }
    let mut error: Option<String> = None;

    let mut open = state.show_dialog;
    egui::Window::new(egui::RichText::new("🎯 污点追踪").size(14.0))
        .open(&mut open)
        .resizable(false)
        .collapsible(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .default_width(380.0)
        .show(ctx, |ui| {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("方向")
                    .size(11.0)
                    .color(egui::Color32::from_rgb(150, 150, 150)),
            );
            ui.horizontal(|ui| {
                let fwd_sel = state.mode == TrackMode::Forward;
                let bwd_sel = state.mode == TrackMode::Backward;
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("→  向前")
                                .size(13.0)
                                .color(if fwd_sel {
                                    egui::Color32::BLACK
                                } else {
                                    FORWARD_COLOR
                                }),
                        )
                        .fill(if fwd_sel {
                            FORWARD_COLOR
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .min_size(egui::vec2(120.0, 28.0)),
                    )
                    .clicked()
                {
                    state.mode = TrackMode::Forward;
                }
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("←  向后")
                                .size(13.0)
                                .color(if bwd_sel {
                                    egui::Color32::BLACK
                                } else {
                                    BACKWARD_COLOR
                                }),
                        )
                        .fill(if bwd_sel {
                            BACKWARD_COLOR
                        } else {
                            egui::Color32::TRANSPARENT
                        })
                        .min_size(egui::vec2(120.0, 28.0)),
                    )
                    .clicked()
                {
                    state.mode = TrackMode::Backward;
                }
            });

            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("起点目标")
                    .size(11.0)
                    .color(egui::Color32::from_rgb(150, 150, 150)),
            );
            ui.add(
                egui::TextEdit::singleline(&mut state.source_text)
                    .hint_text("x0 / w12 / sp / mem:0x76ff376b90")
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(8.0);
            ui.label(
                egui::RichText::new("起始行号")
                    .size(11.0)
                    .color(egui::Color32::from_rgb(150, 150, 150)),
            );
            ui.add(
                egui::TextEdit::singleline(&mut state.start_line_text)
                    .hint_text("从 1 开始计数")
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(8.0);
            ui.collapsing("高级选项", |ui| {
                ui.horizontal(|ui| {
                    ui.label("结果上限:");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.scan_limit_text)
                            .desired_width(80.0),
                    )
                    .on_hover_text(
                        "最大结果条数(向前:连续空闲行数;向后:BFS 节点数)",
                    );
                });
                if state.mode == TrackMode::Backward {
                    ui.horizontal(|ui| {
                        ui.label("追踪深度:");
                        ui.add(
                            egui::TextEdit::singleline(&mut state.max_depth_text)
                                .desired_width(60.0),
                        )
                        .on_hover_text("反向追踪的最大依赖跳数(默认 64)");
                    });
                }
                if state.mode == TrackMode::Forward {
                    ui.horizontal(|ui| {
                        ui.label("向前加载窗口 (MB):");
                        ui.add(
                            egui::TextEdit::singleline(&mut state.forward_window_mb_text)
                                .desired_width(60.0),
                        )
                        .on_hover_text("向前模式下从起点往后加载的字节数");
                    });
                }
            });

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let can_run = !state.running && reader.is_some();
                let accent = mode_color(state.mode);
                if ui
                    .add_enabled(
                        can_run,
                        egui::Button::new(
                            egui::RichText::new("▶  运行")
                                .size(13.0)
                                .color(egui::Color32::BLACK)
                                .strong(),
                        )
                        .fill(accent)
                        .min_size(egui::vec2(90.0, 28.0)),
                    )
                    .clicked()
                {
                    if let Some(reader) = reader {
                        match state.start_job(reader.clone()) {
                            Ok(()) => {
                                state.show_dialog = false;
                            }
                            Err(e) => {
                                error = Some(e);
                            }
                        }
                    }
                }
                if ui
                    .add(
                        egui::Button::new(egui::RichText::new("关闭").size(13.0))
                            .min_size(egui::vec2(80.0, 28.0)),
                    )
                    .clicked()
                {
                    state.show_dialog = false;
                }
                if state.running
                    && ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("取消当前任务").size(13.0),
                            )
                            .min_size(egui::vec2(120.0, 28.0)),
                        )
                        .clicked()
                {
                    if let Some(c) = &state.cancel {
                        c.store(true, Ordering::Relaxed);
                    }
                    state.status_text = "正在取消...".to_string();
                }
            });
            if !state.status_text.is_empty() {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(&state.status_text)
                        .size(11.0)
                        .color(egui::Color32::from_rgb(200, 200, 120)),
                );
            }
        });
    state.show_dialog = state.show_dialog && open;
    if let Some(msg) = error {
        state.status_text = msg;
        state.show_dialog = true;
    }
    None
}

/// Floating results window. Returns Some(byte_offset) when the user
/// double-clicks a row — the caller should scroll the central panel to that
/// byte offset (translate via `LineIndexer::find_line_at_offset`).
pub fn render_panel(ctx: &egui::Context, state: &mut TaintState) -> Option<u64> {
    let has_error = state.status_text.starts_with("错误");
    if !state.show_panel {
        return None;
    }
    let mut clicked_offset: Option<u64> = None;
    let mut save_clicked = false;
    let mut close_clicked = false;

    // Update filter if needed.
    if state.filter_dirty {
        rebuild_filter(state);
        state.filter_dirty = false;
    }

    let mut body = |ui: &mut egui::Ui, state: &mut TaintState| {
        // Always-visible mini toolbar (dock switch + close + save when available),
        // so users can move / hide the panel even before any result exists.
        render_panel_mini_toolbar(
            ui,
            state.completed.is_some(),
            &mut state.dock_side,
            &mut save_clicked,
            &mut close_clicked,
        );
        ui.separator();

        // Running / error banner.
        if state.running {
            render_running_banner(ui, &state.status_text, state.cancel.as_ref());
            ui.add_space(4.0);
        } else if has_error {
            render_error_banner(ui, &state.status_text);
            ui.add_space(4.0);
        }

        let Some(completed) = state.completed.as_ref() else {
            ui.add_space(6.0);
            ui.label(
                egui::RichText::new("暂无污点追踪结果")
                    .size(12.0)
                    .color(egui::Color32::from_rgb(180, 180, 180))
                    .strong(),
            );
            ui.label(
                egui::RichText::new(
                    "在主视图右键某条指令,选“向前/向后追踪起点…”,或点菜单 工具 → 污点追踪…",
                )
                .size(11.0)
                .color(egui::Color32::from_rgb(150, 150, 150)),
            );
            return;
        };
        render_panel_header_summary(ui, completed);

        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("过滤")
                    .size(11.0)
                    .color(egui::Color32::from_rgb(150, 150, 150)),
            );
            let resp = ui.add(
                egui::TextEdit::singleline(&mut state.filter_text)
                    .hint_text("子串匹配,任意列(例: ldr / mem:0xac2 / x8)")
                    .desired_width(f32::INFINITY),
            );
            if resp.changed() {
                state.filter_dirty = true;
            }
        });
        let shown = state.filtered_indices.len();
        let total = state.completed.as_ref().map_or(0, |c| c.hits.len());
        ui.label(
            egui::RichText::new(format!(
                "显示 {} / {} 条 — 双击跳转到对应 trace 行",
                shown, total
            ))
            .size(11.0)
            .color(egui::Color32::from_rgb(160, 160, 160)),
        );
        ui.add_space(4.0);

        clicked_offset = render_hits_table(ui, state);
    };

    // Dock as a side panel / bottom panel. The central text area takes
    // whatever space is left — there is no overlap with the editor.
    // Each side keeps its own id so widths/heights are remembered per dock.
    //
    // 内层 `ScrollArea` **不是装饰**,它是面板宽度稳定的关键:
    //
    // egui 的 SidePanel 每帧会把 `inner_response.response.rect` 存回
    // PanelState(`egui-0.31/src/containers/panel.rs`),下一帧再读取。
    // 也就是说面板宽度 = 上一帧内容的 min_rect。如果内容 min_rect 随帧
    // 变化(污点运行时长状态消息、命中表格列宽…),面板宽度就会跟着
    // 抖动 —— 进而 CentralPanel rect 跳动,TextEdit 键盘事件路由会
    // 间歇失效(表现就是"搜索框按不进字")。
    //
    // ScrollArea 是 egui 里唯一一个"outer rect 由 allocation 决定而
    // 非 content 决定"的容器(`scroll_area.rs:553` 那行
    // `outer_size = available_outer.size().at_most(max_size)`),所以它
    // 天然截断 min_rect 的向上传播。
    //
    // `auto_shrink([false, false])` 防止 ScrollArea 在内容少时反向缩
    // 小,否则面板会在"内容多/少"之间来回抖。
    match state.dock_side {
        DockSide::Right => {
            egui::SidePanel::right("taint_panel_right")
                .resizable(true)
                .default_width(360.0)
                .min_width(240.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::horizontal()
                        .auto_shrink([false, false])
                        .show(ui, |ui| body(ui, state));
                });
        }
        DockSide::Left => {
            egui::SidePanel::left("taint_panel_left")
                .resizable(true)
                .default_width(360.0)
                .min_width(240.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::horizontal()
                        .auto_shrink([false, false])
                        .show(ui, |ui| body(ui, state));
                });
        }
        DockSide::Bottom => {
            egui::TopBottomPanel::bottom("taint_panel_bottom")
                .resizable(true)
                .default_height(180.0)
                .min_height(100.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .auto_shrink([false, false])
                        .show(ui, |ui| body(ui, state));
                });
        }
    }

    if save_clicked {
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name("taint_result.log")
            .save_file()
        {
            save_results_to_file(state, &path);
        }
    }
    if close_clicked {
        state.show_panel = false;
    }
    clicked_offset
}

// =========================================================================
// Panel rendering helpers
// =========================================================================

const FORWARD_COLOR: egui::Color32 = egui::Color32::from_rgb(90, 200, 140);
const BACKWARD_COLOR: egui::Color32 = egui::Color32::from_rgb(120, 170, 255);

fn mode_color(mode: TrackMode) -> egui::Color32 {
    match mode {
        TrackMode::Forward => FORWARD_COLOR,
        TrackMode::Backward => BACKWARD_COLOR,
    }
}

fn mode_label(mode: TrackMode) -> &'static str {
    match mode {
        TrackMode::Forward => "向前",
        TrackMode::Backward => "向后",
    }
}

fn render_chip(ui: &mut egui::Ui, text: &str, bg: egui::Color32, fg: egui::Color32) {
    egui::Frame::NONE
        .fill(bg)
        .corner_radius(egui::CornerRadius::same(4))
        .inner_margin(egui::Margin::symmetric(6, 2))
        .show(ui, |ui| {
            ui.add(egui::Label::new(
                egui::RichText::new(text)
                    .monospace()
                    .size(12.0)
                    .color(fg),
            ).selectable(false));
        });
}

/// Visible "🔄 running" banner painted at the top of the panel. Shows a
/// spinner + current status text + a Cancel button so the user always knows
/// a taint job is in flight, even when the previous result is still shown
/// below.
fn render_running_banner(
    ui: &mut egui::Ui,
    status: &str,
    cancel: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
) {
    egui::Frame::NONE
        .fill(egui::Color32::from_rgb(70, 55, 20))
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgb(255, 210, 100),
        ))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(
                    egui::RichText::new("污点分析进行中")
                        .size(12.0)
                        .strong()
                        .color(egui::Color32::from_rgb(255, 230, 150)),
                );
                if !status.is_empty() {
                    ui.label(
                        egui::RichText::new(status)
                            .size(11.0)
                            .color(egui::Color32::from_rgb(220, 220, 200)),
                    );
                }
                if let Some(c) = cancel {
                    if ui
                        .add(
                            egui::Button::new(
                                egui::RichText::new("取消")
                                    .size(11.0)
                                    .color(egui::Color32::BLACK),
                            )
                            .fill(egui::Color32::from_rgb(255, 210, 100))
                            .min_size(egui::vec2(60.0, 22.0)),
                        )
                        .clicked()
                    {
                        c.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            });
        });
}

/// Red error banner — replaces the rest of the panel content until the next
/// job runs.
fn render_error_banner(ui: &mut egui::Ui, message: &str) {
    egui::Frame::NONE
        .fill(egui::Color32::from_rgb(70, 30, 30))
        .stroke(egui::Stroke::new(
            1.0,
            egui::Color32::from_rgb(240, 120, 120),
        ))
        .corner_radius(egui::CornerRadius::same(6))
        .inner_margin(egui::Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("⚠")
                        .size(16.0)
                        .color(egui::Color32::from_rgb(255, 180, 180)),
                );
                ui.label(
                    egui::RichText::new(message)
                        .size(12.0)
                        .color(egui::Color32::from_rgb(255, 200, 200))
                        .strong(),
                );
            });
        });
}

/// Always-visible toolbar: section label + dock switch + close + save.
/// Shown even when there are no results so the user can move / hide the panel
/// immediately after the app starts.
fn render_panel_mini_toolbar(
    ui: &mut egui::Ui,
    has_results: bool,
    dock_side: &mut DockSide,
    save_clicked: &mut bool,
    close_clicked: &mut bool,
) {
    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("🎯 污点追踪")
                .size(13.0)
                .strong()
                .color(egui::Color32::from_rgb(255, 210, 100)),
        );

        ui.separator();
        if ui
            .add_enabled(
                has_results,
                egui::Button::new(egui::RichText::new("💾 保存").size(12.0)),
            )
            .on_hover_text("保存结果到日志文件")
            .clicked()
        {
            *save_clicked = true;
        }

        ui.separator();
        ui.label(
            egui::RichText::new("停靠")
                .size(11.0)
                .color(egui::Color32::from_rgb(150, 150, 150)),
        );
        let mut dock_btn = |ui: &mut egui::Ui, label: &str, side: DockSide, tip: &str| {
            let selected = *dock_side == side;
            let btn = egui::Button::new(
                egui::RichText::new(label)
                    .size(14.0)
                    .color(if selected {
                        egui::Color32::BLACK
                    } else {
                        egui::Color32::from_rgb(210, 210, 210)
                    }),
            )
            .fill(if selected {
                egui::Color32::from_rgb(255, 210, 100)
            } else {
                egui::Color32::TRANSPARENT
            })
            .min_size(egui::vec2(26.0, 22.0));
            if ui.add(btn).on_hover_text(tip).clicked() {
                *dock_side = side;
            }
        };
        dock_btn(ui, "⬅", DockSide::Left, "停靠到左侧");
        dock_btn(ui, "⬇", DockSide::Bottom, "停靠到底部");
        dock_btn(ui, "➡", DockSide::Right, "停靠到右侧");

        ui.separator();
        if ui
            .add(egui::Button::new(egui::RichText::new("✖ 关闭").size(12.0)))
            .on_hover_text("关闭面板(菜单可重新打开)")
            .clicked()
        {
            *close_clicked = true;
        }
    });
}

/// Title + source + stat chips — only drawn when we actually have results.
fn render_panel_header_summary(ui: &mut egui::Ui, completed: &TaintCompleted) {
    let accent = mode_color(completed.mode);

    egui::Frame::NONE
        .fill(ui.visuals().extreme_bg_color)
        .inner_margin(egui::Margin::symmetric(10, 10))
        .corner_radius(egui::CornerRadius::same(6))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 38.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 2.0, accent);
                ui.add_space(6.0);

                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("方向")
                                .size(11.0)
                                .color(egui::Color32::from_rgb(160, 160, 160))
                                .strong(),
                        );
                        ui.label(
                            egui::RichText::new(mode_label(completed.mode))
                                .size(14.0)
                                .color(accent)
                                .strong(),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("起点:")
                                .size(11.0)
                                .color(egui::Color32::from_rgb(140, 140, 140)),
                        );
                        render_chip(
                            ui,
                            &completed.source_label,
                            accent.linear_multiply(0.25),
                            accent,
                        );
                    });
                });
            });
        });

    ui.add_space(6.0);

    ui.horizontal(|ui| {
        render_chip(
            ui,
            &format!("命中 {} 条", completed.hits.len()),
            egui::Color32::from_rgb(40, 60, 40),
            egui::Color32::from_rgb(180, 240, 180),
        );
        render_chip(
            ui,
            &format!("已解析 {} 条", completed.instructions_parsed),
            egui::Color32::from_rgb(40, 50, 60),
            egui::Color32::from_rgb(180, 210, 240),
        );
        let stop = stop_reason_label(completed.stop_reason);
        let (bg, fg) = match completed.stop_reason {
            StopReason::AllTaintCleared => (
                egui::Color32::from_rgb(60, 40, 40),
                egui::Color32::from_rgb(240, 180, 180),
            ),
            StopReason::ScanLimitReached => (
                egui::Color32::from_rgb(60, 55, 30),
                egui::Color32::from_rgb(240, 220, 150),
            ),
            StopReason::EndOfTrace => (
                egui::Color32::from_rgb(50, 50, 50),
                egui::Color32::from_rgb(200, 200, 200),
            ),
            StopReason::Cancelled => (
                egui::Color32::from_rgb(60, 40, 60),
                egui::Color32::from_rgb(220, 180, 220),
            ),
        };
        render_chip(ui, stop, bg, fg);
    });

    ui.add_space(4.0);
}

fn rebuild_filter(state: &mut TaintState) {
    if let Some(completed) = &state.completed {
        let q = state.filter_text.trim().to_lowercase();
        if q.is_empty() {
            state.filtered_indices = (0..completed.hits.len()).collect();
            return;
        }
        state.filtered_indices = completed
            .hits
            .iter()
            .enumerate()
            .filter_map(|(i, h)| {
                fn contains_ci(haystack: &str, needle: &str) -> bool {
                    let n = needle.len();
                    if n == 0 { return true; }
                    if n > haystack.len() { return false; }
                    let nb = needle.as_bytes();
                    haystack.as_bytes().windows(n).any(|w| {
                        w.iter().zip(nb).all(|(a, b)| a.to_ascii_lowercase() == *b)
                    })
                }
                if contains_ci(&h.module_offset, &q)
                    || contains_ci(&h.addr, &q)
                    || contains_ci(&h.asm, &q)
                    || contains_ci(&h.raw_line, &q)
                    || contains_ci(&h.tainted_text, &q)
                    || h.line_number.to_string().contains(&q)
                {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();
    }
}

/// Table view — five columns like taint_gui.py (Line / Module!Offset / Addr /
/// ASM / Tainted). Double-click a row to jump. Returns the target row on jump.
fn render_hits_table(ui: &mut egui::Ui, state: &mut TaintState) -> Option<u64> {
    use egui_extras::{Column, TableBuilder};

    let mut jump_to: Option<u64> = None;
    let text_h = ui.text_style_height(&egui::TextStyle::Monospace);
    let row_h = text_h + 6.0;

    let total_rows = state.filtered_indices.len();
    let completed_ref = state.completed.as_ref()?;
    let hits_ptr: *const Vec<TaintHit> = &completed_ref.hits;
    // SAFETY: `state.completed` is held for the duration of this function and
    // not mutated from inside the closures below; we only need a shared borrow.
    let hits: &Vec<TaintHit> = unsafe { &*hits_ptr };
    let filtered_ptr: *const Vec<usize> = &state.filtered_indices;
    let filtered: &Vec<usize> = unsafe { &*filtered_ptr };

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        // Row-level click sense — cell labels themselves stay non-interactive
        // so they can never steal focus from TextEdits elsewhere (e.g. the
        // Ctrl+F search bar).
        .sense(egui::Sense::click())
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(70.0).at_least(50.0))
        .column(Column::initial(170.0).at_least(80.0))
        .column(Column::initial(130.0).at_least(80.0))
        .column(Column::initial(460.0).at_least(180.0))
        .column(Column::remainder().at_least(120.0))
        .header(22.0, |mut header| {
            let hfmt = |s: &str| {
                egui::RichText::new(s)
                    .size(12.0)
                    .strong()
                    .color(egui::Color32::from_rgb(210, 210, 210))
            };
            header.col(|ui| {
                ui.label(hfmt("行号"));
            });
            header.col(|ui| {
                ui.label(hfmt("模块!偏移"));
            });
            header.col(|ui| {
                ui.label(hfmt("地址"));
            });
            header.col(|ui| {
                ui.label(hfmt("汇编"));
            });
            header.col(|ui| {
                ui.label(hfmt("污点集"));
            });
        })
        .body(|body| {
            body.rows(row_h, total_rows, |mut row| {
                let row_i = row.index();
                let hit_idx = filtered[row_i];
                let hit = &hits[hit_idx];
                let is_sel = state.selected_hit == Some(hit_idx);
                row.set_selected(is_sel);

                let line_txt = egui::RichText::new(hit.line_number.to_string())
                    .monospace()
                    .size(12.0)
                    .color(egui::Color32::from_rgb(255, 210, 120));
                let module_txt = egui::RichText::new(&hit.module_offset)
                    .monospace()
                    .size(12.0)
                    .color(egui::Color32::from_rgb(180, 210, 240));
                let addr_txt = egui::RichText::new(&hit.addr)
                    .monospace()
                    .size(12.0)
                    .color(egui::Color32::from_rgb(160, 160, 160));
                let asm_job = format_asm_job(&hit.asm);
                let tainted_job = format_tainted_job(hit);

                row.col(|ui| {
                    ui.add(egui::Label::new(line_txt).selectable(false));
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(module_txt).selectable(false));
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(addr_txt).selectable(false));
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(asm_job).selectable(false).truncate());
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(tainted_job).selectable(false).truncate());
                });

                // One interact rect for the whole row — cells above have no
                // Sense, so the search bar (and any other TextEdit) keeps its
                // focus even when the panel is on screen.
                let row_resp = row.response().on_hover_text(&hit.raw_line);
                if row_resp.clicked() {
                    state.selected_hit = Some(hit_idx);
                    state.selected_offset = Some(hit.file_offset);
                }
                if row_resp.double_clicked() {
                    state.selected_hit = Some(hit_idx);
                    state.selected_offset = Some(hit.file_offset);
                    jump_to = Some(hit.file_offset);
                }
            });
        });

    jump_to
}

/// Colour the ASM column: mnemonic in orange, register tokens in blue, rest in
/// light gray. Kept compact because it gets drawn once per visible row.
fn format_asm_job(asm: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let mono = |size: f32, color: egui::Color32| egui::TextFormat {
        font_id: egui::FontId::monospace(size),
        color,
        ..Default::default()
    };
    let bright = egui::Color32::from_rgb(225, 225, 225);
    let mnem_color = egui::Color32::from_rgb(255, 180, 100);
    let reg_color = egui::Color32::from_rgb(150, 210, 255);
    let imm_color = egui::Color32::from_rgb(180, 230, 180);

    let trimmed = asm.trim_start();
    let pad_len = asm.len() - trimmed.len();
    if pad_len > 0 {
        job.append(&asm[..pad_len], 0.0, mono(12.0, bright));
    }
    let rest = trimmed;
    let mnem_end = rest
        .find(|c: char| c.is_whitespace())
        .unwrap_or(rest.len());
    job.append(&rest[..mnem_end], 0.0, mono(12.0, mnem_color));
    let operands = &rest[mnem_end..];
    let bytes = operands.as_bytes();
    let mut last = 0usize;
    let mut i = 0;
    while i < bytes.len() {
        if is_word_start(bytes, i) {
            let start = i;
            while i < bytes.len() && (bytes[i] as char).is_ascii_alphanumeric() {
                i += 1;
            }
            let tok = &operands[start..i];
            if parse_reg_name(tok.as_bytes()) != REG_INVALID {
                if start > last {
                    job.append(&operands[last..start], 0.0, mono(12.0, bright));
                }
                job.append(tok, 0.0, mono(12.0, reg_color));
                last = i;
            }
        } else if bytes[i] == b'#' {
            let start = i;
            i += 1;
            while i < bytes.len()
                && !(bytes[i] as char).is_whitespace()
                && bytes[i] != b','
                && bytes[i] != b']'
            {
                i += 1;
            }
            if start > last {
                job.append(&operands[last..start], 0.0, mono(12.0, bright));
            }
            job.append(&operands[start..i], 0.0, mono(12.0, imm_color));
            last = i;
        } else {
            i += 1;
        }
    }
    if last < operands.len() {
        job.append(&operands[last..], 0.0, mono(12.0, bright));
    }
    job
}

fn format_tainted_job(hit: &TaintHit) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let mono = |color: egui::Color32| egui::TextFormat {
        font_id: egui::FontId::monospace(12.0),
        color,
        ..Default::default()
    };
    if hit.tainted_regs.is_empty() && hit.tainted_mems.is_empty() {
        job.append(
            "∅",
            0.0,
            mono(egui::Color32::from_rgb(120, 120, 120)),
        );
        return job;
    }
    let mut first = true;
    for r in &hit.tainted_regs {
        if !first {
            job.append(", ", 0.0, mono(egui::Color32::from_rgb(120, 120, 120)));
        }
        let color = match r.as_str() {
            "fp" | "lr" | "sp" => egui::Color32::from_rgb(255, 210, 150),
            "nzcv" => egui::Color32::from_rgb(255, 170, 210),
            _ if r.starts_with('q') || r.starts_with('d') || r.starts_with('s') => {
                egui::Color32::from_rgb(170, 230, 170)
            }
            _ => egui::Color32::from_rgb(150, 210, 255),
        };
        job.append(r, 0.0, mono(color));
        first = false;
    }
    for m in &hit.tainted_mems {
        if !first {
            job.append(", ", 0.0, mono(egui::Color32::from_rgb(120, 120, 120)));
        }
        job.append(
            &format!("mem:0x{:x}", m),
            0.0,
            mono(egui::Color32::from_rgb(220, 180, 255)),
        );
        first = false;
    }
    job
}

fn is_word_start(bytes: &[u8], i: usize) -> bool {
    if i >= bytes.len() {
        return false;
    }
    let prev = if i > 0 { bytes[i - 1] } else { b' ' };
    if (prev as char).is_ascii_alphanumeric() {
        return false;
    }
    (bytes[i] as char).is_ascii_alphabetic()
}

fn save_results_to_file(state: &TaintState, path: &PathBuf) {
    if let Some(c) = &state.completed {
        if let Err(e) = std::fs::write(path, &c.formatted) {
            eprintln!("failed to save taint results: {}", e);
        }
    }
}
