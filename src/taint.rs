//! Taint-tracking integration for the viewer.
//!
//! Holds the dialog/panel state, runs `TraceParser` + `TaintEngine` on the
//! currently loaded mmap in a background thread, and reports results back via
//! mpsc channels following the same pattern as `SearchEngine`.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;

use eframe::egui;
use egui_extras::{Column, TableBuilder};
use large_text_core::file_reader::FileReader;
use large_text_taint::engine::{
    MemRange, ResultEntry, StopReason, TaintEngine, TaintSource, TrackMode,
};
use large_text_taint::parser::{read_raw_line, TraceParser};
use large_text_taint::reg::{normalize, parse_reg_name, reg_name, REG_INVALID};
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
    pub asm: String, // contents of the double-quoted asm string (tabs normalised to spaces)
    pub tainted_text: String, // "x0, x8, mem:0x1234" for filtering + details
    pub tainted_regs: Vec<String>,
    pub tainted_mems: Vec<MemRange>,
    pub delta_text: String, // "+x0, -x8, +mem:0x1234" relative to previous hit
    pub delta_added_regs: Vec<String>,
    pub delta_removed_regs: Vec<String>,
    pub delta_added_mems: Vec<MemRange>,
    pub delta_removed_mems: Vec<MemRange>,
    pub note_text: String, // e.g. "libc.so!malloc(48)" for ExternalCall rows
}

// ---- Tree structures ----

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TaintTarget {
    Reg(u8),
    Mem(MemRange),
}

impl TaintTarget {
    fn label(&self) -> String {
        match self {
            TaintTarget::Reg(id) => reg_name(*id).to_string(),
            TaintTarget::Mem(range) => format_mem_range(*range),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TaintTreeNode {
    pub target: TaintTarget,
    pub insn_index: usize,
    pub line_number: u32,
    pub file_offset: u64,
    pub asm: String,
    pub raw_line: String,
    pub children: Vec<TaintTreeNode>,
}

struct TreeEdge {
    insn_index: usize,
    parent: TaintTarget,
    child: TaintTarget,
}

struct DisplayTraceLine {
    line_number: u32,
    file_offset: u64,
    raw_line: String,
    module_offset: String,
    addr: String,
    asm: String,
}

pub struct TaintCompleted {
    pub hits: Vec<TaintHit>,
    pub tree: Option<TaintTreeNode>,
    pub stop_reason: StopReason,
    pub mode: TrackMode,
    pub source_label: String,
    pub instructions_parsed: usize,
    pub formatted: String,
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
        let source = parse_source(&self.source_text).map_err(|e| format!("起点格式无效: {}", e))?;
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
            let _ = tx.send(TaintMessage::Status("定位起始行...".to_string()));
            match offset_of_line(bytes, start_line) {
                Some(o) => o,
                None => {
                    let _ = tx.send(TaintMessage::Error(format!("未找到起始行 {}", start_line)));
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
    engine.set_cancel_token(cancel.clone());
    match mode {
        TrackMode::Backward => {
            engine.run_backward_with_mem_search(parser.lines(), start_index, bytes);
        }
        TrackMode::Forward => {
            engine.run(parser.lines(), start_index);
        }
    }

    if cancel.load(Ordering::Relaxed) && engine.stop_reason() == StopReason::Cancelled {
        let _ = tx.send(TaintMessage::Error("已取消".to_string()));
        return;
    }

    let formatted = engine.format_result(parser.lines(), bytes);
    let stop_reason = engine.stop_reason();
    let lines = parser.lines();
    let hits = build_hits(engine.results(), lines, bytes);

    let tree = build_taint_tree(
        engine.results(),
        &source,
        mode,
        start_index,
        parser.lines(),
        bytes,
    );

    let completed = TaintCompleted {
        hits,
        tree,
        stop_reason,
        mode,
        source_label,
        instructions_parsed: parser.len(),
        formatted,
    };
    let _ = tx.send(TaintMessage::Done(Box::new(completed)));
}

// ---- Tree building ----

fn build_taint_tree(
    results: &[ResultEntry],
    source: &TaintSource,
    mode: TrackMode,
    start_index: usize,
    lines: &[TraceLine],
    bytes: &[u8],
) -> Option<TaintTreeNode> {
    if results.is_empty() {
        return None;
    }
    let mut edges = collect_edges(results, source, mode, lines);
    let root_target = if source.is_mem {
        TaintTarget::Mem(MemRange::single(source.mem_addr))
    } else {
        TaintTarget::Reg(normalize(source.reg))
    };
    Some(match mode {
        TrackMode::Backward => build_backward_subtree(
            &root_target,
            start_index,
            start_index,
            &mut edges,
            lines,
            bytes,
            0,
        ),
        TrackMode::Forward => build_subtree(&root_target, start_index, &mut edges, lines, bytes, 0),
    })
}

fn collect_edges(
    results: &[ResultEntry],
    source: &TaintSource,
    mode: TrackMode,
    lines: &[TraceLine],
) -> Vec<TreeEdge> {
    let mut edges = Vec::new();
    let mut prev_regs = [false; 256];
    let mut prev_mems: HashSet<MemRange> = HashSet::new();
    if source.is_mem {
        prev_mems.insert(MemRange::single(source.mem_addr));
    } else {
        prev_regs[normalize(source.reg) as usize] = true;
    }

    let entries: Vec<&ResultEntry> = match mode {
        TrackMode::Backward => results.iter().rev().collect(),
        TrackMode::Forward => results.iter().collect(),
    };

    for entry in entries {
        let cur_regs = &entry.reg_snapshot;
        let cur_mems: HashSet<MemRange> = entry.mem_snapshot.iter().copied().collect();

        let mut removed = Vec::new();
        let mut added = Vec::new();
        for r in 0..256u16 {
            let ri = r as usize;
            if prev_regs[ri] && !cur_regs[ri] {
                removed.push(TaintTarget::Reg(r as u8));
            }
            if !prev_regs[ri] && cur_regs[ri] {
                added.push(TaintTarget::Reg(r as u8));
            }
        }
        for &range in &prev_mems {
            if !cur_mems.contains(&range) {
                removed.push(TaintTarget::Mem(range));
            }
        }
        for &range in &cur_mems {
            if !prev_mems.contains(&range) {
                added.push(TaintTarget::Mem(range));
            }
        }

        match mode {
            TrackMode::Backward => {
                // Parents = removed targets (untainted by this insn)
                // PLUS dst regs that stayed tainted (re-tainted because
                // the reg is both dst and src, e.g. `add x1, x1, x2`).
                let mut parents = removed;
                let tl = &lines[entry.index];
                for d in 0..tl.num_dst as usize {
                    let r = normalize(tl.dst_regs[d]);
                    if prev_regs[r as usize] && cur_regs[r as usize] {
                        let t = TaintTarget::Reg(r);
                        if !parents.contains(&t) {
                            parents.push(t);
                        }
                    }
                }
                for p in &parents {
                    if added.is_empty() {
                        edges.push(TreeEdge {
                            insn_index: entry.index,
                            parent: p.clone(),
                            child: p.clone(),
                        });
                    } else {
                        for c in &added {
                            edges.push(TreeEdge {
                                insn_index: entry.index,
                                parent: p.clone(),
                                child: c.clone(),
                            });
                        }
                    }
                }
            }
            TrackMode::Forward => {
                if !added.is_empty() {
                    let tl = &lines[entry.index];
                    let mut parents = Vec::new();
                    for s in 0..tl.num_src as usize {
                        let r = normalize(tl.src_regs[s]);
                        if prev_regs[r as usize] {
                            let t = TaintTarget::Reg(r);
                            if !parents.contains(&t) {
                                parents.push(t);
                            }
                        }
                    }
                    if tl.has_mem_read {
                        let read = MemRange::new(tl.mem_read_addr, tl.mem_read_size);
                        if let Some(range) = prev_mems.iter().find(|range| range.overlaps(read)) {
                            parents.push(TaintTarget::Mem(*range));
                        }
                    }
                    if tl.has_mem_read2 {
                        let read = MemRange::new(tl.mem_read_addr2, tl.mem_read_size2);
                        if let Some(range) = prev_mems.iter().find(|range| range.overlaps(read)) {
                            parents.push(TaintTarget::Mem(*range));
                        }
                    }
                    for p in &parents {
                        for c in &added {
                            edges.push(TreeEdge {
                                insn_index: entry.index,
                                parent: p.clone(),
                                child: c.clone(),
                            });
                        }
                    }
                }
            }
        }

        prev_regs = *cur_regs;
        prev_mems = cur_mems;
    }
    edges
}

fn build_subtree(
    target: &TaintTarget,
    insn_index: usize,
    edges: &mut Vec<TreeEdge>,
    lines: &[TraceLine],
    bytes: &[u8],
    depth: usize,
) -> TaintTreeNode {
    let mut child_nodes = Vec::new();
    if depth < 200 {
        let mut child_edges = Vec::new();
        let mut i = 0;
        while i < edges.len() {
            if edges[i].parent == *target {
                child_edges.push(edges.remove(i));
            } else {
                i += 1;
            }
        }
        for ce in child_edges {
            child_nodes.push(build_subtree(
                &ce.child,
                ce.insn_index,
                edges,
                lines,
                bytes,
                depth + 1,
            ));
        }
    }

    let display = display_trace_line_for_index(insn_index, lines, bytes);

    TaintTreeNode {
        target: target.clone(),
        insn_index,
        line_number: display.line_number,
        file_offset: display.file_offset,
        asm: display.asm,
        raw_line: display.raw_line,
        children: child_nodes,
    }
}

fn build_backward_subtree(
    target: &TaintTarget,
    display_index: usize,
    search_upper_bound: usize,
    edges: &mut Vec<TreeEdge>,
    lines: &[TraceLine],
    bytes: &[u8],
    depth: usize,
) -> TaintTreeNode {
    let mut child_nodes = Vec::new();
    if depth < 200 {
        let mut latest_step: Option<usize> = None;
        for edge in edges.iter() {
            if edge.parent == *target && edge.insn_index <= search_upper_bound {
                latest_step =
                    Some(latest_step.map_or(edge.insn_index, |best| best.max(edge.insn_index)));
            }
        }

        if let Some(step_idx) = latest_step {
            let mut child_edges = Vec::new();
            let mut i = 0;
            while i < edges.len() {
                if edges[i].parent == *target && edges[i].insn_index == step_idx {
                    child_edges.push(edges.remove(i));
                } else {
                    i += 1;
                }
            }

            let has_self_child = child_edges.iter().any(|e| e.child == *target);
            let has_earlier_same_target = edges
                .iter()
                .any(|e| e.parent == *target && e.insn_index < step_idx);

            if has_earlier_same_target && !has_self_child {
                child_nodes.push(build_backward_subtree(
                    target,
                    step_idx,
                    step_idx.saturating_sub(1),
                    edges,
                    lines,
                    bytes,
                    depth + 1,
                ));
            }

            for ce in child_edges {
                child_nodes.push(build_backward_subtree(
                    &ce.child,
                    step_idx,
                    step_idx.saturating_sub(1),
                    edges,
                    lines,
                    bytes,
                    depth + 1,
                ));
            }
        }
    }

    let display = display_trace_line_for_index(display_index, lines, bytes);

    TaintTreeNode {
        target: target.clone(),
        insn_index: display_index,
        line_number: display.line_number,
        file_offset: display.file_offset,
        asm: display.asm,
        raw_line: display.raw_line,
        children: child_nodes,
    }
}

fn build_hits(results: &[ResultEntry], lines: &[TraceLine], bytes: &[u8]) -> Vec<TaintHit> {
    let mut out = Vec::with_capacity(results.len());
    let mut prev_regs = [false; 256];
    let mut prev_mems: HashSet<MemRange> = HashSet::new();

    for entry in results {
        let mut delta_added_regs = Vec::new();
        let mut delta_removed_regs = Vec::new();
        for i in 0..256u16 {
            let idx = i as usize;
            let was = prev_regs[idx];
            let now = entry.reg_snapshot[idx];
            if !was && now {
                delta_added_regs.push(reg_name(i as u8).to_string());
            } else if was && !now {
                delta_removed_regs.push(reg_name(i as u8).to_string());
            }
        }

        let current_mems: HashSet<MemRange> = entry.mem_snapshot.iter().copied().collect();
        let mut delta_added_mems: Vec<MemRange> =
            current_mems.difference(&prev_mems).copied().collect();
        let mut delta_removed_mems: Vec<MemRange> =
            prev_mems.difference(&current_mems).copied().collect();
        delta_added_mems.sort_unstable();
        delta_removed_mems.sort_unstable();

        out.push(build_hit(
            entry,
            lines,
            bytes,
            delta_added_regs,
            delta_removed_regs,
            delta_added_mems,
            delta_removed_mems,
        ));

        prev_regs = entry.reg_snapshot;
        prev_mems = current_mems;
    }

    out
}

fn build_hit(
    entry: &ResultEntry,
    lines: &[TraceLine],
    bytes: &[u8],
    delta_added_regs: Vec<String>,
    delta_removed_regs: Vec<String>,
    delta_added_mems: Vec<MemRange>,
    delta_removed_mems: Vec<MemRange>,
) -> TaintHit {
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

    let display = display_trace_line_for_index(entry.index, lines, bytes);

    // 污点集:ExternalCall 显示函数名,普通指令显示 tainted regs/mems
    let mut tainted_text = if is_ext {
        extract_external_call_name(&raw)
    } else {
        regs.join(", ")
    };
    if !is_ext {
        // 普通指令才把 mems 追加到 regs 后面
        for mem in format_mem_ranges(&mems) {
            if !tainted_text.is_empty() {
                tainted_text.push_str(", ");
            }
            tainted_text.push_str(&mem);
        }
    }

    let note_text = if is_ext {
        extract_external_call_name(&raw)
    } else {
        String::new()
    };

    let mut delta_parts = Vec::new();
    delta_parts.extend(delta_added_regs.iter().map(|reg| format!("+{}", reg)));
    delta_parts.extend(delta_removed_regs.iter().map(|reg| format!("-{}", reg)));
    delta_parts.extend(format_mem_delta('+', &delta_added_mems));
    delta_parts.extend(format_mem_delta('-', &delta_removed_mems));

    TaintHit {
        file_offset: display.file_offset,
        line_number: display.line_number,
        raw_line: display.raw_line,
        module_offset: display.module_offset,
        addr: display.addr,
        asm: display.asm,
        tainted_text,
        tainted_regs: regs,
        tainted_mems: mems,
        delta_text: delta_parts.join(", "),
        delta_added_regs,
        delta_removed_regs,
        delta_added_mems,
        delta_removed_mems,
        note_text,
    }
}

fn display_trace_line_for_index(
    index: usize,
    lines: &[TraceLine],
    bytes: &[u8],
) -> DisplayTraceLine {
    let Some(tl) = lines.get(index) else {
        return DisplayTraceLine {
            line_number: 0,
            file_offset: 0,
            raw_line: String::new(),
            module_offset: String::new(),
            addr: String::new(),
            asm: String::new(),
        };
    };

    let raw = read_raw_line(bytes, tl);
    let raw = raw.trim_end_matches(['\n', '\r']).to_string();
    let is_ext = tl.category == large_text_taint::trace::InsnCategory::ExternalCall;

    if is_ext && index > 0 {
        let prev_tl = &lines[index - 1];
        let prev_raw = read_raw_line(bytes, prev_tl);
        let prev_raw = prev_raw.trim_end_matches(['\n', '\r']).to_string();
        let (module_offset, addr, asm) = split_trace_line(&prev_raw);
        return DisplayTraceLine {
            line_number: prev_tl.line_number,
            file_offset: prev_tl.file_offset,
            raw_line: prev_raw,
            module_offset,
            addr,
            asm,
        };
    }

    if is_ext {
        return DisplayTraceLine {
            line_number: tl.line_number,
            file_offset: tl.file_offset,
            raw_line: raw.clone(),
            module_offset: "外部调用".to_string(),
            addr: String::new(),
            asm: extract_external_call_name(&raw),
        };
    }

    let (module_offset, addr, asm) = split_trace_line(&raw);
    DisplayTraceLine {
        line_number: tl.line_number,
        file_offset: tl.file_offset,
        raw_line: raw,
        module_offset,
        addr,
        asm,
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
pub fn collect_targets(tl: &TraceLine) -> Vec<TaintSource> {
    let mut out: Vec<TaintSource> = Vec::new();
    let mut seen_reg: [bool; 256] = [false; 256];
    let push_reg = |id: u8, out: &mut Vec<TaintSource>, seen: &mut [bool; 256]| {
        if id == REG_INVALID {
            return;
        }
        let n = large_text_taint::reg::normalize(id) as usize;
        if !seen[n] {
            seen[n] = true;
            out.push(TaintSource::from_reg(id));
        }
    };
    for i in 0..tl.num_dst as usize {
        push_reg(tl.dst_regs[i], &mut out, &mut seen_reg);
    }
    for i in 0..tl.num_src as usize {
        push_reg(tl.src_regs[i], &mut out, &mut seen_reg);
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

pub fn source_display(src: &TaintSource) -> String {
    format_source_label(src)
}

fn format_mem_ranges(ranges: &[MemRange]) -> Vec<String> {
    if ranges.is_empty() {
        return Vec::new();
    }
    let mut sorted = ranges.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut out = Vec::new();
    let mut current = sorted[0];
    for &range in sorted.iter().skip(1) {
        if current.touches_or_overlaps(range) {
            let end = current.end().max(range.end());
            current = MemRange::new(current.addr, (end - current.addr).min(u8::MAX as u64) as u8);
            continue;
        }
        out.push(format_mem_range(current));
        current = range;
    }
    out.push(format_mem_range(current));
    out
}

fn format_mem_range(range: MemRange) -> String {
    if range.size <= 1 {
        format!("mem:0x{:x}", range.addr)
    } else {
        format!("mem:0x{:x}..0x{:x}", range.addr, range.end() - 1)
    }
}

fn format_mem_delta(prefix: char, ranges: &[MemRange]) -> Vec<String> {
    format_mem_ranges(ranges)
        .into_iter()
        .map(|s| format!("{}{}", prefix, s))
        .collect()
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
                        egui::Button::new(egui::RichText::new("→  向前").size(13.0).color(
                            if fwd_sel {
                                egui::Color32::BLACK
                            } else {
                                FORWARD_COLOR
                            },
                        ))
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
                        egui::Button::new(egui::RichText::new("←  向后").size(13.0).color(
                            if bwd_sel {
                                egui::Color32::BLACK
                            } else {
                                BACKWARD_COLOR
                            },
                        ))
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
                    ui.label("扫描上限:");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.scan_limit_text).desired_width(80.0),
                    )
                    .on_hover_text("连续 N 条指令无污点传播则停止");
                });
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
                            egui::Button::new(egui::RichText::new("取消当前任务").size(13.0))
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
        ui.label(
            egui::RichText::new("双击节点跳转到对应 trace 行")
                .size(11.0)
                .color(egui::Color32::from_rgb(160, 160, 160)),
        );
        ui.add_space(4.0);

        ui.add_space(2.0);
        render_hits_toolbar(ui, state);
        ui.add_space(4.0);

        clicked_offset = render_hits_table(ui, state);

        if state
            .completed
            .as_ref()
            .and_then(|c| c.tree.as_ref())
            .is_some()
        {
            ui.add_space(8.0);
            egui::CollapsingHeader::new("污点路径图")
                .id_salt("taint_tree_section")
                .default_open(false)
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new(
                            "树图按污点目标压缩显示；逐条命中数量和跳转以表格为准。",
                        )
                        .size(11.0)
                        .color(egui::Color32::from_rgb(160, 160, 160)),
                    );
                    ui.add_space(4.0);
                    if let Some(offset) = render_taint_tree(ui, state) {
                        clicked_offset = Some(offset);
                    }
                });
        }
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
            ui.add(
                egui::Label::new(egui::RichText::new(text).monospace().size(12.0).color(fg))
                    .selectable(false),
            );
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
            let btn = egui::Button::new(egui::RichText::new(label).size(14.0).color(if selected {
                egui::Color32::BLACK
            } else {
                egui::Color32::from_rgb(210, 210, 210)
            }))
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

fn render_hits_toolbar(ui: &mut egui::Ui, state: &mut TaintState) {
    let total = state.completed.as_ref().map(|c| c.hits.len()).unwrap_or(0);
    let shown = state.filtered_indices.len();

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new("命中明细")
                .size(12.0)
                .strong()
                .color(egui::Color32::from_rgb(255, 210, 100)),
        );
        ui.separator();

        let count_text = if shown == total {
            format!("显示 {} 条", shown)
        } else {
            format!("显示 {}/{} 条", shown, total)
        };
        ui.label(
            egui::RichText::new(count_text)
                .size(11.0)
                .color(egui::Color32::from_rgb(180, 180, 180)),
        );

        ui.separator();
        ui.label(
            egui::RichText::new("过滤")
                .size(11.0)
                .color(egui::Color32::from_rgb(150, 150, 150)),
        );
        let resp = ui.add(
            egui::TextEdit::singleline(&mut state.filter_text)
                .hint_text("行号 / 模块 / 地址 / 汇编 / 污点")
                .desired_width(220.0),
        );
        if resp.changed() {
            state.filter_dirty = true;
        }
        if !state.filter_text.is_empty()
            && ui
                .add(egui::Button::new(egui::RichText::new("清空").size(11.0)))
                .clicked()
        {
            state.filter_text.clear();
            state.filter_dirty = true;
        }
    });

    ui.add_space(4.0);
    ui.label(
        egui::RichText::new("单击行高亮主视图，双击跳回原始 trace。")
            .size(11.0)
            .color(egui::Color32::from_rgb(160, 160, 160)),
    );
}

fn render_hits_table(ui: &mut egui::Ui, state: &mut TaintState) -> Option<u64> {
    let table_height = ui.available_height().clamp(140.0, 320.0);

    let (jump_to, next_selected_hit, next_selected_offset) = {
        let Some(completed) = state.completed.as_ref() else {
            return None;
        };
        let filtered_indices = &state.filtered_indices;
        let selected_hit = state.selected_hit;
        let selected_offset = state.selected_offset;

        if filtered_indices.is_empty() {
            egui::Frame::NONE
                .fill(ui.visuals().faint_bg_color)
                .corner_radius(egui::CornerRadius::same(6))
                .inner_margin(egui::Margin::symmetric(10, 8))
                .show(ui, |ui| {
                    ui.label(
                        egui::RichText::new("当前过滤条件没有匹配到任何命中。")
                            .size(11.0)
                            .color(egui::Color32::from_rgb(180, 180, 180)),
                    );
                });
            return None;
        }

        let text_h = ui.text_style_height(&egui::TextStyle::Monospace);
        let row_h = text_h + 6.0;
        let mut jump_to = None;
        let mut next_selected_hit = None;
        let mut next_selected_offset = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .sense(egui::Sense::click())
            .vscroll(true)
            .max_scroll_height(table_height)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::initial(58.0).at_least(44.0))
            .column(Column::initial(150.0).at_least(100.0))
            .column(Column::initial(124.0).at_least(90.0))
            .column(Column::initial(260.0).at_least(160.0))
            .column(Column::remainder().at_least(140.0))
            .header(22.0, |mut header| {
                let hfmt = |s: &str| {
                    egui::RichText::new(s)
                        .size(12.0)
                        .strong()
                        .color(egui::Color32::from_rgb(210, 210, 210))
                };
                header.col(|ui| {
                    ui.label(hfmt("Line"));
                });
                header.col(|ui| {
                    ui.label(hfmt("Module!Offset"));
                });
                header.col(|ui| {
                    ui.label(hfmt("Addr"));
                });
                header.col(|ui| {
                    ui.label(hfmt("ASM"));
                });
                header.col(|ui| {
                    ui.label(hfmt("Tainted"));
                });
            })
            .body(|body| {
                body.rows(row_h, filtered_indices.len(), |mut row| {
                    let filtered_idx = filtered_indices[row.index()];
                    let hit = &completed.hits[filtered_idx];
                    let is_selected = selected_hit == Some(filtered_idx)
                        || selected_offset == Some(hit.file_offset);
                    row.set_selected(is_selected);

                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(hit.line_number.to_string())
                                    .monospace()
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(255, 210, 120)),
                            )
                            .selectable(false),
                        );
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&hit.module_offset)
                                    .monospace()
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(180, 220, 255)),
                            )
                            .selectable(false)
                            .truncate(),
                        );
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&hit.addr)
                                    .monospace()
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(170, 200, 240)),
                            )
                            .selectable(false),
                        );
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&hit.asm)
                                    .monospace()
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(225, 225, 225)),
                            )
                            .selectable(false)
                            .truncate(),
                        );
                    });
                    row.col(|ui| {
                        ui.add(
                            egui::Label::new(
                                egui::RichText::new(&hit.tainted_text)
                                    .monospace()
                                    .size(12.0)
                                    .color(egui::Color32::from_rgb(190, 240, 190)),
                            )
                            .selectable(false)
                            .truncate(),
                        );
                    });

                    let row_resp = row.response().on_hover_text(&hit.raw_line);
                    if row_resp.clicked() {
                        next_selected_hit = Some(filtered_idx);
                        next_selected_offset = Some(hit.file_offset);
                    }
                    if row_resp.double_clicked() {
                        next_selected_hit = Some(filtered_idx);
                        next_selected_offset = Some(hit.file_offset);
                        jump_to = Some(hit.file_offset);
                    }
                });
            });

        (jump_to, next_selected_hit, next_selected_offset)
    };

    if let Some(hit_idx) = next_selected_hit {
        state.selected_hit = Some(hit_idx);
    }
    if let Some(offset) = next_selected_offset {
        state.selected_offset = Some(offset);
    }

    jump_to
}

// ---- Tree topology rendering ----

struct TreeGraphNodeLayout<'a> {
    node: &'a TaintTreeNode,
    rect: egui::Rect,
}

const TREE_GRAPH_MARGIN: f32 = 18.0;
const TREE_GRAPH_COL_GAP: f32 = 44.0;
const TREE_GRAPH_ROW_GAP: f32 = 20.0;
const TREE_NODE_PAD_X: f32 = 12.0;
const TREE_NODE_PAD_Y: f32 = 9.0;
const TREE_NODE_MIN_W: f32 = 144.0;
const TREE_NODE_MIN_H: f32 = 36.0;

fn render_taint_tree(ui: &mut egui::Ui, state: &mut TaintState) -> Option<u64> {
    let tree_ptr: *const TaintTreeNode = state.completed.as_ref()?.tree.as_ref()?;
    // SAFETY: `state.completed` is not mutated inside the render call;
    // only `state.selected_offset` is written.
    let tree: &TaintTreeNode = unsafe { &*tree_ptr };
    let mut jump_to: Option<u64> = None;
    egui::Frame::NONE
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(egui::CornerRadius::same(8))
        .inner_margin(egui::Margin::same(8))
        .show(ui, |ui| {
            egui::ScrollArea::both()
                .id_salt("taint_tree_graph_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    render_taint_graph(ui, tree, &mut state.selected_offset, &mut jump_to);
                });
        });
    jump_to
}

fn render_taint_graph(
    ui: &mut egui::Ui,
    tree: &TaintTreeNode,
    selected_offset: &mut Option<u64>,
    jump_to: &mut Option<u64>,
) {
    let mut level_heights = Vec::new();
    collect_tree_level_heights(ui, tree, 0, &mut level_heights);
    let level_y = tree_level_positions(&level_heights);
    let mut subtree_widths: HashMap<*const TaintTreeNode, f32> = HashMap::new();
    measure_tree_subtree_widths(ui, tree, &mut subtree_widths);

    let mut layouts = Vec::new();
    let mut root_left = TREE_GRAPH_MARGIN;
    let mut max_right = 0.0;
    let mut max_bottom = 0.0;
    layout_tree_graph(
        ui,
        tree,
        0,
        &mut root_left,
        &subtree_widths,
        &level_y,
        &mut layouts,
        &mut max_right,
        &mut max_bottom,
    );

    let desired = egui::vec2(
        (max_right + TREE_GRAPH_MARGIN).max(ui.available_width()),
        max_bottom + TREE_GRAPH_MARGIN,
    );
    let (graph_rect, _) = ui.allocate_exact_size(desired, egui::Sense::hover());
    let offset = graph_rect.min.to_vec2();
    let painter = ui.painter_at(graph_rect);

    let mut rects: HashMap<*const TaintTreeNode, egui::Rect> =
        HashMap::with_capacity(layouts.len());
    for layout in &layouts {
        rects.insert(layout.node as *const _, layout.rect.translate(offset));
    }

    paint_tree_graph_edges(
        &painter,
        tree,
        &rects,
        egui::Stroke::new(1.4, egui::Color32::from_rgb(88, 88, 96)),
    );

    for layout in &layouts {
        let rect = match rects.get(&(layout.node as *const _)) {
            Some(rect) => *rect,
            None => continue,
        };
        let target_label = layout.node.target.label();
        let id = ui.id().with((
            "taint_tree_graph_node",
            layout.node.insn_index,
            layout.node.file_offset,
            &target_label,
        ));
        let response = ui
            .interact(rect, id, egui::Sense::click())
            .on_hover_text(&layout.node.raw_line);
        if response.clicked() {
            *selected_offset = Some(layout.node.file_offset);
        }
        if response.double_clicked() {
            *selected_offset = Some(layout.node.file_offset);
            *jump_to = Some(layout.node.file_offset);
        }
        paint_tree_graph_node(
            ui,
            &painter,
            layout.node,
            rect,
            response.hovered(),
            *selected_offset == Some(layout.node.file_offset),
        );
    }
}

fn collect_tree_level_heights(
    ui: &egui::Ui,
    node: &TaintTreeNode,
    depth: usize,
    heights: &mut Vec<f32>,
) {
    let size = tree_node_size(ui, node);
    if heights.len() <= depth {
        heights.resize(depth + 1, 0.0);
    }
    heights[depth] = heights[depth].max(size.y);
    for child in &node.children {
        collect_tree_level_heights(ui, child, depth + 1, heights);
    }
}

fn tree_level_positions(heights: &[f32]) -> Vec<f32> {
    let mut out = Vec::with_capacity(heights.len());
    let mut y = TREE_GRAPH_MARGIN;
    for height in heights {
        out.push(y);
        y += *height + TREE_GRAPH_ROW_GAP;
    }
    out
}

fn measure_tree_subtree_widths(
    ui: &egui::Ui,
    node: &TaintTreeNode,
    widths: &mut HashMap<*const TaintTreeNode, f32>,
) -> f32 {
    let own_width = tree_node_size(ui, node).x;
    let children_total = if node.children.is_empty() {
        0.0
    } else {
        let mut total = 0.0;
        for (i, child) in node.children.iter().enumerate() {
            if i > 0 {
                total += TREE_GRAPH_COL_GAP;
            }
            total += measure_tree_subtree_widths(ui, child, widths);
        }
        total
    };
    let subtree_width = own_width.max(children_total);
    widths.insert(node as *const _, subtree_width);
    subtree_width
}

fn layout_tree_graph<'a>(
    ui: &egui::Ui,
    node: &'a TaintTreeNode,
    depth: usize,
    left: &mut f32,
    subtree_widths: &HashMap<*const TaintTreeNode, f32>,
    level_y: &[f32],
    out: &mut Vec<TreeGraphNodeLayout<'a>>,
    max_right: &mut f32,
    max_bottom: &mut f32,
) -> egui::Rect {
    let size = tree_node_size(ui, node);
    let subtree_width = subtree_widths
        .get(&(node as *const _))
        .copied()
        .unwrap_or(size.x);
    let rect = egui::Rect::from_min_size(
        egui::pos2(*left + (subtree_width - size.x) * 0.5, level_y[depth]),
        size,
    );
    *max_right = (*max_right).max(rect.right());
    *max_bottom = (*max_bottom).max(rect.bottom());
    out.push(TreeGraphNodeLayout { node, rect });

    if !node.children.is_empty() {
        let children_total: f32 = node
            .children
            .iter()
            .enumerate()
            .map(|(i, child)| {
                let gap = if i == 0 { 0.0 } else { TREE_GRAPH_COL_GAP };
                gap + subtree_widths
                    .get(&(child as *const _))
                    .copied()
                    .unwrap_or(0.0)
            })
            .sum();
        let mut child_left = *left + (subtree_width - children_total) * 0.5;
        for child in &node.children {
            let child_width = subtree_widths
                .get(&(child as *const _))
                .copied()
                .unwrap_or_else(|| tree_node_size(ui, child).x);
            layout_tree_graph(
                ui,
                child,
                depth + 1,
                &mut child_left,
                subtree_widths,
                level_y,
                out,
                max_right,
                max_bottom,
            );
            child_left += child_width + TREE_GRAPH_COL_GAP;
        }
    }
    rect
}

fn paint_tree_graph_edges(
    painter: &egui::Painter,
    node: &TaintTreeNode,
    rects: &HashMap<*const TaintTreeNode, egui::Rect>,
    stroke: egui::Stroke,
) {
    let Some(parent_rect) = rects.get(&(node as *const _)).copied() else {
        return;
    };
    let start = egui::pos2(parent_rect.center().x, parent_rect.bottom());
    for child in &node.children {
        if let Some(child_rect) = rects.get(&(child as *const _)).copied() {
            let end = egui::pos2(child_rect.center().x, child_rect.top());
            let bend_y = start.y + ((end.y - start.y) * 0.5).max(18.0);
            painter.line_segment([start, egui::pos2(start.x, bend_y)], stroke);
            painter.line_segment(
                [egui::pos2(start.x, bend_y), egui::pos2(end.x, bend_y)],
                stroke,
            );
            painter.line_segment([egui::pos2(end.x, bend_y), end], stroke);
        }
        paint_tree_graph_edges(painter, child, rects, stroke);
    }
}

fn paint_tree_graph_node(
    ui: &egui::Ui,
    painter: &egui::Painter,
    node: &TaintTreeNode,
    rect: egui::Rect,
    hovered: bool,
    selected: bool,
) {
    let accent = tree_target_color(&node.target);
    let fill = if selected {
        accent.linear_multiply(0.22)
    } else if hovered {
        ui.visuals().widgets.hovered.bg_fill
    } else {
        ui.visuals().extreme_bg_color
    };
    let stroke = if selected {
        egui::Stroke::new(2.0, accent)
    } else if hovered {
        egui::Stroke::new(1.6, accent.linear_multiply(0.8))
    } else {
        egui::Stroke::new(1.0, egui::Color32::from_rgb(70, 70, 78))
    };

    painter.rect_filled(rect, egui::CornerRadius::same(8), fill);
    painter.rect_stroke(
        rect,
        egui::CornerRadius::same(8),
        stroke,
        egui::StrokeKind::Outside,
    );

    let strip = egui::Rect::from_min_max(rect.min, egui::pos2(rect.min.x + 4.0, rect.max.y));
    painter.rect_filled(strip, egui::CornerRadius::same(8), accent);

    let galley = ui.fonts(|f| f.layout_job(tree_node_job(node)));
    painter.galley(
        rect.min + egui::vec2(TREE_NODE_PAD_X, TREE_NODE_PAD_Y),
        galley,
        egui::Color32::WHITE,
    );
}

fn tree_target_color(target: &TaintTarget) -> egui::Color32 {
    match target {
        TaintTarget::Reg(_) => egui::Color32::from_rgb(150, 210, 255),
        TaintTarget::Mem(_) => egui::Color32::from_rgb(220, 180, 255),
    }
}

fn tree_node_size(ui: &egui::Ui, node: &TaintTreeNode) -> egui::Vec2 {
    let galley = ui.fonts(|f| f.layout_job(tree_node_job(node)));
    egui::vec2(
        (galley.size().x + TREE_NODE_PAD_X * 2.0).max(TREE_NODE_MIN_W),
        (galley.size().y + TREE_NODE_PAD_Y * 2.0).max(TREE_NODE_MIN_H),
    )
}

fn tree_node_job(node: &TaintTreeNode) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let mono = |size: f32, color: egui::Color32| egui::TextFormat {
        font_id: egui::FontId::monospace(size),
        color,
        ..Default::default()
    };
    let target_color = match &node.target {
        TaintTarget::Reg(_) => egui::Color32::from_rgb(150, 210, 255),
        TaintTarget::Mem(_) => egui::Color32::from_rgb(220, 180, 255),
    };
    job.append(&node.target.label(), 0.0, mono(12.0, target_color));
    job.append(
        &format!("  L{}", node.line_number),
        0.0,
        mono(11.0, egui::Color32::from_rgb(255, 210, 120)),
    );
    if !node.asm.is_empty() {
        job.append(
            &format!("  {}", node.asm),
            0.0,
            mono(11.0, egui::Color32::from_rgb(180, 180, 180)),
        );
    }
    job
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
                    if n == 0 {
                        return true;
                    }
                    if n > haystack.len() {
                        return false;
                    }
                    let nb = needle.as_bytes();
                    haystack
                        .as_bytes()
                        .windows(n)
                        .any(|w| w.iter().zip(nb).all(|(a, b)| a.to_ascii_lowercase() == *b))
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

fn save_results_to_file(state: &TaintState, path: &PathBuf) {
    if let Some(c) = &state.completed {
        if let Err(e) = std::fs::write(path, &c.formatted) {
            eprintln!("failed to save taint results: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use large_text_taint::engine::{TaintEngine, TaintSource, TrackMode};
    use large_text_taint::parser::TraceParser;

    const TREE_FIXTURE: &str = "\
libtiny.so!1000 0x7000: \"\tldr\tx1, [x19, #0x10]\" X19=0x1000 => X1=0x1234
MEM R 0x1010 [8 bytes]: 34 12 00 00 00 00 00 00  4.......
libtiny.so!1004 0x7004: \"\tadd\tx8, x1, x2\" X1=0x1234, X2=0x1 => X8=0x1235
libtiny.so!1008 0x7008: \"\tadd\tx8, x8, x10\" X8=0x1235, X10=0x10 => X8=0x1245
libtiny.so!100c 0x700c: \"\tstr\tx8, [x19, #0x8]\" X8=0x1245, X19=0x1000
MEM W 0x1008 [8 bytes]: 45 12 00 00 00 00 00 00  E.......
";

    const EXTERNAL_CALL_FIXTURE: &str = "\
libtiny.so!2000 0x8000: \"\tblr\tx17\" X17=0x9000
-> libc.so!strlen(16) ret: 0x10
libtiny.so!2004 0x8004: \"\tmov\tx11, x10\" X10=0x10 => X11=0x10
";

    fn child<'a>(node: &'a TaintTreeNode, target: &TaintTarget) -> &'a TaintTreeNode {
        node.children
            .iter()
            .find(|child| child.target == *target)
            .expect("expected child target to exist")
    }

    #[test]
    fn backward_tree_keeps_same_register_at_distinct_steps() {
        let mut parser = TraceParser::new();
        parser.load_from_bytes(TREE_FIXTURE.as_bytes());
        let lines = parser.lines();
        let start_index = lines
            .iter()
            .position(|tl| tl.has_mem_write && tl.mem_write_addr == 0x1008)
            .expect("store line should exist");

        let mut engine = TaintEngine::new();
        engine.set_mode(TrackMode::Backward);
        engine.set_source(TaintSource::from_mem(0x1008));
        engine.run(lines, start_index);

        let tree = build_taint_tree(
            engine.results(),
            &TaintSource::from_mem(0x1008),
            TrackMode::Backward,
            start_index,
            lines,
            TREE_FIXTURE.as_bytes(),
        )
        .expect("tree should be built");

        let x8_after_store = child(&tree, &TaintTarget::Reg(8));
        assert_eq!(x8_after_store.line_number, 5);

        let x8_continuation = child(x8_after_store, &TaintTarget::Reg(8));
        let x10_branch = child(x8_after_store, &TaintTarget::Reg(10));
        assert_eq!(x8_continuation.line_number, 4);
        assert_eq!(x10_branch.line_number, 4);

        let x1_branch = child(x8_continuation, &TaintTarget::Reg(1));
        let x2_branch = child(x8_continuation, &TaintTarget::Reg(2));
        assert_eq!(x1_branch.line_number, 3);
        assert_eq!(x2_branch.line_number, 3);

        let mem_source = child(x1_branch, &TaintTarget::Mem(MemRange::new(0x1010, 8)));
        assert_eq!(mem_source.line_number, 1);
    }

    #[test]
    fn backward_tree_keeps_external_call_terminal_step_visible() {
        let mut parser = TraceParser::new();
        parser.load_from_bytes(EXTERNAL_CALL_FIXTURE.as_bytes());
        let lines = parser.lines();
        let start_index = lines
            .iter()
            .position(|tl| tl.line_number == 3)
            .expect("mov line should exist");

        let mut engine = TaintEngine::new();
        engine.set_mode(TrackMode::Backward);
        engine.set_source(TaintSource::from_reg(11));
        engine.run(lines, start_index);

        let tree = build_taint_tree(
            engine.results(),
            &TaintSource::from_reg(11),
            TrackMode::Backward,
            start_index,
            lines,
            EXTERNAL_CALL_FIXTURE.as_bytes(),
        )
        .expect("tree should be built");

        let x10_from_mov = child(&tree, &TaintTarget::Reg(10));
        assert_eq!(x10_from_mov.line_number, 3);

        let x10_terminal = child(x10_from_mov, &TaintTarget::Reg(10));
        assert_eq!(x10_terminal.line_number, 1);
        assert!(x10_terminal.raw_line.contains("blr\tx17"));
    }
}
