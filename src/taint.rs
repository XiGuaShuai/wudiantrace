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
    pub row: usize,           // 0-based line index for viewer scrolling
    pub line_number: u32,     // 1-based, original
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
    pub hit_rows: HashSet<usize>, // for O(1) row lookup during render
    pub selected_hit: Option<usize>,

    // Table filter
    pub filter_text: String,
    pub filter_dirty: bool,
    pub filtered_indices: Vec<usize>, // indices into completed.hits that match filter
}

impl Default for TaintState {
    fn default() -> Self {
        Self {
            show_dialog: false,
            show_panel: false,
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
            hit_rows: HashSet::new(),
            selected_hit: None,
            filter_text: String::new(),
            filter_dirty: false,
            filtered_indices: Vec::new(),
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
        self.hit_rows.clear();
        self.selected_hit = None;
        self.filter_text.clear();
        self.filter_dirty = false;
        self.filtered_indices.clear();
        self.status_text.clear();
    }

    /// Kick off a job without going through the dialog — called by the
    /// right-click quick-start menu. `mode` and `source` are taken directly;
    /// other options fall back to whatever is currently in the dialog state
    /// (scan_limit / forward_window_mb).
    pub fn quick_start(
        &mut self,
        reader: Arc<FileReader>,
        mode: TrackMode,
        source: TaintSource,
        start_line: u32,
    ) -> Result<(), String> {
        // sync dialog state so the UI reflects the job parameters
        self.mode = mode;
        self.source_text = format_source_label(&source);
        self.start_line_text = start_line.to_string();
        self.start_job_with(reader, mode, source, start_line)
    }

    /// Kick off a tracking job in a background thread using the dialog inputs.
    pub fn start_job(&mut self, reader: Arc<FileReader>) -> Result<(), String> {
        let source = parse_source(&self.source_text)
            .map_err(|e| format!("Source target invalid: {}", e))?;
        let start_line: u32 = self
            .start_line_text
            .trim()
            .parse()
            .map_err(|_| "Start line must be a positive integer".to_string())?;
        if start_line == 0 {
            return Err("Start line must be >= 1".to_string());
        }
        self.start_job_with(reader, self.mode, source, start_line)
    }

    fn start_job_with(
        &mut self,
        reader: Arc<FileReader>,
        mode: TrackMode,
        source: TaintSource,
        start_line: u32,
    ) -> Result<(), String> {
        let scan_limit: u32 = self
            .scan_limit_text
            .trim()
            .parse()
            .map_err(|_| "Scan limit must be a non-negative integer".to_string())?;
        let window_mb: u64 = self
            .forward_window_mb_text
            .trim()
            .parse()
            .map_err(|_| "Forward window must be an integer (MB)".to_string())?;

        if let Some(c) = self.cancel.take() {
            c.store(true, Ordering::Relaxed);
        }

        let cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx): (Sender<TaintMessage>, Receiver<TaintMessage>) = channel();

        self.cancel = Some(cancel.clone());
        self.rx = Some(rx);
        self.running = true;
        self.status_text = format!(
            "Running {} from line {} ({})",
            match mode {
                TrackMode::Forward => "forward",
                TrackMode::Backward => "backward",
            },
            start_line,
            format_source_label(&source),
        );
        self.completed = None;
        self.hit_rows.clear();
        self.selected_hit = None;

        let job = JobConfig {
            reader,
            mode,
            source,
            source_label: format_source_label(&source),
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
                        self.hit_rows = boxed.hits.iter().map(|h| h.row).collect();
                        self.status_text = format!(
                            "Done. {} hits, {} parsed, stop: {}",
                            boxed.hits.len(),
                            boxed.instructions_parsed,
                            stop_reason_label(boxed.stop_reason)
                        );
                        self.filtered_indices = (0..boxed.hits.len()).collect();
                        self.filter_dirty = false;
                        self.completed = Some(*boxed);
                        self.show_panel = true;
                        self.running = false;
                    }
                    TaintMessage::Error(e) => {
                        self.status_text = format!("Error: {}", e);
                        self.running = false;
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
        start_line,
        scan_limit,
        forward_window_bytes,
        cancel,
        tx,
    } = job;
    let bytes = reader.all_data();

    // For backward mode load just [0, start_line]; for forward, count newlines
    // up to start_line then load [0, that_offset + window].
    let mut parser = TraceParser::new();
    match mode {
        TrackMode::Backward => {
            let _ = tx.send(TaintMessage::Status(format!(
                "Parsing trace lines [1..{}] ...",
                start_line
            )));
            parser.load_range(bytes, start_line, u64::MAX);
        }
        TrackMode::Forward => {
            // find byte offset of start_line by counting newlines
            let _ = tx.send(TaintMessage::Status(
                "Locating start line in file...".to_string(),
            ));
            let start_off = match offset_of_line(bytes, start_line) {
                Some(o) => o,
                None => {
                    let _ = tx.send(TaintMessage::Error(format!(
                        "start line {} not found",
                        start_line
                    )));
                    return;
                }
            };
            let max_off = start_off.saturating_add(forward_window_bytes);
            let _ = tx.send(TaintMessage::Status(format!(
                "Parsing trace [0..byte {}] (~{} MB) ...",
                max_off,
                max_off / (1024 * 1024)
            )));
            parser.load_range(bytes, u32::MAX, max_off);
        }
    }
    if cancel.load(Ordering::Relaxed) {
        let _ = tx.send(TaintMessage::Error("cancelled".to_string()));
        return;
    }
    if parser.is_empty() {
        let _ = tx.send(TaintMessage::Error(
            "no instruction lines found in the parsed range".to_string(),
        ));
        return;
    }

    let start_index = match parser.find_by_line(start_line) {
        Some(i) => i,
        None => {
            let _ = tx.send(TaintMessage::Error(format!(
                "start line {} did not contain a parseable instruction",
                start_line
            )));
            return;
        }
    };

    let _ = tx.send(TaintMessage::Status(format!(
        "Tracking {} from index {} (line {}) ...",
        match mode {
            TrackMode::Forward => "forward",
            TrackMode::Backward => "backward",
        },
        start_index,
        parser.lines()[start_index].line_number
    )));

    let mut engine = TaintEngine::new();
    engine.set_mode(mode);
    engine.set_source(source);
    engine.set_max_scan_distance(scan_limit);
    engine.set_cancel_token(cancel.clone());
    engine.run(parser.lines(), start_index);

    if cancel.load(Ordering::Relaxed) && engine.stop_reason() == StopReason::Cancelled {
        let _ = tx.send(TaintMessage::Error("cancelled".to_string()));
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
    let mut mems: Vec<u64> = entry.mem_snapshot.iter().copied().collect();
    mems.sort_unstable();

    let (module_offset, addr, asm) = split_trace_line(&raw);
    let mut tainted_text = regs.join(", ");
    for m in &mems {
        if !tainted_text.is_empty() {
            tainted_text.push_str(", ");
        }
        tainted_text.push_str(&format!("mem:0x{:x}", m));
    }

    let _ = raw; // consumed into the split fields
    TaintHit {
        row: tl.line_number.saturating_sub(1) as usize,
        line_number: tl.line_number,
        module_offset,
        addr,
        asm,
        tainted_text,
        tainted_regs: regs,
        tainted_mems: mems,
    }
}

/// Split an xgtrace instruction line into (`libxxx.so!offset`, `0x<addr>`, `<asm>`).
/// On malformed input returns the whole string in the module field.
fn split_trace_line(raw: &str) -> (String, String, String) {
    // Expected shape: `<module>!<offset> 0x<addr>: "<asm>" ...`
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b' ' {
        i += 1;
    }
    let module_offset = raw[..i].to_string();
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    // addr: read until ':' or space
    let addr_start = i;
    while i < bytes.len() && bytes[i] != b':' && bytes[i] != b' ' {
        i += 1;
    }
    let addr = raw[addr_start..i].to_string();
    // quoted asm
    let asm = if let Some(qs) = raw[i..].find('"') {
        let qs = i + qs + 1;
        if let Some(qe) = raw[qs..].find('"') {
            let mut s = raw[qs..qs + qe].to_string();
            // normalise tabs/leading spaces so the column aligns nicely
            s = s.replace('\t', "  ");
            s.trim_start().to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    (module_offset, addr, asm)
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

fn parse_source(s: &str) -> Result<TaintSource, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("empty target".to_string());
    }
    if let Some(rest) = s.strip_prefix("mem:").or_else(|| s.strip_prefix("MEM:")) {
        let hex = rest
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X");
        let addr = u64::from_str_radix(hex, 16).map_err(|e| format!("bad mem addr: {}", e))?;
        return Ok(TaintSource::from_mem(addr));
    }
    let id = parse_reg_name(s.as_bytes());
    if id == REG_INVALID {
        return Err(format!("unknown register '{}'", s));
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
        StopReason::AllTaintCleared => "all taint cleared",
        StopReason::EndOfTrace => "end of trace",
        StopReason::ScanLimitReached => "scan limit reached",
        StopReason::Cancelled => "cancelled",
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
    egui::Window::new(egui::RichText::new("🎯 Taint Tracking").size(14.0))
        .open(&mut open)
        .resizable(false)
        .collapsible(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
        .default_width(380.0)
        .show(ctx, |ui| {
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new("Direction")
                    .size(11.0)
                    .color(egui::Color32::from_rgb(150, 150, 150)),
            );
            ui.horizontal(|ui| {
                let fwd_sel = state.mode == TrackMode::Forward;
                let bwd_sel = state.mode == TrackMode::Backward;
                if ui
                    .add(
                        egui::Button::new(
                            egui::RichText::new("→  Forward")
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
                            egui::RichText::new("←  Backward")
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
                egui::RichText::new("Source")
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
                egui::RichText::new("Start line")
                    .size(11.0)
                    .color(egui::Color32::from_rgb(150, 150, 150)),
            );
            ui.add(
                egui::TextEdit::singleline(&mut state.start_line_text)
                    .hint_text("1-based line number")
                    .desired_width(f32::INFINITY),
            );

            ui.add_space(8.0);
            ui.collapsing("Advanced options", |ui| {
                ui.horizontal(|ui| {
                    ui.label("Scan limit:");
                    ui.add(
                        egui::TextEdit::singleline(&mut state.scan_limit_text)
                            .desired_width(80.0),
                    )
                    .on_hover_text(
                        "Stop after N consecutive instructions without taint propagation.",
                    );
                });
                if state.mode == TrackMode::Forward {
                    ui.horizontal(|ui| {
                        ui.label("Forward window (MB):");
                        ui.add(
                            egui::TextEdit::singleline(&mut state.forward_window_mb_text)
                                .desired_width(60.0),
                        )
                        .on_hover_text("Bytes after start line to load for forward mode.");
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
                            egui::RichText::new("▶  Run")
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
                        egui::Button::new(egui::RichText::new("Close").size(13.0))
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
                                egui::RichText::new("Cancel running").size(13.0),
                            )
                            .min_size(egui::vec2(120.0, 28.0)),
                        )
                        .clicked()
                {
                    if let Some(c) = &state.cancel {
                        c.store(true, Ordering::Relaxed);
                    }
                    state.status_text = "Cancel requested...".to_string();
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

/// Right-side dock listing the most recent results. Returns Some(row) when the
/// user double-clicks a row — the caller should scroll the central panel to it.
pub fn render_panel(ctx: &egui::Context, state: &mut TaintState) -> Option<usize> {
    if !state.show_panel || state.completed.is_none() {
        return None;
    }
    let mut clicked_row = None;
    let mut save_clicked = false;
    let mut close_clicked = false;

    // Update filter if needed.
    if state.filter_dirty {
        rebuild_filter(state);
        state.filter_dirty = false;
    }

    egui::SidePanel::right("taint_panel")
        .default_width(900.0)
        .min_width(500.0)
        .resizable(true)
        .show(ctx, |ui| {
            let completed = state.completed.as_ref().unwrap();
            render_panel_header(
                ui,
                completed,
                &mut save_clicked,
                &mut close_clicked,
            );

            // Filter box (like taint_gui.py)
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    egui::RichText::new("filter")
                        .size(11.0)
                        .color(egui::Color32::from_rgb(150, 150, 150)),
                );
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut state.filter_text)
                        .hint_text("substring, any column (e.g. ldr / mem:0xac2 / x8)")
                        .desired_width(f32::INFINITY),
                );
                if resp.changed() {
                    state.filter_dirty = true;
                }
            });
            let shown = state.filtered_indices.len();
            let total = completed.hits.len();
            ui.label(
                egui::RichText::new(format!(
                    "showing {} of {} — double-click a row to jump",
                    shown, total
                ))
                .size(11.0)
                .color(egui::Color32::from_rgb(160, 160, 160)),
            );
            ui.add_space(4.0);

            clicked_row = render_hits_table(ui, state);
        });
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
    clicked_row
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
        TrackMode::Forward => "FORWARD",
        TrackMode::Backward => "BACKWARD",
    }
}

fn render_chip(ui: &mut egui::Ui, text: &str, bg: egui::Color32, fg: egui::Color32) {
    egui::Frame::none()
        .fill(bg)
        .rounding(egui::Rounding::same(4.0))
        .inner_margin(egui::Margin::symmetric(6.0, 2.0))
        .show(ui, |ui| {
            ui.add(egui::Label::new(
                egui::RichText::new(text)
                    .monospace()
                    .size(12.0)
                    .color(fg),
            ).selectable(false));
        });
}

fn render_panel_header(
    ui: &mut egui::Ui,
    completed: &TaintCompleted,
    save_clicked: &mut bool,
    close_clicked: &mut bool,
) {
    let accent = mode_color(completed.mode);

    // Title bar with colored accent stripe on the left
    egui::Frame::none()
        .fill(ui.visuals().extreme_bg_color)
        .inner_margin(egui::Margin::symmetric(10.0, 10.0))
        .rounding(egui::Rounding::same(6.0))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                // Accent bar
                let (rect, _) = ui.allocate_exact_size(egui::vec2(4.0, 38.0), egui::Sense::hover());
                ui.painter().rect_filled(rect, 2.0, accent);
                ui.add_space(6.0);

                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        ui.label(
                            egui::RichText::new("TAINT")
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
                            egui::RichText::new("source:")
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

    // Stat badges row
    ui.horizontal(|ui| {
        render_chip(
            ui,
            &format!("{} hits", completed.hits.len()),
            egui::Color32::from_rgb(40, 60, 40),
            egui::Color32::from_rgb(180, 240, 180),
        );
        render_chip(
            ui,
            &format!("{} parsed", completed.instructions_parsed),
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

    ui.add_space(6.0);

    // Toolbar
    ui.horizontal(|ui| {
        if ui
            .add(egui::Button::new(egui::RichText::new("💾 Save").size(12.0)))
            .on_hover_text("Save results to a log file")
            .clicked()
        {
            *save_clicked = true;
        }
        if ui
            .add(egui::Button::new(egui::RichText::new("✖ Close").size(12.0)))
            .on_hover_text("Close this panel (results are kept)")
            .clicked()
        {
            *close_clicked = true;
        }
    });
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
                if h.module_offset.to_lowercase().contains(&q)
                    || h.addr.to_lowercase().contains(&q)
                    || h.asm.to_lowercase().contains(&q)
                    || h.tainted_text.to_lowercase().contains(&q)
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
fn render_hits_table(ui: &mut egui::Ui, state: &mut TaintState) -> Option<usize> {
    use egui_extras::{Column, TableBuilder};

    let mut jump_to: Option<usize> = None;
    let text_h = ui.text_style_height(&egui::TextStyle::Monospace);
    let row_h = text_h + 6.0;

    let total_rows = state.filtered_indices.len();
    let hits_ptr: *const Vec<TaintHit> = &state.completed.as_ref().unwrap().hits;
    // SAFETY: `state.completed` is held for the duration of this function and
    // not mutated from inside the closures below; we only need a shared borrow.
    let hits: &Vec<TaintHit> = unsafe { &*hits_ptr };
    let filtered_ptr: *const Vec<usize> = &state.filtered_indices;
    let filtered: &Vec<usize> = unsafe { &*filtered_ptr };

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(70.0).at_least(50.0))
        .column(Column::initial(170.0).at_least(80.0))
        .column(Column::initial(130.0).at_least(80.0))
        .column(Column::initial(360.0).at_least(150.0))
        .column(Column::remainder().at_least(120.0))
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

                let mut any_resp: Option<egui::Response> = None;
                let mut add_cell_label = |ui: &mut egui::Ui, widget: egui::Label| {
                    let r = ui.add(widget);
                    any_resp = Some(match any_resp.take() {
                        Some(prev) => prev.union(r.clone()),
                        None => r,
                    });
                };

                row.col(|ui| {
                    add_cell_label(
                        ui,
                        egui::Label::new(line_txt).sense(egui::Sense::click()).selectable(false),
                    );
                });
                row.col(|ui| {
                    add_cell_label(
                        ui,
                        egui::Label::new(module_txt).sense(egui::Sense::click()).selectable(false),
                    );
                });
                row.col(|ui| {
                    add_cell_label(
                        ui,
                        egui::Label::new(addr_txt).sense(egui::Sense::click()).selectable(false),
                    );
                });
                row.col(|ui| {
                    add_cell_label(
                        ui,
                        egui::Label::new(asm_job)
                            .sense(egui::Sense::click())
                            .selectable(false)
                            .truncate(),
                    );
                });
                row.col(|ui| {
                    add_cell_label(
                        ui,
                        egui::Label::new(tainted_job)
                            .sense(egui::Sense::click())
                            .selectable(false)
                            .truncate(),
                    );
                });

                if let Some(resp) = any_resp {
                    if resp.clicked() {
                        state.selected_hit = Some(hit_idx);
                    }
                    if resp.double_clicked() {
                        state.selected_hit = Some(hit_idx);
                        jump_to = Some(hit.row);
                    }
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
