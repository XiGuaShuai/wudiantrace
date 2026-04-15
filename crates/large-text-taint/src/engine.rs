//! Taint propagation engine — direct port of TaintEngine.{h,cpp}.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::parser::read_raw_line;
use crate::reg::{normalize, reg_name, RegId, REG_INVALID, REG_NZCV, REG_XZR};
use crate::trace::{InsnCategory, TraceLine};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrackMode {
    Forward,
    Backward,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StopReason {
    AllTaintCleared,
    EndOfTrace,
    ScanLimitReached,
    Cancelled,
}

#[derive(Copy, Clone, Debug)]
pub struct TaintSource {
    pub reg: RegId,
    pub mem_addr: u64,
    pub is_mem: bool,
}

impl TaintSource {
    pub fn from_reg(reg: RegId) -> Self {
        Self {
            reg,
            mem_addr: 0,
            is_mem: false,
        }
    }
    pub fn from_mem(addr: u64) -> Self {
        Self {
            reg: REG_INVALID,
            mem_addr: addr,
            is_mem: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ResultEntry {
    pub index: usize,
    pub reg_snapshot: [bool; 256],
    pub mem_snapshot: HashSet<u64>,
}

pub struct TaintEngine {
    mode: TrackMode,
    source: TaintSource,
    max_scan_distance: u32,
    cancel: Option<Arc<AtomicBool>>,

    reg_taint: [bool; 256],
    tainted_reg_count: i32,
    tainted_mem: HashSet<u64>,
    results: Vec<ResultEntry>,
    stop_reason: StopReason,
    /// 上次 `run()` 的起点在 parser.lines() 里的下标。`None` 表示从未
    /// 调用过 run()。`format_result` 里会根据这个字段在日志 header
    /// 打印 "Started from: line N (file offset 0xXXX)" —— 历史上
    /// 出现过"主视图行号和 parser 精确行号不一致"的混乱(稀疏索引
    /// 估算偏差),把精确起点行号/字节写进日志可一眼对账。
    start_index: Option<usize>,
}

impl Default for TaintEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TaintEngine {
    pub fn new() -> Self {
        Self {
            mode: TrackMode::Forward,
            source: TaintSource::from_reg(REG_INVALID),
            max_scan_distance: 50_000,
            cancel: None,
            reg_taint: [false; 256],
            tainted_reg_count: 0,
            tainted_mem: HashSet::new(),
            results: Vec::new(),
            stop_reason: StopReason::EndOfTrace,
            start_index: None,
        }
    }

    pub fn set_mode(&mut self, mode: TrackMode) {
        self.mode = mode;
    }
    pub fn set_max_scan_distance(&mut self, n: u32) {
        self.max_scan_distance = n;
    }
    pub fn set_cancel_token(&mut self, token: Arc<AtomicBool>) {
        self.cancel = Some(token);
    }
    pub fn stop_reason(&self) -> StopReason {
        self.stop_reason
    }
    pub fn results(&self) -> &[ResultEntry] {
        &self.results
    }
    pub fn into_results(self) -> Vec<ResultEntry> {
        self.results
    }
    pub fn mode(&self) -> TrackMode {
        self.mode
    }
    pub fn source(&self) -> TaintSource {
        self.source
    }

    pub fn set_source(&mut self, source: TaintSource) {
        self.source = source;
        self.reg_taint = [false; 256];
        self.tainted_reg_count = 0;
        self.tainted_mem.clear();
        self.results.clear();
        self.stop_reason = StopReason::EndOfTrace;

        if source.is_mem {
            self.tainted_mem.insert(source.mem_addr);
        } else {
            self.taint_reg(source.reg);
        }
    }

    #[inline]
    fn taint_reg(&mut self, id: RegId) {
        if id == REG_INVALID || id == REG_XZR {
            return;
        }
        let nid = normalize(id) as usize;
        if !self.reg_taint[nid] {
            self.reg_taint[nid] = true;
            self.tainted_reg_count += 1;
        }
    }

    #[inline]
    fn untaint_reg(&mut self, id: RegId) {
        if id == REG_INVALID || id == REG_XZR {
            return;
        }
        let nid = normalize(id) as usize;
        if self.reg_taint[nid] {
            self.reg_taint[nid] = false;
            self.tainted_reg_count -= 1;
        }
    }

    #[inline]
    fn is_reg_tainted(&self, id: RegId) -> bool {
        if id == REG_INVALID || id == REG_XZR {
            return false;
        }
        self.reg_taint[normalize(id) as usize]
    }

    fn any_src_tainted(&self, line: &TraceLine) -> bool {
        for i in 0..line.num_src as usize {
            if self.is_reg_tainted(line.src_regs[i]) {
                return true;
            }
        }
        if line.has_mem_read && self.tainted_mem.contains(&line.mem_read_addr) {
            return true;
        }
        if line.has_mem_read2 && self.tainted_mem.contains(&line.mem_read_addr2) {
            return true;
        }
        false
    }

    fn any_dst_tainted(&self, line: &TraceLine) -> bool {
        for i in 0..line.num_dst as usize {
            if self.is_reg_tainted(line.dst_regs[i]) {
                return true;
            }
        }
        if line.has_mem_write && self.tainted_mem.contains(&line.mem_write_addr) {
            return true;
        }
        if line.has_mem_write2 && self.tainted_mem.contains(&line.mem_write_addr2) {
            return true;
        }
        false
    }

    fn record(&mut self, index: usize) {
        self.results.push(ResultEntry {
            index,
            reg_snapshot: self.reg_taint,
            mem_snapshot: self.tainted_mem.clone(),
        });
    }

    fn propagate_forward(&mut self, line: &TraceLine) {
        use InsnCategory::*;
        match line.category {
            ImmLoad => {
                for i in 0..line.num_dst as usize {
                    self.untaint_reg(line.dst_regs[i]);
                }
            }
            PartialModify => {
                // movk preserves existing taint
            }
            DataMove | Arithmetic | Logic | ShiftExt | Bitfield | CondSelect => {
                let src_t = self.any_src_tainted(line);
                for i in 0..line.num_dst as usize {
                    if src_t {
                        self.taint_reg(line.dst_regs[i]);
                    } else {
                        self.untaint_reg(line.dst_regs[i]);
                    }
                }
                if line.sets_flags {
                    if src_t {
                        self.taint_reg(REG_NZCV);
                    } else {
                        self.untaint_reg(REG_NZCV);
                    }
                }
            }
            Load => {
                if line.has_mem_read2 && line.num_dst >= 2 {
                    let mem_t1 =
                        line.has_mem_read && self.tainted_mem.contains(&line.mem_read_addr);
                    let mem_t2 = self.tainted_mem.contains(&line.mem_read_addr2);
                    if mem_t1 {
                        self.taint_reg(line.dst_regs[0]);
                    } else {
                        self.untaint_reg(line.dst_regs[0]);
                    }
                    if mem_t2 {
                        self.taint_reg(line.dst_regs[1]);
                    } else {
                        self.untaint_reg(line.dst_regs[1]);
                    }
                } else {
                    let mem_t =
                        line.has_mem_read && self.tainted_mem.contains(&line.mem_read_addr);
                    for i in 0..line.num_dst as usize {
                        if mem_t {
                            self.taint_reg(line.dst_regs[i]);
                        } else {
                            self.untaint_reg(line.dst_regs[i]);
                        }
                    }
                }
            }
            Store => {
                if line.has_mem_write {
                    if line.has_mem_write2 && line.num_src >= 2 {
                        if self.is_reg_tainted(line.src_regs[0]) {
                            self.tainted_mem.insert(line.mem_write_addr);
                        } else {
                            self.tainted_mem.remove(&line.mem_write_addr);
                        }
                        if self.is_reg_tainted(line.src_regs[1]) {
                            self.tainted_mem.insert(line.mem_write_addr2);
                        } else {
                            self.tainted_mem.remove(&line.mem_write_addr2);
                        }
                    } else {
                        let src_t =
                            line.num_src > 0 && self.is_reg_tainted(line.src_regs[0]);
                        if src_t {
                            self.tainted_mem.insert(line.mem_write_addr);
                        } else {
                            self.tainted_mem.remove(&line.mem_write_addr);
                        }
                    }
                }
            }
            Compare => {
                let src_t = self.any_src_tainted(line);
                if src_t {
                    self.taint_reg(REG_NZCV);
                } else {
                    self.untaint_reg(REG_NZCV);
                }
            }
            Branch => {}
            Other => {
                let src_t = self.any_src_tainted(line);
                for i in 0..line.num_dst as usize {
                    if src_t {
                        self.taint_reg(line.dst_regs[i]);
                    } else {
                        self.untaint_reg(line.dst_regs[i]);
                    }
                }
                if line.has_mem_write {
                    if src_t {
                        self.tainted_mem.insert(line.mem_write_addr);
                    } else {
                        self.tainted_mem.remove(&line.mem_write_addr);
                    }
                }
            }
        }
    }

    fn propagate_backward(&mut self, line: &TraceLine) {
        use InsnCategory::*;
        match line.category {
            ImmLoad => {
                for i in 0..line.num_dst as usize {
                    if self.is_reg_tainted(line.dst_regs[i]) {
                        self.untaint_reg(line.dst_regs[i]);
                    }
                }
            }
            PartialModify => {}
            DataMove | Arithmetic | Logic | ShiftExt | Bitfield | CondSelect => {
                let dst_t = self.any_dst_tainted(line);
                let nzcv_t = line.sets_flags && self.is_reg_tainted(REG_NZCV);
                if dst_t || nzcv_t {
                    for i in 0..line.num_dst as usize {
                        self.untaint_reg(line.dst_regs[i]);
                    }
                    if nzcv_t {
                        self.untaint_reg(REG_NZCV);
                    }
                    for i in 0..line.num_src as usize {
                        self.taint_reg(line.src_regs[i]);
                    }
                }
            }
            Load => {
                if line.has_mem_read2 && line.num_dst >= 2 {
                    let t0 = self.is_reg_tainted(line.dst_regs[0]);
                    let t1 = self.is_reg_tainted(line.dst_regs[1]);
                    if t0 {
                        self.untaint_reg(line.dst_regs[0]);
                        if line.has_mem_read {
                            self.tainted_mem.insert(line.mem_read_addr);
                        }
                    }
                    if t1 {
                        self.untaint_reg(line.dst_regs[1]);
                        self.tainted_mem.insert(line.mem_read_addr2);
                    }
                } else {
                    let mut dst_t = false;
                    for i in 0..line.num_dst as usize {
                        if self.is_reg_tainted(line.dst_regs[i]) {
                            dst_t = true;
                            self.untaint_reg(line.dst_regs[i]);
                        }
                    }
                    if dst_t && line.has_mem_read {
                        self.tainted_mem.insert(line.mem_read_addr);
                    }
                }
            }
            Store => {
                if line.has_mem_write {
                    if line.has_mem_write2 && line.num_src >= 2 {
                        if self.tainted_mem.contains(&line.mem_write_addr) {
                            self.tainted_mem.remove(&line.mem_write_addr);
                            self.taint_reg(line.src_regs[0]);
                        }
                        if self.tainted_mem.contains(&line.mem_write_addr2) {
                            self.tainted_mem.remove(&line.mem_write_addr2);
                            self.taint_reg(line.src_regs[1]);
                        }
                    } else if self.tainted_mem.contains(&line.mem_write_addr) {
                        self.tainted_mem.remove(&line.mem_write_addr);
                        if line.num_src > 0 {
                            self.taint_reg(line.src_regs[0]);
                        }
                    }
                }
            }
            Compare => {
                if self.is_reg_tainted(REG_NZCV) {
                    self.untaint_reg(REG_NZCV);
                    for i in 0..line.num_src as usize {
                        self.taint_reg(line.src_regs[i]);
                    }
                }
            }
            Branch => {}
            Other => {
                let dst_t = self.any_dst_tainted(line);
                if dst_t {
                    for i in 0..line.num_dst as usize {
                        self.untaint_reg(line.dst_regs[i]);
                    }
                    for i in 0..line.num_src as usize {
                        self.taint_reg(line.src_regs[i]);
                    }
                    if line.has_mem_read {
                        self.tainted_mem.insert(line.mem_read_addr);
                    }
                }
            }
        }
    }

    pub fn run(&mut self, lines: &[TraceLine], start_index: usize) {
        self.results.clear();
        self.stop_reason = StopReason::EndOfTrace;
        self.start_index = None;
        if lines.is_empty() || start_index >= lines.len() {
            return;
        }
        self.start_index = Some(start_index);

        match self.mode {
            TrackMode::Forward => {
                self.record(start_index);
                let mut idle: u32 = 0;
                let mut i = start_index + 1;
                while i < lines.len() {
                    if self.is_cancelled() {
                        self.stop_reason = StopReason::Cancelled;
                        return;
                    }
                    let line = &lines[i].clone();
                    let mut involved = self.any_src_tainted(line);
                    if !involved
                        && line.has_mem_write
                        && self.tainted_mem.contains(&line.mem_write_addr)
                    {
                        involved = true;
                    }
                    if !involved
                        && line.has_mem_write2
                        && self.tainted_mem.contains(&line.mem_write_addr2)
                    {
                        involved = true;
                    }
                    self.propagate_forward(line);
                    if involved {
                        self.record(i);
                        idle = 0;
                    } else {
                        idle += 1;
                        if idle >= self.max_scan_distance {
                            self.stop_reason = StopReason::ScanLimitReached;
                            break;
                        }
                    }
                    if self.tainted_reg_count == 0 && self.tainted_mem.is_empty() {
                        self.stop_reason = StopReason::AllTaintCleared;
                        break;
                    }
                    i += 1;
                }
            }
            TrackMode::Backward => {
                let start_line = lines[start_index].clone();
                self.propagate_backward(&start_line);
                self.record(start_index);
                let mut idle: u32 = 0;
                let mut i = start_index as isize - 1;
                while i >= 0 {
                    if self.is_cancelled() {
                        self.stop_reason = StopReason::Cancelled;
                        // reverse to chronological
                        self.results.reverse();
                        return;
                    }
                    let line = &lines[i as usize].clone();
                    let mut involved = self.any_dst_tainted(line);
                    if !involved
                        && line.has_mem_write
                        && self.tainted_mem.contains(&line.mem_write_addr)
                    {
                        involved = true;
                    }
                    if !involved
                        && line.has_mem_write2
                        && self.tainted_mem.contains(&line.mem_write_addr2)
                    {
                        involved = true;
                    }
                    if !involved && line.sets_flags && self.is_reg_tainted(REG_NZCV) {
                        involved = true;
                    }
                    if involved {
                        self.propagate_backward(line);
                        self.record(i as usize);
                        idle = 0;
                    } else {
                        idle += 1;
                        if idle >= self.max_scan_distance {
                            self.stop_reason = StopReason::ScanLimitReached;
                            break;
                        }
                    }
                    if self.tainted_reg_count == 0 && self.tainted_mem.is_empty() {
                        self.stop_reason = StopReason::AllTaintCleared;
                        break;
                    }
                    i -= 1;
                }
                self.results.reverse();
            }
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .map(|c| c.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// Format the result the same way the C++ `write_result` does, returning a String.
    /// `lines` are the parsed trace lines and `bytes` is the underlying buffer
    /// they reference (used to read raw line text by file_offset/line_len).
    pub fn format_result(&self, lines: &[TraceLine], bytes: &[u8]) -> String {
        let mut out = String::new();
        let mode_s = match self.mode {
            TrackMode::Forward => "Forward",
            TrackMode::Backward => "Backward",
        };
        out.push_str(&format!("=== Taint {} Tracking ===\n", mode_s));
        out.push_str("Source: ");
        if self.source.is_mem {
            out.push_str(&format!("mem:0x{:x}", self.source.mem_addr));
        } else {
            out.push_str(reg_name(self.source.reg));
        }
        out.push('\n');
        // 记录 engine 实际起点的"trace 行号 + 文件字节 offset"。
        // 主视图在稀疏索引模式下显示的行号是估算的,与 parser 精确数
        // `\n` 得到的行号可能差几行;日志里把精确起点写明,就能一眼
        // 对上"我点的是 N 行"和"日志说从 M 行开始"。
        if let Some(idx) = self.start_index {
            if let Some(tl) = lines.get(idx) {
                out.push_str(&format!(
                    "Started from: line {} (file offset 0x{:x})\n",
                    tl.line_number, tl.file_offset
                ));
            }
        }
        out.push_str(&format!(
            "Total matched: {} instructions\n",
            self.results.len()
        ));
        let stop = match self.stop_reason {
            StopReason::AllTaintCleared => "all taint cleared".to_string(),
            StopReason::ScanLimitReached => format!(
                "scan limit reached ({} lines without propagation)",
                self.max_scan_distance
            ),
            StopReason::EndOfTrace => "end of trace".to_string(),
            StopReason::Cancelled => "cancelled".to_string(),
        };
        out.push_str(&format!("Stop reason: {}\n", stop));
        out.push_str("============================================================\n\n");

        for entry in &self.results {
            let tl = &lines[entry.index];
            let raw = read_raw_line(bytes, tl);
            let raw = raw.trim_end_matches(['\n', '\r']);
            out.push_str(&format!("[{}] {}\n", tl.line_number, raw));
            out.push_str("      tainted: {");
            let mut first = true;
            for i in 0..256u16 {
                if entry.reg_snapshot[i as usize] {
                    if !first {
                        out.push_str(", ");
                    }
                    out.push_str(reg_name(i as u8));
                    first = false;
                }
            }
            for m in &entry.mem_snapshot {
                if !first {
                    out.push_str(", ");
                }
                out.push_str(&format!("mem:0x{:x}", m));
                first = false;
            }
            out.push_str("}\n\n");
        }
        out
    }
}
