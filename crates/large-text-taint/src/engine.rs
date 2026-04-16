//! Taint propagation engine.
//!
//! Forward mode: linear taint-bitmap propagation (unchanged from original).
//! Backward mode: forward-scan builds def-use dependency graph, then BFS
//! traverses it from the target instruction to find all data sources.

use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::parser::read_raw_line;
use crate::reg::{normalize, reg_name, RegId, REG_INVALID, REG_NZCV, REG_XZR};
use crate::trace::{InsnCategory, TraceLine};

/// Sentinel: "this register/memory has no definition in the scanned range."
const NO_DEF: u32 = u32::MAX;

/// Default maximum dependency depth for backward BFS.
const DEFAULT_MAX_DEPTH: u32 = 64;

// ───────────────────────── public types ─────────────────────────

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
    /// When true (backward mode), BFS seeds from `reg_last_def[reg]`
    /// instead of from the full deps of the start instruction. Used for
    /// tracking address-source registers of Load instructions.
    pub skip_start_propagation: bool,
    /// Optional expected register value. Preserved for API compatibility.
    pub expected_val: Option<u64>,
}

impl TaintSource {
    pub fn from_reg(reg: RegId) -> Self {
        Self { reg, mem_addr: 0, is_mem: false, skip_start_propagation: false, expected_val: None }
    }
    pub fn from_reg_with_val(reg: RegId, val: u64) -> Self {
        Self { reg, mem_addr: 0, is_mem: false, skip_start_propagation: false, expected_val: Some(val) }
    }
    pub fn from_mem(addr: u64) -> Self {
        Self { reg: REG_INVALID, mem_addr: addr, is_mem: true, skip_start_propagation: false, expected_val: None }
    }
    pub fn from_reg_as_source(reg: RegId) -> Self {
        Self { reg, mem_addr: 0, is_mem: false, skip_start_propagation: true, expected_val: None }
    }
    pub fn from_reg_as_source_with_val(reg: RegId, val: u64) -> Self {
        Self { reg, mem_addr: 0, is_mem: false, skip_start_propagation: true, expected_val: Some(val) }
    }
}

#[derive(Clone, Debug)]
pub struct ResultEntry {
    pub index: usize,
    pub reg_snapshot: [bool; 256],
    pub mem_snapshot: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct ValueMismatch {
    pub index: usize,
    pub mem_addr: u64,
    pub expected_val: u64,
    pub actual_val: u64,
}

#[derive(Clone, Debug)]
pub struct RemainingTaint {
    pub regs: Vec<String>,
    pub mems: Vec<u64>,
}

// ───────────────────── dep-graph (backward) ─────────────────────

/// Forward-scan state used to build the per-instruction dependency graph.
struct DepGraphBuilder {
    reg_last_def: [u32; 256],
    mem_last_def: FxHashMap<u64, u32>,
}

impl DepGraphBuilder {
    fn new() -> Self {
        Self {
            reg_last_def: [NO_DEF; 256],
            mem_last_def: FxHashMap::default(),
        }
    }

    #[inline]
    fn reg_def(&self, reg: RegId) -> Option<u32> {
        if reg == REG_INVALID || reg == REG_XZR { return None; }
        let idx = self.reg_last_def[normalize(reg) as usize];
        if idx == NO_DEF { None } else { Some(idx) }
    }

    #[inline]
    fn set_reg_def(&mut self, reg: RegId, i: u32) {
        if reg == REG_INVALID || reg == REG_XZR { return; }
        self.reg_last_def[normalize(reg) as usize] = i;
    }

    /// Build the dependency graph for `lines[0..=end]`.
    ///
    /// Returns `(deps, reg_last_def_snapshot)` where the snapshot captures
    /// the register definition state *just before* instruction `end` updates
    /// its own definitions (for `skip_start_propagation` lookups).
    fn build(
        &mut self,
        lines: &[TraceLine],
        end: usize,
        cancel: &Option<Arc<AtomicBool>>,
    ) -> (Vec<SmallVec<[u32; 4]>>, [u32; 256]) {
        let n = end + 1;
        let mut deps: Vec<SmallVec<[u32; 4]>> = Vec::with_capacity(n);
        let mut snapshot = [NO_DEF; 256];

        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            if i & 0x1_FFFF == 0 {
                if let Some(c) = cancel {
                    if c.load(Ordering::Relaxed) {
                        deps.resize_with(n, SmallVec::new);
                        return (deps, snapshot);
                    }
                }
            }

            let line = &lines[i];
            let mut preds = SmallVec::<[u32; 4]>::new();

            // ── collect source dependencies ──

            let skip_src_deps = matches!(
                line.category,
                InsnCategory::ImmLoad | InsnCategory::ExternalCall
            );

            if !skip_src_deps {
                // Register sources
                for j in 0..line.num_src as usize {
                    if let Some(def) = self.reg_def(line.src_regs[j]) {
                        push_unique(&mut preds, def);
                    }
                }

                // CondSelect: implicit NZCV dependency (control flow).
                // We still add it because csel's output depends on which
                // branch was taken — but the taint-set reconstruction
                // handles it separately (see below).
                if line.category == InsnCategory::CondSelect {
                    if let Some(def) = self.reg_def(REG_NZCV) {
                        push_unique(&mut preds, def);
                    }
                }

                // PartialModify (movk): read-modify-write on dst.
                if line.category == InsnCategory::PartialModify {
                    for j in 0..line.num_dst as usize {
                        if let Some(def) = self.reg_def(line.dst_regs[j]) {
                            push_unique(&mut preds, def);
                        }
                    }
                }
            }

            // Memory read dependencies
            if line.has_mem_read {
                if let Some(&def) = self.mem_last_def.get(&line.mem_read_addr) {
                    push_unique(&mut preds, def);
                }
            }
            if line.has_mem_read2 {
                if let Some(&def) = self.mem_last_def.get(&line.mem_read_addr2) {
                    push_unique(&mut preds, def);
                }
            }

            deps.push(preds);

            // ── snapshot reg_last_def right before start updates ──
            if i == end {
                snapshot = self.reg_last_def;
            }

            // ── update definitions ──
            match line.category {
                InsnCategory::ExternalCall => {
                    for r in 0..=18u8 {
                        self.set_reg_def(r, i as u32);
                    }
                    self.reg_last_def[REG_NZCV as usize] = i as u32;
                }
                InsnCategory::Branch => {}
                _ => {
                    for j in 0..line.num_dst as usize {
                        self.set_reg_def(line.dst_regs[j], i as u32);
                    }
                    if line.sets_flags {
                        self.reg_last_def[REG_NZCV as usize] = i as u32;
                    }
                }
            }

            if line.has_mem_write {
                self.mem_last_def.insert(line.mem_write_addr, i as u32);
            }
            if line.has_mem_write2 {
                self.mem_last_def.insert(line.mem_write_addr2, i as u32);
            }
        }

        (deps, snapshot)
    }
}

/// Depth-limited BFS backward on the dependency graph.
fn bfs_backward(
    deps: &[SmallVec<[u32; 4]>],
    seeds: &[u32],
    max_depth: u32,
    max_nodes: usize,
    cancel: &Option<Arc<AtomicBool>>,
) -> (Vec<usize>, bool) {
    let n = deps.len();
    let mut visited = vec![false; n];
    let mut queue: VecDeque<(u32, u32)> = VecDeque::new();
    let mut count: usize = 0;
    let mut truncated = false;

    for &seed in seeds {
        let s = seed as usize;
        if s < n && !visited[s] {
            visited[s] = true;
            queue.push_back((seed, 0));
            count += 1;
        }
    }

    while let Some((idx, depth)) = queue.pop_front() {
        if let Some(c) = cancel {
            if c.load(Ordering::Relaxed) { break; }
        }
        if depth >= max_depth {
            truncated = true;
            continue;
        }
        for &pred in &deps[idx as usize] {
            let p = pred as usize;
            if p < n && !visited[p] {
                visited[p] = true;
                count += 1;
                if count >= max_nodes {
                    let mut result = Vec::with_capacity(count);
                    for (i, &v) in visited.iter().enumerate() {
                        if v { result.push(i); }
                    }
                    return (result, true);
                }
                queue.push_back((pred, depth + 1));
            }
        }
    }

    let mut result = Vec::with_capacity(count);
    for (i, &v) in visited.iter().enumerate() {
        if v { result.push(i); }
    }
    (result, truncated)
}

#[inline]
fn push_unique(v: &mut SmallVec<[u32; 4]>, val: u32) {
    if !v.contains(&val) { v.push(val); }
}

/// Reconstruct cumulative taint sets by walking BFS results in reverse,
/// simulating backward taint propagation on just the visited instructions.
///
/// For Store instructions, only the *value* source register is added to
/// the active set (not the address base register). This is determined by
/// checking which src_reg's value matches the stored memory value.
/// Reconstruct results. Returns `(entries, remaining_regs, remaining_mems)`.
fn reconstruct_taint_sets(
    lines: &[TraceLine],
    visited: &[usize],
    source: &TaintSource,
) -> (Vec<ResultEntry>, [bool; 256], FxHashMap<u64, ()>) {
    let mut active_regs = [false; 256];
    let mut active_mem: FxHashMap<u64, ()> = FxHashMap::default();

    // Seed
    if source.is_mem {
        active_mem.insert(source.mem_addr, ());
    } else {
        let nid = normalize(source.reg) as usize;
        active_regs[nid] = true;
    }

    let mut entries: Vec<ResultEntry> = Vec::with_capacity(visited.len());

    for &idx in visited.iter().rev() {
        let line = &lines[idx];

        // Check which outputs of this instruction are in the active set
        let mut dst_active = false;
        for j in 0..line.num_dst as usize {
            let nid = normalize(line.dst_regs[j]) as usize;
            if active_regs[nid] { dst_active = true; }
        }
        let nzcv_active = line.sets_flags && active_regs[REG_NZCV as usize];
        let mem_w_active = line.has_mem_write
            && active_mem.contains_key(&line.mem_write_addr);
        let mem_w2_active = line.has_mem_write2
            && active_mem.contains_key(&line.mem_write_addr2);

        if dst_active || nzcv_active || mem_w_active || mem_w2_active {
            // Remove outputs
            if dst_active {
                for j in 0..line.num_dst as usize {
                    active_regs[normalize(line.dst_regs[j]) as usize] = false;
                }
            }
            if nzcv_active {
                active_regs[REG_NZCV as usize] = false;
            }
            if mem_w_active {
                active_mem.remove(&line.mem_write_addr);
            }
            if mem_w2_active {
                active_mem.remove(&line.mem_write_addr2);
            }

            // Add inputs (category-aware)
            match line.category {
                InsnCategory::ImmLoad | InsnCategory::ExternalCall => {
                    // No data inputs to add
                }
                InsnCategory::Load => {
                    // Data source: memory
                    if line.has_mem_read {
                        active_mem.insert(line.mem_read_addr, ());
                    }
                    if line.has_mem_read2 {
                        active_mem.insert(line.mem_read_addr2, ());
                    }
                    // Address registers
                    for j in 0..line.num_src as usize {
                        active_regs[normalize(line.src_regs[j]) as usize] = true;
                    }
                }
                InsnCategory::Store => {
                    // Only taint the VALUE source register(s), not the
                    // address base register.
                    //
                    // For single store (str x1, [x19]):
                    //   src_regs[0] = x1 (value), rest are address regs
                    // For pair store (stp x28, x27, [sp]):
                    //   src_regs[0] = x28, src_regs[1] = x27, rest = addr
                    if mem_w_active && line.num_src > 0 {
                        active_regs[normalize(line.src_regs[0]) as usize] = true;
                    }
                    if mem_w2_active && line.num_src > 1 {
                        active_regs[normalize(line.src_regs[1]) as usize] = true;
                    }
                }
                InsnCategory::Compare => {
                    // Compare → NZCV: taint the compared registers
                    for j in 0..line.num_src as usize {
                        active_regs[normalize(line.src_regs[j]) as usize] = true;
                    }
                }
                InsnCategory::CondSelect => {
                    // CondSelect: taint src regs (the two candidate values)
                    // but NOT NZCV (control dependency, not data).
                    for j in 0..line.num_src as usize {
                        active_regs[normalize(line.src_regs[j]) as usize] = true;
                    }
                    // Note: we intentionally do NOT add NZCV here.
                    // The BFS already included the Compare instruction
                    // via the NZCV dep edge in the graph. But for the
                    // taint-set display, showing NZCV is noise.
                }
                _ => {
                    // Generic: add src regs
                    for j in 0..line.num_src as usize {
                        active_regs[normalize(line.src_regs[j]) as usize] = true;
                    }
                    if line.has_mem_read {
                        active_mem.insert(line.mem_read_addr, ());
                    }
                }
            }
        }

        entries.push(ResultEntry {
            index: idx,
            reg_snapshot: active_regs,
            mem_snapshot: active_mem.keys().copied().collect(),
        });
    }

    entries.reverse();
    // Return remaining active state = unresolved sources (from before trace)
    (entries, active_regs, active_mem)
}

// ───────────────────────── engine ─────────────────────────

pub struct TaintEngine {
    mode: TrackMode,
    source: TaintSource,
    max_scan_distance: u32,
    max_depth: u32,
    cancel: Option<Arc<AtomicBool>>,

    // Forward-mode state
    reg_taint: [bool; 256],
    tainted_reg_count: i32,
    tainted_mem: FxHashMap<u64, Option<u64>>,

    results: Vec<ResultEntry>,
    mismatches: Vec<ValueMismatch>,
    stop_reason: StopReason,
    start_index: Option<usize>,
    remaining_taint_at_boundary: Option<RemainingTaint>,
}

impl Default for TaintEngine {
    fn default() -> Self { Self::new() }
}

impl TaintEngine {
    pub fn new() -> Self {
        Self {
            mode: TrackMode::Forward,
            source: TaintSource::from_reg(REG_INVALID),
            max_scan_distance: 50_000,
            max_depth: DEFAULT_MAX_DEPTH,
            cancel: None,
            reg_taint: [false; 256],
            tainted_reg_count: 0,
            tainted_mem: FxHashMap::default(),
            results: Vec::new(),
            mismatches: Vec::new(),
            stop_reason: StopReason::EndOfTrace,
            start_index: None,
            remaining_taint_at_boundary: None,
        }
    }

    pub fn remaining_taint(&self) -> Option<&RemainingTaint> {
        self.remaining_taint_at_boundary.as_ref()
    }

    pub fn set_mode(&mut self, mode: TrackMode) { self.mode = mode; }
    pub fn set_max_scan_distance(&mut self, n: u32) { self.max_scan_distance = n; }
    pub fn set_max_depth(&mut self, n: u32) { self.max_depth = n; }
    pub fn set_cancel_token(&mut self, token: Arc<AtomicBool>) { self.cancel = Some(token); }
    pub fn stop_reason(&self) -> StopReason { self.stop_reason }
    pub fn results(&self) -> &[ResultEntry] { &self.results }
    pub fn into_results(self) -> Vec<ResultEntry> { self.results }
    pub fn mode(&self) -> TrackMode { self.mode }
    pub fn source(&self) -> TaintSource { self.source }
    pub fn mismatches(&self) -> &[ValueMismatch] { &self.mismatches }

    pub fn set_source(&mut self, source: TaintSource) {
        self.source = source;
        self.reg_taint = [false; 256];
        self.tainted_reg_count = 0;
        self.tainted_mem.clear();
        self.results.clear();
        self.mismatches.clear();
        self.stop_reason = StopReason::EndOfTrace;

        if source.is_mem {
            self.tainted_mem.insert(source.mem_addr, None);
        } else {
            self.taint_reg(source.reg);
        }
    }

    // ───────── forward-mode helpers ─────────

    #[inline]
    fn taint_reg(&mut self, id: RegId) {
        if id == REG_INVALID || id == REG_XZR { return; }
        let nid = normalize(id) as usize;
        if !self.reg_taint[nid] {
            self.reg_taint[nid] = true;
            self.tainted_reg_count += 1;
        }
    }

    #[inline]
    fn untaint_reg(&mut self, id: RegId) {
        if id == REG_INVALID || id == REG_XZR { return; }
        let nid = normalize(id) as usize;
        if self.reg_taint[nid] {
            self.reg_taint[nid] = false;
            self.tainted_reg_count -= 1;
        }
    }

    #[inline]
    fn is_reg_tainted(&self, id: RegId) -> bool {
        if id == REG_INVALID || id == REG_XZR { return false; }
        self.reg_taint[normalize(id) as usize]
    }

    fn any_src_tainted(&self, line: &TraceLine) -> bool {
        for i in 0..line.num_src as usize {
            if self.is_reg_tainted(line.src_regs[i]) { return true; }
        }
        if line.has_mem_read && self.tainted_mem.contains_key(&line.mem_read_addr) { return true; }
        if line.has_mem_read2 && self.tainted_mem.contains_key(&line.mem_read_addr2) { return true; }
        false
    }

    fn any_caller_saved_tainted(&self) -> bool {
        for reg_id in 0..=18u8 {
            if self.is_reg_tainted(reg_id) { return true; }
        }
        self.is_reg_tainted(REG_NZCV)
    }

    fn untaint_caller_saved(&mut self) {
        for reg_id in 0..=18u8 { self.untaint_reg(reg_id); }
        self.untaint_reg(REG_NZCV);
    }

    fn record(&mut self, index: usize) {
        self.results.push(ResultEntry {
            index,
            reg_snapshot: self.reg_taint,
            mem_snapshot: self.tainted_mem.keys().copied().collect(),
        });
    }

    fn check_mem_read_mismatch(&mut self, addr: u64, actual_val: u64, index: usize) {
        if let Some(&Some(expected)) = self.tainted_mem.get(&addr) {
            if expected != actual_val {
                self.mismatches.push(ValueMismatch {
                    index, mem_addr: addr, expected_val: expected, actual_val,
                });
            }
        }
    }

    fn propagate_forward(&mut self, line: &TraceLine, index: usize) {
        use InsnCategory::*;
        match line.category {
            ImmLoad => {
                for i in 0..line.num_dst as usize { self.untaint_reg(line.dst_regs[i]); }
            }
            ExternalCall => { self.untaint_caller_saved(); }
            PartialModify => {}
            DataMove | Arithmetic | Logic | ShiftExt | Bitfield | CondSelect => {
                let src_t = self.any_src_tainted(line);
                for i in 0..line.num_dst as usize {
                    if src_t { self.taint_reg(line.dst_regs[i]); }
                    else { self.untaint_reg(line.dst_regs[i]); }
                }
                if line.sets_flags {
                    if src_t { self.taint_reg(REG_NZCV); }
                    else { self.untaint_reg(REG_NZCV); }
                }
            }
            Load => {
                if line.has_mem_read2 && line.num_dst >= 2 {
                    let mem_t1 = line.has_mem_read && self.tainted_mem.contains_key(&line.mem_read_addr);
                    let mem_t2 = self.tainted_mem.contains_key(&line.mem_read_addr2);
                    if mem_t1 {
                        self.check_mem_read_mismatch(line.mem_read_addr, line.mem_read_val, index);
                        self.taint_reg(line.dst_regs[0]);
                    } else { self.untaint_reg(line.dst_regs[0]); }
                    if mem_t2 {
                        self.check_mem_read_mismatch(line.mem_read_addr2, line.mem_read_val2, index);
                        self.taint_reg(line.dst_regs[1]);
                    } else { self.untaint_reg(line.dst_regs[1]); }
                } else {
                    let mem_t = line.has_mem_read && self.tainted_mem.contains_key(&line.mem_read_addr);
                    if mem_t { self.check_mem_read_mismatch(line.mem_read_addr, line.mem_read_val, index); }
                    for i in 0..line.num_dst as usize {
                        if mem_t { self.taint_reg(line.dst_regs[i]); }
                        else { self.untaint_reg(line.dst_regs[i]); }
                    }
                }
            }
            Store => {
                if line.has_mem_write {
                    if line.has_mem_write2 && line.num_src >= 2 {
                        if self.is_reg_tainted(line.src_regs[0]) {
                            self.tainted_mem.insert(line.mem_write_addr, Some(line.mem_write_val));
                        } else { self.tainted_mem.remove(&line.mem_write_addr); }
                        if self.is_reg_tainted(line.src_regs[1]) {
                            self.tainted_mem.insert(line.mem_write_addr2, Some(line.mem_write_val2));
                        } else { self.tainted_mem.remove(&line.mem_write_addr2); }
                    } else {
                        let src_t = line.num_src > 0 && self.is_reg_tainted(line.src_regs[0]);
                        if src_t { self.tainted_mem.insert(line.mem_write_addr, Some(line.mem_write_val)); }
                        else { self.tainted_mem.remove(&line.mem_write_addr); }
                    }
                }
            }
            Compare => {
                let src_t = self.any_src_tainted(line);
                if src_t { self.taint_reg(REG_NZCV); } else { self.untaint_reg(REG_NZCV); }
            }
            Branch => {}
            Other => {
                let src_t = self.any_src_tainted(line);
                for i in 0..line.num_dst as usize {
                    if src_t { self.taint_reg(line.dst_regs[i]); }
                    else { self.untaint_reg(line.dst_regs[i]); }
                }
                if line.has_mem_write {
                    if src_t { self.tainted_mem.insert(line.mem_write_addr, Some(line.mem_write_val)); }
                    else { self.tainted_mem.remove(&line.mem_write_addr); }
                }
            }
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(false)
    }

    // ───────── main entry points ─────────

    pub fn run(&mut self, lines: &[TraceLine], start_index: usize) {
        self.run_with_bytes(lines, start_index, &[]);
    }

    pub fn run_with_bytes(
        &mut self,
        lines: &[TraceLine],
        start_index: usize,
        _bytes: &[u8],
    ) {
        self.results.clear();
        self.mismatches.clear();
        self.stop_reason = StopReason::EndOfTrace;
        self.start_index = None;
        self.remaining_taint_at_boundary = None;
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
                    let line = &lines[i];
                    let mut involved = self.any_src_tainted(line);
                    if !involved && line.category == InsnCategory::ExternalCall && self.any_caller_saved_tainted() {
                        involved = true;
                    }
                    if !involved && line.has_mem_write && self.tainted_mem.contains_key(&line.mem_write_addr) {
                        involved = true;
                    }
                    if !involved && line.has_mem_write2 && self.tainted_mem.contains_key(&line.mem_write_addr2) {
                        involved = true;
                    }
                    self.propagate_forward(line, i);
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
                // Phase 1: forward scan to build dependency graph
                let mut builder = DepGraphBuilder::new();
                let (deps, reg_snapshot) =
                    builder.build(lines, start_index, &self.cancel);

                if self.is_cancelled() {
                    self.stop_reason = StopReason::Cancelled;
                    return;
                }

                // Determine BFS seeds
                let seeds = self.compute_bfs_seeds(
                    &lines[start_index], start_index, &reg_snapshot,
                    &builder.mem_last_def,
                );

                // Phase 2: depth-limited BFS
                let max_nodes = self.max_scan_distance as usize;
                let (mut visited, truncated) =
                    bfs_backward(&deps, &seeds, self.max_depth, max_nodes, &self.cancel);

                if self.is_cancelled() {
                    self.stop_reason = StopReason::Cancelled;
                    return;
                }

                if truncated {
                    self.stop_reason = StopReason::ScanLimitReached;
                }

                // Ensure start_index is in results even if it wasn't a
                // BFS seed (happens when target is a src register of the
                // start instruction, e.g. tracking x8 from `str x8, [x19]`).
                if !visited.contains(&start_index) {
                    let pos = visited.partition_point(|&x| x < start_index);
                    visited.insert(pos, start_index);
                }

                // Phase 3: reconstruct taint sets.
                // Remaining active_regs/active_mem after reconstruction
                // = unresolved sources from before the trace.
                let (entries, remaining_regs, remaining_mem) =
                    reconstruct_taint_sets(lines, &visited, &self.source);
                self.results = entries;

                // Build boundary taint from remaining active set
                let mut regs = Vec::new();
                for i in 0..256u16 {
                    if remaining_regs[i as usize] {
                        regs.push(reg_name(i as u8).to_string());
                    }
                }
                let mut mems: Vec<u64> = remaining_mem.keys().copied().collect();
                mems.sort_unstable();
                if !regs.is_empty() || !mems.is_empty() {
                    self.remaining_taint_at_boundary =
                        Some(RemainingTaint { regs, mems });
                }
            }
        }
    }

    /// Compute BFS seed indices based on the TaintSource type.
    ///
    /// Key logic: if the target register is a DST of the start instruction,
    /// seed from start_index (expanding all its deps). Otherwise the target
    /// is a SRC (e.g. tracking x8 from `str x8, [x19]`) — seed only from
    /// `reg_last_def[target_reg]` to avoid expanding unrelated deps like
    /// the Store's address registers.
    fn compute_bfs_seeds(
        &self,
        start_line: &TraceLine,
        start_index: usize,
        reg_snapshot: &[u32; 256],
        mem_last_def: &FxHashMap<u64, u32>,
    ) -> SmallVec<[u32; 4]> {
        let mut seeds = SmallVec::<[u32; 4]>::new();

        if self.source.skip_start_propagation {
            // Explicitly tracking a source register (e.g. address offset)
            let nid = normalize(self.source.reg) as usize;
            let def = reg_snapshot[nid];
            if def != NO_DEF {
                seeds.push(def);
            }
        } else if self.source.is_mem {
            if let Some(&def) = mem_last_def.get(&self.source.mem_addr) {
                seeds.push(def);
            }
        } else {
            // Check: is the target register a DST of the start instruction?
            let target_nid = normalize(self.source.reg) as usize;
            let mut is_dst = false;
            for j in 0..start_line.num_dst as usize {
                if normalize(start_line.dst_regs[j]) as usize == target_nid {
                    is_dst = true;
                    break;
                }
            }

            if is_dst {
                // Target is a destination: expand from the instruction
                seeds.push(start_index as u32);
            } else {
                // Target is a source (e.g. x8 in `str x8, [x19]`):
                // seed from its definition only, skip address deps.
                let def = reg_snapshot[target_nid];
                if def != NO_DEF {
                    seeds.push(def);
                }
            }
        }

        seeds
    }


    // ───────── format_result ─────────

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
        if let Some(idx) = self.start_index {
            if let Some(tl) = lines.get(idx) {
                out.push_str(&format!(
                    "Started from: line {} (file offset 0x{:x})\n",
                    tl.line_number, tl.file_offset
                ));
            }
        }
        out.push_str(&format!("Total matched: {} instructions\n", self.results.len()));
        let stop = match self.stop_reason {
            StopReason::AllTaintCleared => "all taint cleared".to_string(),
            StopReason::ScanLimitReached => format!(
                "scan limit reached (depth {} / {} nodes)", self.max_depth, self.max_scan_distance
            ),
            StopReason::EndOfTrace => "end of trace".to_string(),
            StopReason::Cancelled => "cancelled".to_string(),
        };
        out.push_str(&format!("Stop reason: {}\n", stop));

        if let Some(ref remaining) = self.remaining_taint_at_boundary {
            out.push_str("⚠ 以下 taint 在到达 trace 边界时仍未清除:\n");
            out.push_str(&format!("  寄存器: {}\n",
                if remaining.regs.is_empty() { "(无)".to_string() }
                else { remaining.regs.join(", ") }
            ));
            if !remaining.mems.is_empty() {
                let mems: Vec<String> = remaining.mems.iter().map(|a| format!("0x{:x}", a)).collect();
                out.push_str(&format!("  内存: {}\n", mems.join(", ")));
            }
            if !lines.is_empty() {
                let first_line = read_raw_line(bytes, &lines[0]);
                let first_line = first_line.trim();
                let func_id = first_line.split_whitespace().next().unwrap_or("?");
                let lr = first_line.find("LR=")
                    .map(|pos| {
                        let rest = &first_line[pos + 3..];
                        rest.split([',', ' ', ')']).next().unwrap_or("?")
                    })
                    .unwrap_or("?");
                out.push_str(&format!(
                    "  → 这些值是函数 {} 的入参/初始状态,由调用方(LR={})传入\n",
                    func_id, lr
                ));
            }
        }

        if !self.mismatches.is_empty() {
            out.push_str(&format!(
                "⚠ 发现 {} 处内存值不匹配(中间可能有 trace 未覆盖的写入):\n",
                self.mismatches.len()
            ));
            for mm in &self.mismatches {
                let tl = &lines[mm.index];
                out.push_str(&format!(
                    "  line {} mem:0x{:x}: 期望 0x{:x}, 实际 0x{:x}\n",
                    tl.line_number, mm.mem_addr, mm.expected_val, mm.actual_val
                ));
            }
        }

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
                    if !first { out.push_str(", "); }
                    out.push_str(reg_name(i as u8));
                    first = false;
                }
            }
            for m in &entry.mem_snapshot {
                if !first { out.push_str(", "); }
                out.push_str(&format!("mem:0x{:x}", m));
                first = false;
            }
            out.push_str("}\n\n");
        }
        out
    }
}
