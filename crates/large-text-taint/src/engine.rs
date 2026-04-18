//! Taint propagation engine.
//!
//! Forward mode: linear taint-bitmap propagation.
//! Backward mode: forward-scan builds labeled def-use graph, then
//! taint-guided traversal follows only the edges relevant to the
//! currently active registers/memory.

use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::parser::read_raw_line;
use crate::reg::{normalize, reg_name, RegId, REG_INVALID, REG_LR, REG_NZCV, REG_Q0, REG_XZR};
use crate::trace::{InsnCategory, TraceLine};

const NO_DEF: u32 = u32::MAX;
const DEFAULT_MAX_DEPTH: u32 = 64;

// ───────────────────────── public types ─────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TrackMode { Forward, Backward }

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StopReason { AllTaintCleared, EndOfTrace, ScanLimitReached, Cancelled }

#[derive(Copy, Clone, Debug)]
pub struct TaintSource {
    pub reg: RegId,
    pub mem_addr: u64,
    pub is_mem: bool,
    pub skip_start_propagation: bool,
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

// ────────────────── labeled dep-graph (backward) ──────────────────

/// Per-instruction dependency edges, labeled by which register/memory
/// each edge serves. This allows taint-guided traversal to follow only
/// the edges relevant to the currently tracked registers.
struct InsnDeps {
    /// (normalized_reg_id, predecessor_instruction_index)
    /// Each entry means: "this instruction uses register R, which was
    /// last defined by instruction P."
    reg_preds: SmallVec<[(u8, u32); 4]>,
    /// (memory_address, predecessor_store_index)
    mem_preds: SmallVec<[(u64, u32); 2]>,
}

impl InsnDeps {
    fn new() -> Self {
        Self { reg_preds: SmallVec::new(), mem_preds: SmallVec::new() }
    }
}

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

    fn reg_def(&self, reg: RegId) -> Option<(u8, u32)> {
        if reg == REG_INVALID || reg == REG_XZR { return None; }
        let nid = normalize(reg);
        let idx = self.reg_last_def[nid as usize];
        if idx == NO_DEF { None } else { Some((nid, idx)) }
    }

    fn set_reg_def(&mut self, reg: RegId, i: u32) {
        if reg == REG_INVALID || reg == REG_XZR { return; }
        self.reg_last_def[normalize(reg) as usize] = i;
    }

    fn build(
        &mut self,
        lines: &[TraceLine],
        end: usize,
        cancel: &Option<Arc<AtomicBool>>,
    ) -> (Vec<InsnDeps>, [u32; 256]) {
        let n = end + 1;
        let mut deps: Vec<InsnDeps> = Vec::with_capacity(n);
        let mut snapshot = [NO_DEF; 256];

        #[allow(clippy::needless_range_loop)]
        for i in 0..n {
            if i & 0x1_FFFF == 0 {
                if let Some(c) = cancel {
                    if c.load(Ordering::Relaxed) {
                        deps.resize_with(n, InsnDeps::new);
                        return (deps, snapshot);
                    }
                }
            }

            let line = &lines[i];
            let mut d = InsnDeps::new();

            let skip_src = matches!(
                line.category,
                InsnCategory::ImmLoad | InsnCategory::ExternalCall
            );

            if !skip_src {
                for j in 0..line.num_src as usize {
                    if let Some((nid, pred)) = self.reg_def(line.src_regs[j]) {
                        push_unique_reg(&mut d.reg_preds, nid, pred);
                    }
                }
                if line.category == InsnCategory::CondSelect {
                    if let Some((nid, pred)) = self.reg_def(REG_NZCV) {
                        push_unique_reg(&mut d.reg_preds, nid, pred);
                    }
                }
                if line.category == InsnCategory::PartialModify {
                    for j in 0..line.num_dst as usize {
                        if let Some((nid, pred)) = self.reg_def(line.dst_regs[j]) {
                            push_unique_reg(&mut d.reg_preds, nid, pred);
                        }
                    }
                }
            }

            if line.has_mem_read {
                if let Some(&pred) = self.mem_last_def.get(&line.mem_read_addr) {
                    d.mem_preds.push((line.mem_read_addr, pred));
                }
            }
            if line.has_mem_read2 {
                if let Some(&pred) = self.mem_last_def.get(&line.mem_read_addr2) {
                    d.mem_preds.push((line.mem_read_addr2, pred));
                }
            }

            deps.push(d);

            if i == end {
                snapshot = self.reg_last_def;
            }

            // Update definitions
            match line.category {
                InsnCategory::ExternalCall => {
                    // AAPCS64 caller-saved: x0..x18, x30 (LR), q0..q7, NZCV.
                    for r in 0..=18u8 {
                        self.set_reg_def(r, i as u32);
                    }
                    self.set_reg_def(REG_LR, i as u32);
                    for r in 0..8u8 {
                        self.set_reg_def(REG_Q0 + r, i as u32);
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

#[inline]
fn push_unique_reg(v: &mut SmallVec<[(u8, u32); 4]>, nid: u8, pred: u32) {
    if !v.iter().any(|&(n, _)| n == nid) {
        v.push((nid, pred));
    }
}

/// Index of the writeback-base dst within `dst_regs`, or `None`. Parser
/// places the writeback base as the last dst when present.
#[inline]
fn writeback_dst_idx(line: &TraceLine) -> Option<usize> {
    if line.has_writeback_base && line.num_dst > 0 {
        Some((line.num_dst - 1) as usize)
    } else {
        None
    }
}

/// Taint-guided backward traversal on the labeled dep graph.
///
/// Instead of blindly expanding all deps (which explodes through
/// paired ldp/stp), this only follows dep edges whose output register
/// or memory address is currently in the active (tracked) set.
/// Phase 2a: taint-guided traversal to find the visited set.
/// Only follows dep edges whose register/memory is in the active set.
/// Returns (visited_indices_sorted, truncated).
#[allow(clippy::too_many_arguments)]
fn taint_guided_collect(
    lines: &[TraceLine],
    deps: &[InsnDeps],
    start_index: usize,
    source: &TaintSource,
    is_dst: bool,
    max_depth: u32,
    max_nodes: usize,
    cancel: &Option<Arc<AtomicBool>>,
) -> (Vec<usize>, bool) {
    let mut active_regs = [false; 256];
    let mut active_mem: FxHashMap<u64, ()> = FxHashMap::default();

    if source.is_mem {
        active_mem.insert(source.mem_addr, ());
    } else {
        active_regs[normalize(source.reg) as usize] = true;
    }

    let mut queue: VecDeque<(u32, u32)> = VecDeque::new();
    let mut visited = vec![false; deps.len()];
    let mut count: usize = 0;
    let mut truncated = false;

    if is_dst {
        queue.push_back((start_index as u32, 0));
    } else {
        visited[start_index] = true;
        count += 1;
        if source.is_mem {
            // Mem-source backward: find the predecessor that last wrote
            // the target address.
            for &(addr, pred) in &deps[start_index].mem_preds {
                if addr == source.mem_addr {
                    queue.push_back((pred, 1));
                    break;
                }
            }
        } else {
            let nid = normalize(source.reg);
            for &(rn, pred) in &deps[start_index].reg_preds {
                if rn == nid {
                    queue.push_back((pred, 1));
                    break;
                }
            }
        }
    }

    while let Some((idx, depth)) = queue.pop_front() {
        if let Some(c) = cancel {
            if c.load(Ordering::Relaxed) { break; }
        }
        let ui = idx as usize;
        if ui >= deps.len() || visited[ui] { continue; }
        if depth > max_depth { truncated = true; continue; }
        if count >= max_nodes { truncated = true; break; }

        let line = &lines[ui];

        // Per-dst active bitmap (needed to route LDP-pair mem correctly and
        // to re-activate writeback base registers after clearing dst).
        let mut dst_active_mask: u32 = 0;
        for j in 0..line.num_dst as usize {
            if active_regs[normalize(line.dst_regs[j]) as usize] {
                dst_active_mask |= 1 << j;
            }
        }
        let dst_active = dst_active_mask != 0;
        let nzcv_active = line.sets_flags && active_regs[REG_NZCV as usize];
        let mem_w_active = line.has_mem_write && active_mem.contains_key(&line.mem_write_addr);
        let mem_w2_active = line.has_mem_write2 && active_mem.contains_key(&line.mem_write_addr2);

        if !dst_active && !nzcv_active && !mem_w_active && !mem_w2_active {
            continue;
        }

        visited[ui] = true;
        count += 1;

        // Propagate: remove outputs, add inputs
        if dst_active {
            for j in 0..line.num_dst as usize { active_regs[normalize(line.dst_regs[j]) as usize] = false; }
        }
        if nzcv_active { active_regs[REG_NZCV as usize] = false; }
        if mem_w_active { active_mem.remove(&line.mem_write_addr); }
        if mem_w2_active { active_mem.remove(&line.mem_write_addr2); }

        // Writeback base (pre/post-index): new base = old base + imm, same
        // register — re-activate after the blanket clear above.
        let wb_idx = writeback_dst_idx(line);
        if let Some(wi) = wb_idx {
            if (dst_active_mask >> wi) & 1 != 0 {
                active_regs[normalize(line.dst_regs[wi]) as usize] = true;
            }
        }

        match line.category {
            InsnCategory::ImmLoad | InsnCategory::ExternalCall => {}
            InsnCategory::Load => {
                // Only follow the data chain through memory.
                // Address registers are NOT added to active — they are
                // a separate concern ("向后追踪地址来源" menu).
                // Route mem reads by which data-dst was active:
                //   LDP: dst[0] ↔ read_addr, dst[1] ↔ read_addr2
                //   LDR: dst[0] ↔ read_addr (single read)
                //   Writeback base dst is skipped (handled above).
                let d0_data = (dst_active_mask & 1) != 0 && wb_idx != Some(0);
                let d1_data = (dst_active_mask & 2) != 0 && wb_idx != Some(1);
                if line.has_mem_read2 {
                    if d0_data { active_mem.insert(line.mem_read_addr, ()); }
                    if d1_data { active_mem.insert(line.mem_read_addr2, ()); }
                } else if d0_data && line.has_mem_read {
                    active_mem.insert(line.mem_read_addr, ());
                }
            }
            InsnCategory::Store => {
                if mem_w_active && line.num_src > 0 { active_regs[normalize(line.src_regs[0]) as usize] = true; }
                if mem_w2_active && line.num_src > 1 { active_regs[normalize(line.src_regs[1]) as usize] = true; }
            }
            InsnCategory::CondSelect => {
                for j in 0..line.num_src as usize { active_regs[normalize(line.src_regs[j]) as usize] = true; }
                // csel depends on NZCV; dep-graph recorded the edge but the
                // traversal only follows edges whose nid is in active_regs.
                active_regs[REG_NZCV as usize] = true;
            }
            _ => {
                for j in 0..line.num_src as usize { active_regs[normalize(line.src_regs[j]) as usize] = true; }
                if line.has_mem_read { active_mem.insert(line.mem_read_addr, ()); }
            }
        }

        // Queue only active predecessors
        let d = &deps[ui];
        for &(nid, pred) in &d.reg_preds {
            if active_regs[nid as usize] && !visited[pred as usize] {
                queue.push_back((pred, depth + 1));
            }
        }
        for &(addr, pred) in &d.mem_preds {
            if active_mem.contains_key(&addr) && !visited[pred as usize] {
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

/// Phase 2b: rebuild taint snapshots in descending instruction order
/// over the visited set. This produces correct sequential taint evolution.
fn rebuild_snapshots(
    lines: &[TraceLine],
    visited: &[usize],
    source: &TaintSource,
) -> (Vec<ResultEntry>, [bool; 256], FxHashMap<u64, ()>) {
    let mut active_regs = [false; 256];
    let mut active_mem: FxHashMap<u64, ()> = FxHashMap::default();

    if source.is_mem {
        active_mem.insert(source.mem_addr, ());
    } else {
        active_regs[normalize(source.reg) as usize] = true;
    }

    let mut entries: Vec<ResultEntry> = Vec::with_capacity(visited.len());

    // Process in DESCENDING order (target → earliest)
    for &idx in visited.iter().rev() {
        let line = &lines[idx];

        let mut dst_active_mask: u32 = 0;
        for j in 0..line.num_dst as usize {
            if active_regs[normalize(line.dst_regs[j]) as usize] {
                dst_active_mask |= 1 << j;
            }
        }
        let dst_active = dst_active_mask != 0;
        let nzcv_active = line.sets_flags && active_regs[REG_NZCV as usize];
        let mem_w_active = line.has_mem_write && active_mem.contains_key(&line.mem_write_addr);
        let mem_w2_active = line.has_mem_write2 && active_mem.contains_key(&line.mem_write_addr2);

        if dst_active || nzcv_active || mem_w_active || mem_w2_active {
            if dst_active {
                for j in 0..line.num_dst as usize { active_regs[normalize(line.dst_regs[j]) as usize] = false; }
            }
            if nzcv_active { active_regs[REG_NZCV as usize] = false; }
            if mem_w_active { active_mem.remove(&line.mem_write_addr); }
            if mem_w2_active { active_mem.remove(&line.mem_write_addr2); }

            // Writeback base: re-activate (same reg as before, just updated).
            let wb_idx = writeback_dst_idx(line);
            if let Some(wi) = wb_idx {
                if (dst_active_mask >> wi) & 1 != 0 {
                    active_regs[normalize(line.dst_regs[wi]) as usize] = true;
                }
            }

            match line.category {
                InsnCategory::ImmLoad | InsnCategory::ExternalCall => {}
                InsnCategory::Load => {
                    // Same routing as taint_guided_collect: data-dst only,
                    // and do NOT add address-regs (data-only backward chain).
                    let d0_data = (dst_active_mask & 1) != 0 && wb_idx != Some(0);
                    let d1_data = (dst_active_mask & 2) != 0 && wb_idx != Some(1);
                    if line.has_mem_read2 {
                        if d0_data { active_mem.insert(line.mem_read_addr, ()); }
                        if d1_data { active_mem.insert(line.mem_read_addr2, ()); }
                    } else if d0_data && line.has_mem_read {
                        active_mem.insert(line.mem_read_addr, ());
                    }
                }
                InsnCategory::Store => {
                    if mem_w_active && line.num_src > 0 { active_regs[normalize(line.src_regs[0]) as usize] = true; }
                    if mem_w2_active && line.num_src > 1 { active_regs[normalize(line.src_regs[1]) as usize] = true; }
                }
                InsnCategory::CondSelect => {
                    for j in 0..line.num_src as usize { active_regs[normalize(line.src_regs[j]) as usize] = true; }
                    active_regs[REG_NZCV as usize] = true;
                }
                _ => {
                    for j in 0..line.num_src as usize { active_regs[normalize(line.src_regs[j]) as usize] = true; }
                    if line.has_mem_read { active_mem.insert(line.mem_read_addr, ()); }
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
    (entries, active_regs, active_mem)
}

// ───────────────────────── engine ─────────────────────────

pub struct TaintEngine {
    mode: TrackMode,
    source: TaintSource,
    max_scan_distance: u32,
    max_depth: u32,
    cancel: Option<Arc<AtomicBool>>,

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
        if !self.reg_taint[nid] { self.reg_taint[nid] = true; self.tainted_reg_count += 1; }
    }

    #[inline]
    fn untaint_reg(&mut self, id: RegId) {
        if id == REG_INVALID || id == REG_XZR { return; }
        let nid = normalize(id) as usize;
        if self.reg_taint[nid] { self.reg_taint[nid] = false; self.tainted_reg_count -= 1; }
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
        // AAPCS64 caller-saved: x0..x18, x30 (LR), q0..q7, NZCV.
        for reg_id in 0..=18u8 { if self.is_reg_tainted(reg_id) { return true; } }
        if self.is_reg_tainted(REG_LR) { return true; }
        for i in 0..8u8 { if self.is_reg_tainted(REG_Q0 + i) { return true; } }
        self.is_reg_tainted(REG_NZCV)
    }

    fn untaint_caller_saved(&mut self) {
        for reg_id in 0..=18u8 { self.untaint_reg(reg_id); }
        self.untaint_reg(REG_LR);
        for i in 0..8u8 { self.untaint_reg(REG_Q0 + i); }
        self.untaint_reg(REG_NZCV);
    }

    fn record(&mut self, index: usize) {
        self.results.push(ResultEntry {
            index, reg_snapshot: self.reg_taint,
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
            DataMove | Arithmetic | Logic | ShiftExt | Bitfield => {
                let src_t = self.any_src_tainted(line);
                for i in 0..line.num_dst as usize {
                    if src_t { self.taint_reg(line.dst_regs[i]); }
                    else { self.untaint_reg(line.dst_regs[i]); }
                }
                if line.sets_flags {
                    if src_t { self.taint_reg(REG_NZCV); } else { self.untaint_reg(REG_NZCV); }
                }
            }
            CondSelect => {
                // csel/csinc/... depends on the chosen srcs AND NZCV.
                let src_t = self.any_src_tainted(line) || self.is_reg_tainted(REG_NZCV);
                for i in 0..line.num_dst as usize {
                    if src_t { self.taint_reg(line.dst_regs[i]); }
                    else { self.untaint_reg(line.dst_regs[i]); }
                }
                if line.sets_flags {
                    if src_t { self.taint_reg(REG_NZCV); } else { self.untaint_reg(REG_NZCV); }
                }
            }
            Load => {
                let wb_idx = writeback_dst_idx(line);
                if line.has_mem_read2 && line.num_dst >= 2 {
                    // LDP data pair: dst[0]↔read_addr, dst[1]↔read_addr2.
                    // Writeback base (if any) is dst[last], skipped here so
                    // its taint carries over unchanged from the old base.
                    let mt1 = line.has_mem_read && self.tainted_mem.contains_key(&line.mem_read_addr);
                    let mt2 = self.tainted_mem.contains_key(&line.mem_read_addr2);
                    if mt1 { self.check_mem_read_mismatch(line.mem_read_addr, line.mem_read_val, index); self.taint_reg(line.dst_regs[0]); }
                    else { self.untaint_reg(line.dst_regs[0]); }
                    if mt2 { self.check_mem_read_mismatch(line.mem_read_addr2, line.mem_read_val2, index); self.taint_reg(line.dst_regs[1]); }
                    else { self.untaint_reg(line.dst_regs[1]); }
                } else {
                    let mt = line.has_mem_read && self.tainted_mem.contains_key(&line.mem_read_addr);
                    if mt { self.check_mem_read_mismatch(line.mem_read_addr, line.mem_read_val, index); }
                    for i in 0..line.num_dst as usize {
                        if wb_idx == Some(i) { continue; } // keep writeback base's taint
                        if mt { self.taint_reg(line.dst_regs[i]); } else { self.untaint_reg(line.dst_regs[i]); }
                    }
                }
            }
            Store => {
                if line.has_mem_write {
                    if line.has_mem_write2 && line.num_src >= 2 {
                        if self.is_reg_tainted(line.src_regs[0]) { self.tainted_mem.insert(line.mem_write_addr, Some(line.mem_write_val)); }
                        else { self.tainted_mem.remove(&line.mem_write_addr); }
                        if self.is_reg_tainted(line.src_regs[1]) { self.tainted_mem.insert(line.mem_write_addr2, Some(line.mem_write_val2)); }
                        else { self.tainted_mem.remove(&line.mem_write_addr2); }
                    } else {
                        let st = line.num_src > 0 && self.is_reg_tainted(line.src_regs[0]);
                        if st { self.tainted_mem.insert(line.mem_write_addr, Some(line.mem_write_val)); }
                        else { self.tainted_mem.remove(&line.mem_write_addr); }
                    }
                }
            }
            Compare => {
                let st = self.any_src_tainted(line);
                if st { self.taint_reg(REG_NZCV); } else { self.untaint_reg(REG_NZCV); }
            }
            Branch => {}
            Other => {
                let st = self.any_src_tainted(line);
                for i in 0..line.num_dst as usize {
                    if st { self.taint_reg(line.dst_regs[i]); } else { self.untaint_reg(line.dst_regs[i]); }
                }
                if line.has_mem_write {
                    if st { self.tainted_mem.insert(line.mem_write_addr, Some(line.mem_write_val)); }
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
        if lines.is_empty() || start_index >= lines.len() { return; }
        self.start_index = Some(start_index);

        match self.mode {
            TrackMode::Forward => {
                self.record(start_index);
                let mut idle: u32 = 0;
                let mut i = start_index + 1;
                while i < lines.len() {
                    if self.is_cancelled() { self.stop_reason = StopReason::Cancelled; return; }
                    let line = &lines[i];
                    let mut involved = self.any_src_tainted(line);
                    if !involved && line.category == InsnCategory::ExternalCall && self.any_caller_saved_tainted() { involved = true; }
                    if !involved && line.category == InsnCategory::CondSelect && self.is_reg_tainted(REG_NZCV) { involved = true; }
                    if !involved && line.has_mem_write && self.tainted_mem.contains_key(&line.mem_write_addr) { involved = true; }
                    if !involved && line.has_mem_write2 && self.tainted_mem.contains_key(&line.mem_write_addr2) { involved = true; }
                    self.propagate_forward(line, i);
                    if involved { self.record(i); idle = 0; }
                    else {
                        idle += 1;
                        if idle >= self.max_scan_distance { self.stop_reason = StopReason::ScanLimitReached; break; }
                    }
                    if self.tainted_reg_count == 0 && self.tainted_mem.is_empty() {
                        self.stop_reason = StopReason::AllTaintCleared; break;
                    }
                    i += 1;
                }
            }

            TrackMode::Backward => {
                // Phase 1: build labeled dep graph
                let mut builder = DepGraphBuilder::new();
                let (deps, _reg_snapshot) =
                    builder.build(lines, start_index, &self.cancel);

                if self.is_cancelled() { self.stop_reason = StopReason::Cancelled; return; }

                // Determine if target is a dst of the start instruction
                let start_line = &lines[start_index];
                let is_dst = if self.source.skip_start_propagation || self.source.is_mem {
                    false
                } else {
                    let tnid = normalize(self.source.reg) as usize;
                    (0..start_line.num_dst as usize)
                        .any(|j| normalize(start_line.dst_regs[j]) as usize == tnid)
                };

                // Phase 2a: taint-guided traversal → visited set
                let max_nodes = self.max_scan_distance as usize;
                let (visited, truncated) = taint_guided_collect(
                    lines, &deps, start_index, &self.source,
                    is_dst, self.max_depth, max_nodes, &self.cancel,
                );

                if self.is_cancelled() { self.stop_reason = StopReason::Cancelled; return; }

                if truncated {
                    self.stop_reason = StopReason::ScanLimitReached;
                }

                // Phase 2b: rebuild snapshots in correct sequential order
                let (entries, remaining_regs, remaining_mem) =
                    rebuild_snapshots(lines, &visited, &self.source);
                self.results = entries;

                // Build boundary taint
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

    // ───────── format_result ─────────

    pub fn format_result(&self, lines: &[TraceLine], bytes: &[u8]) -> String {
        let mut out = String::new();
        let mode_s = match self.mode { TrackMode::Forward => "Forward", TrackMode::Backward => "Backward" };
        out.push_str(&format!("=== Taint {} Tracking ===\n", mode_s));
        out.push_str("Source: ");
        if self.source.is_mem { out.push_str(&format!("mem:0x{:x}", self.source.mem_addr)); }
        else { out.push_str(reg_name(self.source.reg)); }
        out.push('\n');
        if let Some(idx) = self.start_index {
            if let Some(tl) = lines.get(idx) {
                out.push_str(&format!("Started from: line {} (file offset 0x{:x})\n", tl.line_number, tl.file_offset));
            }
        }
        out.push_str(&format!("Total matched: {} instructions\n", self.results.len()));
        let stop = match self.stop_reason {
            StopReason::AllTaintCleared => "all taint cleared".to_string(),
            StopReason::ScanLimitReached => format!("scan limit reached (depth {} / {} nodes)", self.max_depth, self.max_scan_distance),
            StopReason::EndOfTrace => "end of trace".to_string(),
            StopReason::Cancelled => "cancelled".to_string(),
        };
        out.push_str(&format!("Stop reason: {}\n", stop));

        if let Some(ref remaining) = self.remaining_taint_at_boundary {
            out.push_str("⚠ 以下 taint 在到达 trace 边界时仍未清除:\n");
            out.push_str(&format!("  寄存器: {}\n",
                if remaining.regs.is_empty() { "(无)".to_string() } else { remaining.regs.join(", ") }));
            if !remaining.mems.is_empty() {
                let mems: Vec<String> = remaining.mems.iter().map(|a| format!("0x{:x}", a)).collect();
                out.push_str(&format!("  内存: {}\n", mems.join(", ")));
            }
            if !lines.is_empty() {
                let first_line = read_raw_line(bytes, &lines[0]);
                let first_line = first_line.trim();
                let func_id = first_line.split_whitespace().next().unwrap_or("?");
                let lr = first_line.find("LR=")
                    .map(|pos| { let rest = &first_line[pos + 3..]; rest.split([',', ' ', ')']).next().unwrap_or("?") })
                    .unwrap_or("?");
                out.push_str(&format!("  → 这些值是函数 {} 的入参/初始状态,由调用方(LR={})传入\n", func_id, lr));
            }
        }

        if !self.mismatches.is_empty() {
            out.push_str(&format!("⚠ 发现 {} 处内存值不匹配:\n", self.mismatches.len()));
            for mm in &self.mismatches {
                let tl = &lines[mm.index];
                out.push_str(&format!("  line {} mem:0x{:x}: 期望 0x{:x}, 实际 0x{:x}\n",
                    tl.line_number, mm.mem_addr, mm.expected_val, mm.actual_val));
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
