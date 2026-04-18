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
use crate::reg::{
    normalize, reg_name, RegId, REG_FP, REG_INVALID, REG_LR, REG_NZCV, REG_Q0, REG_SP, REG_X0,
    REG_XZR,
};
use crate::tag::{merge_tags, TagId, TagTable, TAG_UNTAGGED};
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
    /// Phase 1 semantic tags aligned with `reg_snapshot` — index `i` is
    /// the tag for register `i` when `reg_snapshot[i]` is true.
    /// `TAG_UNTAGGED` when there is no specific origin.
    pub reg_tags: [TagId; 256],
    /// Phase 1 semantic tags aligned with `mem_snapshot` by address.
    /// Every entry in `mem_snapshot` may have a corresponding
    /// `(addr, tag)` here; absence means `TAG_UNTAGGED`.
    pub mem_tags: Vec<(u64, TagId)>,
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
    /// Phase 1: per-register semantic tag paralleling `regs`. Empty Vec
    /// means no tag lookup was available. Each entry is
    /// `(reg_name, TagId)`; `TAG_UNTAGGED` when unknown.
    pub reg_tags: Vec<(String, TagId)>,
    /// Phase 1: per-address semantic tag paralleling `mems`.
    pub mem_tags: Vec<(u64, TagId)>,
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

/// Whether `line`'s memory operand is based on SP or FP (x29).
/// Used to recognise stack-spill memory so address-source backward
/// tracing can stop at spill boundaries instead of chasing unrelated
/// values written to the same stack slot by earlier code.
#[inline]
fn is_sp_rel_mem(line: &TraceLine) -> bool {
    let base = line.mem_base_reg;
    if base == REG_INVALID {
        return false;
    }
    let n = normalize(base);
    n == REG_SP || n == normalize(REG_FP)
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
    stop_at_sp_spill: bool,
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
                // Address-source mode: don't chase writers of SP/FP-relative
                // slots — those are stack spills and the value inside is
                // unrelated to the register we're tracing through them.
                // Leaving the address in active_mem means it surfaces as a
                // boundary taint, which is the right UX signal.
                if stop_at_sp_spill && is_sp_rel_mem(&lines[pred as usize]) {
                    continue;
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

/// Phase 2b: rebuild taint snapshots in descending instruction order
/// over the visited set. This produces correct sequential taint evolution.
fn rebuild_snapshots(
    lines: &[TraceLine],
    visited: &[usize],
    source: &TaintSource,
    start_index: usize,
) -> (Vec<ResultEntry>, [bool; 256], FxHashMap<u64, ()>) {
    let mut active_regs = [false; 256];
    let mut active_mem: FxHashMap<u64, ()> = FxHashMap::default();

    if source.is_mem {
        active_mem.insert(source.mem_addr, ());
    } else {
        active_regs[normalize(source.reg) as usize] = true;
    }

    let mut entries: Vec<ResultEntry> = Vec::with_capacity(visited.len());

    // Process in DESCENDING order (target → earliest).
    //
    // Each row's snapshot is **row-scoped**: it shows this line's full
    // taint contribution to the chain — both
    //   • output side (dst / mem-write that downstream actually consumes), AND
    //   • input side (src regs / mem-read that this line pulls in to
    //     feed that dst, following the same category rules as
    //     `taint_guided_collect`).
    //
    // This matches the user intent: "what does *this row* put into and
    // take out of the taint chain". Showing only dst hides the
    // register that flowed into it (e.g. `mov x8, x10` must show BOTH
    // x8 and x10). Showing the engine's full active set bleeds
    // unrelated regs into every row.
    //
    // The start line is special: the configured source is the user's
    // answer to "this is the taint I'm tracing" — we don't append its
    // line's src regs (those are what we're going to trace *to*).
    for &idx in visited.iter().rev() {
        let line = &lines[idx];

        let mut row_regs = [false; 256];
        let mut row_mems: Vec<u64> = Vec::new();

        if idx == start_index {
            // Start line: just the source, untainted src/mem_read of the
            // start line itself is the boundary we're heading toward.
            if source.is_mem {
                row_mems.push(source.mem_addr);
            } else {
                let nid = normalize(source.reg) as usize;
                if nid < 256 {
                    row_regs[nid] = true;
                }
            }
        } else {
            // ── Output side: which dst / mem-write are in active? ──
            let mut dst_active_mask: u32 = 0;
            for j in 0..line.num_dst as usize {
                let nid = normalize(line.dst_regs[j]) as usize;
                if active_regs[nid] {
                    dst_active_mask |= 1 << j;
                    row_regs[nid] = true;
                }
            }
            let nzcv_active = line.sets_flags && active_regs[REG_NZCV as usize];
            if nzcv_active {
                row_regs[REG_NZCV as usize] = true;
            }
            let mem_w_active = line.has_mem_write
                && active_mem.contains_key(&line.mem_write_addr);
            let mem_w2_active = line.has_mem_write2
                && active_mem.contains_key(&line.mem_write_addr2);
            if mem_w_active {
                row_mems.push(line.mem_write_addr);
            }
            if mem_w2_active {
                row_mems.push(line.mem_write_addr2);
            }

            // ── Input side: iff any output is live, mirror the category
            //    rules from taint_guided_collect so the shown src regs /
            //    mem-reads are exactly those that feed the live dsts. ──
            let any_out = dst_active_mask != 0 || nzcv_active || mem_w_active || mem_w2_active;
            if any_out {
                let wb_idx = writeback_dst_idx(line);
                match line.category {
                    InsnCategory::ImmLoad | InsnCategory::ExternalCall => {
                        // No input contribution shown: ImmLoad has no
                        // src that carries upstream taint; ExternalCall
                        // is a black box whose caller-saved upstream is
                        // already clipped by the engine.
                    }
                    InsnCategory::Load => {
                        // Data flow enters via mem_read, not the address
                        // regs (GumTrace "只追数据流" design).
                        let d0_data = (dst_active_mask & 1) != 0 && wb_idx != Some(0);
                        let d1_data = (dst_active_mask & 2) != 0 && wb_idx != Some(1);
                        if line.has_mem_read2 {
                            if d0_data {
                                row_mems.push(line.mem_read_addr);
                            }
                            if d1_data {
                                row_mems.push(line.mem_read_addr2);
                            }
                        } else if d0_data && line.has_mem_read {
                            row_mems.push(line.mem_read_addr);
                        }
                    }
                    InsnCategory::Store => {
                        if mem_w_active && line.num_src > 0 {
                            row_regs[normalize(line.src_regs[0]) as usize] = true;
                        }
                        if mem_w2_active && line.num_src > 1 {
                            row_regs[normalize(line.src_regs[1]) as usize] = true;
                        }
                    }
                    InsnCategory::CondSelect => {
                        for j in 0..line.num_src as usize {
                            row_regs[normalize(line.src_regs[j]) as usize] = true;
                        }
                        // csel depends on NZCV.
                        row_regs[REG_NZCV as usize] = true;
                    }
                    _ => {
                        for j in 0..line.num_src as usize {
                            row_regs[normalize(line.src_regs[j]) as usize] = true;
                        }
                        if line.has_mem_read {
                            row_mems.push(line.mem_read_addr);
                        }
                    }
                }
            }
        }

        entries.push(ResultEntry {
            index: idx,
            reg_snapshot: row_regs,
            mem_snapshot: row_mems,
            // Backward/rebuild doesn't track per-register semantic tags
            // directly yet — tags get resolved from the side-car TagTable
            // at format time based on the mem addresses present in
            // mem_snapshot. Phase 2 will add proper per-reg tag rebuild.
            reg_tags: [TAG_UNTAGGED; 256],
            mem_tags: Vec::new(),
        });

        // Address-source mode: the start line's src (not its dst) is the
        // thing we're tracing. taint_guided_collect mirrors this by never
        // running the match-arm propagation on the start index in that
        // case; rebuild must match, otherwise it would e.g. clear the
        // source reg and insert the start line's mem_read into active_mem
        // — producing a bogus boundary taint from the start line itself.
        let skip_propagate_start = source.skip_start_propagation && idx == start_index;

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

        if !skip_propagate_start && (dst_active || nzcv_active || mem_w_active || mem_w2_active) {
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
    /// When true, backward tracing does not follow mem_preds whose writer
    /// is SP/FP-relative (stack spills). The tracked register's value came
    /// from whatever wrote the spill slot *in this dynamic instance*, but
    /// going further through the slot almost always derails into
    /// unrelated callers that happened to reuse the same slot earlier.
    /// Set by the UI for the "向后追踪地址来源" menu path.
    stop_at_sp_spill: bool,
    cancel: Option<Arc<AtomicBool>>,

    /// Optional semantic-tag side table. When present, the engine
    /// decorates boundary taint and every ResultEntry with human-
    /// readable origin labels (external-call return values, const-mem
    /// ranges, payload strings).
    tag_table: Option<Arc<TagTable>>,
    /// Explicit UserSeed tag attached to the configured `source` (if any).
    source_tag: TagId,

    reg_taint: [bool; 256],
    reg_tag: [TagId; 256],
    tainted_reg_count: i32,
    tainted_mem: FxHashMap<u64, MemTaint>,

    results: Vec<ResultEntry>,
    mismatches: Vec<ValueMismatch>,
    stop_reason: StopReason,
    start_index: Option<usize>,
    remaining_taint_at_boundary: Option<RemainingTaint>,
}

/// Tainted-memory cell metadata.
#[derive(Copy, Clone, Debug, Default)]
struct MemTaint {
    /// Original expected value (for value-sensitive mismatches).
    expected_val: Option<u64>,
    /// Semantic tag for Phase 1 origin reporting.
    tag: TagId,
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
            stop_at_sp_spill: false,
            cancel: None,
            tag_table: None,
            source_tag: TAG_UNTAGGED,
            reg_taint: [false; 256],
            reg_tag: [TAG_UNTAGGED; 256],
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
    pub fn set_stop_at_sp_spill(&mut self, b: bool) { self.stop_at_sp_spill = b; }
    pub fn set_cancel_token(&mut self, token: Arc<AtomicBool>) { self.cancel = Some(token); }

    /// Attach a semantic-origin table. Once set, every subsequent `run`
    /// / `run_with_bytes` call decorates the returned `ResultEntry`s and
    /// boundary report with human-readable tags.
    pub fn set_tag_table(&mut self, table: Arc<TagTable>) { self.tag_table = Some(table); }
    pub fn tag_table(&self) -> Option<&TagTable> { self.tag_table.as_deref() }
    pub fn source_tag(&self) -> TagId { self.source_tag }

    /// Explicitly tag the configured source (e.g. with a `UserSeed`).
    /// Must be called *after* `set_source`.
    pub fn set_source_tag(&mut self, tag: TagId) {
        self.source_tag = tag;
        if !self.source.is_mem {
            let nid = normalize(self.source.reg) as usize;
            if self.reg_taint[nid] {
                self.reg_tag[nid] = tag;
            }
        } else if let Some(cell) = self.tainted_mem.get_mut(&self.source.mem_addr) {
            cell.tag = tag;
        }
    }
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

        self.source_tag = TAG_UNTAGGED;
        self.reg_tag = [TAG_UNTAGGED; 256];
        if source.is_mem {
            self.tainted_mem
                .insert(source.mem_addr, MemTaint::default());
        } else {
            self.taint_reg(source.reg);
        }
    }

    // ───────── forward-mode helpers ─────────

    #[inline]
    fn taint_reg(&mut self, id: RegId) {
        self.taint_reg_with_tag(id, TAG_UNTAGGED);
    }

    #[inline]
    fn taint_reg_with_tag(&mut self, id: RegId, tag: TagId) {
        if id == REG_INVALID || id == REG_XZR {
            return;
        }
        let nid = normalize(id) as usize;
        if !self.reg_taint[nid] {
            self.reg_taint[nid] = true;
            self.tainted_reg_count += 1;
            self.reg_tag[nid] = tag;
        } else {
            self.reg_tag[nid] = self.merge_tag(self.reg_tag[nid], tag);
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
            self.reg_tag[nid] = TAG_UNTAGGED;
        }
    }

    #[inline]
    fn taint_mem(&mut self, addr: u64, val: u64, tag: TagId) {
        let slot = self.tainted_mem.entry(addr).or_default();
        slot.expected_val = Some(val);
        // Merge the new tag with whatever was already labelling this cell.
        if let Some(table) = &self.tag_table {
            slot.tag = merge_tags(table, slot.tag, tag);
        } else if slot.tag == TAG_UNTAGGED {
            slot.tag = tag;
        }
    }

    #[inline]
    fn untaint_mem(&mut self, addr: u64) {
        self.tainted_mem.remove(&addr);
    }

    #[inline]
    fn merge_tag(&self, a: TagId, b: TagId) -> TagId {
        match &self.tag_table {
            Some(table) => merge_tags(table, a, b),
            None => {
                if a == TAG_UNTAGGED {
                    b
                } else {
                    a
                }
            }
        }
    }

    /// Summarise the "is any src tainted, and if so with which tag"
    /// for the given line. Used by propagate arms that need to carry
    /// the upstream tag forward into their dsts.
    fn src_taint_with_tag(&self, line: &TraceLine) -> (bool, TagId) {
        let mut tainted = false;
        let mut tag = TAG_UNTAGGED;
        for i in 0..line.num_src as usize {
            let id = line.src_regs[i];
            if id == REG_INVALID || id == REG_XZR {
                continue;
            }
            let nid = normalize(id) as usize;
            if self.reg_taint[nid] {
                tainted = true;
                tag = self.merge_tag(tag, self.reg_tag[nid]);
            }
        }
        if line.has_mem_read {
            if let Some(mt) = self.tainted_mem.get(&line.mem_read_addr) {
                tainted = true;
                tag = self.merge_tag(tag, mt.tag);
            }
        }
        if line.has_mem_read2 {
            if let Some(mt) = self.tainted_mem.get(&line.mem_read_addr2) {
                tainted = true;
                tag = self.merge_tag(tag, mt.tag);
            }
        }
        (tainted, tag)
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
        let mem_snapshot: Vec<u64> = self.tainted_mem.keys().copied().collect();
        let mem_tags: Vec<(u64, TagId)> = self
            .tainted_mem
            .iter()
            .map(|(&addr, mt)| (addr, mt.tag))
            .collect();
        self.results.push(ResultEntry {
            index,
            reg_snapshot: self.reg_taint,
            mem_snapshot,
            reg_tags: self.reg_tag,
            mem_tags,
        });
    }

    fn check_mem_read_mismatch(&mut self, addr: u64, actual_val: u64, index: usize) {
        if let Some(&MemTaint {
            expected_val: Some(expected),
            ..
        }) = self.tainted_mem.get(&addr)
        {
            if expected != actual_val {
                self.mismatches.push(ValueMismatch {
                    index,
                    mem_addr: addr,
                    expected_val: expected,
                    actual_val,
                });
            }
        }
    }

    fn propagate_forward(&mut self, line: &TraceLine, index: usize) {
        use InsnCategory::*;
        match line.category {
            ImmLoad => {
                for i in 0..line.num_dst as usize {
                    self.untaint_reg(line.dst_regs[i]);
                }
            }
            ExternalCall => {
                // AAPCS64: caller-saved regs clobbered by the call. Anything
                // the caller had tainted in them is *consumed* by the callee.
                // If we had upstream taint going in, the callee's return
                // value is — from our perspective — tainted by that upstream
                // data too (the callee is a black box but its output must
                // depend on its input). We model this by re-tainting x0
                // with the ExternalCall's semantic tag so the downstream
                // taint chain still flows, just labelled.
                let upstream = self.any_caller_saved_tainted();
                let (_, upstream_tag) = self.src_taint_with_tag(line);
                self.untaint_caller_saved();
                if upstream {
                    let ext_tag = self
                        .tag_table
                        .as_ref()
                        .and_then(|t| t.tag_for_ext_call(index as u32))
                        .unwrap_or(TAG_UNTAGGED);
                    let merged = self.merge_tag(upstream_tag, ext_tag);
                    self.taint_reg_with_tag(REG_X0, merged);
                }
            }
            PartialModify => {}
            DataMove | Arithmetic | Logic | ShiftExt | Bitfield => {
                let (src_t, src_tag) = self.src_taint_with_tag(line);
                for i in 0..line.num_dst as usize {
                    if src_t {
                        self.taint_reg_with_tag(line.dst_regs[i], src_tag);
                    } else {
                        self.untaint_reg(line.dst_regs[i]);
                    }
                }
                if line.sets_flags {
                    if src_t {
                        self.taint_reg_with_tag(REG_NZCV, src_tag);
                    } else {
                        self.untaint_reg(REG_NZCV);
                    }
                }
            }
            CondSelect => {
                // csel/csinc/... depends on the chosen srcs AND NZCV.
                let (src_t_data, src_tag_data) = self.src_taint_with_tag(line);
                let nzcv_t = self.is_reg_tainted(REG_NZCV);
                let src_t = src_t_data || nzcv_t;
                let src_tag = if nzcv_t {
                    self.merge_tag(src_tag_data, self.reg_tag[REG_NZCV as usize])
                } else {
                    src_tag_data
                };
                for i in 0..line.num_dst as usize {
                    if src_t {
                        self.taint_reg_with_tag(line.dst_regs[i], src_tag);
                    } else {
                        self.untaint_reg(line.dst_regs[i]);
                    }
                }
                if line.sets_flags {
                    if src_t {
                        self.taint_reg_with_tag(REG_NZCV, src_tag);
                    } else {
                        self.untaint_reg(REG_NZCV);
                    }
                }
            }
            Load => {
                let wb_idx = writeback_dst_idx(line);
                if line.has_mem_read2 && line.num_dst >= 2 {
                    let mt1_slot = line.has_mem_read
                        .then(|| self.tainted_mem.get(&line.mem_read_addr).copied())
                        .flatten();
                    let mt2_slot = self.tainted_mem.get(&line.mem_read_addr2).copied();
                    if let Some(s) = mt1_slot {
                        self.check_mem_read_mismatch(line.mem_read_addr, line.mem_read_val, index);
                        self.taint_reg_with_tag(line.dst_regs[0], s.tag);
                    } else {
                        self.untaint_reg(line.dst_regs[0]);
                    }
                    if let Some(s) = mt2_slot {
                        self.check_mem_read_mismatch(line.mem_read_addr2, line.mem_read_val2, index);
                        self.taint_reg_with_tag(line.dst_regs[1], s.tag);
                    } else {
                        self.untaint_reg(line.dst_regs[1]);
                    }
                } else {
                    let mt_slot = line.has_mem_read
                        .then(|| self.tainted_mem.get(&line.mem_read_addr).copied())
                        .flatten();
                    if mt_slot.is_some() {
                        self.check_mem_read_mismatch(line.mem_read_addr, line.mem_read_val, index);
                    }
                    for i in 0..line.num_dst as usize {
                        if wb_idx == Some(i) {
                            continue; // keep writeback base's taint
                        }
                        if let Some(s) = mt_slot {
                            self.taint_reg_with_tag(line.dst_regs[i], s.tag);
                        } else {
                            self.untaint_reg(line.dst_regs[i]);
                        }
                    }
                }
            }
            Store => {
                if line.has_mem_write {
                    if line.has_mem_write2 && line.num_src >= 2 {
                        let s0 = line.src_regs[0];
                        let s1 = line.src_regs[1];
                        if self.is_reg_tainted(s0) {
                            let tag = self.reg_tag[normalize(s0) as usize];
                            self.taint_mem(line.mem_write_addr, line.mem_write_val, tag);
                        } else {
                            self.untaint_mem(line.mem_write_addr);
                        }
                        if self.is_reg_tainted(s1) {
                            let tag = self.reg_tag[normalize(s1) as usize];
                            self.taint_mem(line.mem_write_addr2, line.mem_write_val2, tag);
                        } else {
                            self.untaint_mem(line.mem_write_addr2);
                        }
                    } else {
                        let s0 = if line.num_src > 0 {
                            line.src_regs[0]
                        } else {
                            REG_INVALID
                        };
                        if line.num_src > 0 && self.is_reg_tainted(s0) {
                            let tag = self.reg_tag[normalize(s0) as usize];
                            self.taint_mem(line.mem_write_addr, line.mem_write_val, tag);
                        } else {
                            self.untaint_mem(line.mem_write_addr);
                        }
                    }
                }
            }
            Compare => {
                let (st, tag) = self.src_taint_with_tag(line);
                if st {
                    self.taint_reg_with_tag(REG_NZCV, tag);
                } else {
                    self.untaint_reg(REG_NZCV);
                }
            }
            Branch => {}
            Other => {
                let (st, tag) = self.src_taint_with_tag(line);
                for i in 0..line.num_dst as usize {
                    if st {
                        self.taint_reg_with_tag(line.dst_regs[i], tag);
                    } else {
                        self.untaint_reg(line.dst_regs[i]);
                    }
                }
                if line.has_mem_write {
                    if st {
                        self.taint_mem(line.mem_write_addr, line.mem_write_val, tag);
                    } else {
                        self.untaint_mem(line.mem_write_addr);
                    }
                }
            }
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancel.as_ref().map(|c| c.load(Ordering::Relaxed)).unwrap_or(false)
    }

    /// Resolve a `TagId` into the short human-readable label via the
    /// installed tag table. Returns `None` when the tag is untagged or no
    /// tag table is present.
    fn tag_label(&self, tag: TagId) -> Option<String> {
        if !tag.is_tagged() {
            return None;
        }
        self.tag_table
            .as_ref()
            .and_then(|t| t.origin(tag))
            .map(|o| o.short_label())
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
                    is_dst, self.max_depth, max_nodes,
                    self.stop_at_sp_spill, &self.cancel,
                );

                if self.is_cancelled() { self.stop_reason = StopReason::Cancelled; return; }

                if truncated {
                    self.stop_reason = StopReason::ScanLimitReached;
                }

                // Phase 2b: rebuild snapshots in correct sequential order
                let (entries, remaining_regs, remaining_mem) =
                    rebuild_snapshots(lines, &visited, &self.source, start_index);
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
                // Resolve mem → TagId via the optional tag table so the
                // boundary report can call out known const / payload
                // regions by name.
                let mem_tags: Vec<(u64, TagId)> = if let Some(table) = &self.tag_table {
                    mems.iter()
                        .map(|&a| (a, table.tag_for_mem(a).unwrap_or(TAG_UNTAGGED)))
                        .collect()
                } else {
                    mems.iter().map(|&a| (a, TAG_UNTAGGED)).collect()
                };
                let reg_tags: Vec<(String, TagId)> =
                    regs.iter().map(|r| (r.clone(), TAG_UNTAGGED)).collect();
                if !regs.is_empty() || !mems.is_empty() {
                    self.remaining_taint_at_boundary = Some(RemainingTaint {
                        regs,
                        mems,
                        reg_tags,
                        mem_tags,
                    });
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
            // Registers, annotated with their tag if any.
            if remaining.regs.is_empty() {
                out.push_str("  寄存器: (无)\n");
            } else {
                out.push_str("  寄存器: ");
                for (i, (r, tag)) in remaining.reg_tags.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(r);
                    if let Some(label) = self.tag_label(*tag) {
                        out.push_str(&format!(" [{}]", label));
                    }
                }
                out.push('\n');
            }
            if !remaining.mems.is_empty() {
                out.push_str("  内存: ");
                for (i, (a, tag)) in remaining.mem_tags.iter().enumerate() {
                    if i > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(&format!("0x{:x}", a));
                    if let Some(label) = self.tag_label(*tag) {
                        out.push_str(&format!(" [{}]", label));
                    }
                }
                out.push('\n');
            }
            // If we have a tag table, list the unique origins touched in
            // this boundary report so the user has a "真正来源" summary.
            if let Some(table) = &self.tag_table {
                let mut tags: Vec<TagId> = remaining
                    .mem_tags
                    .iter()
                    .map(|&(_, t)| t)
                    .chain(remaining.reg_tags.iter().map(|(_, t)| *t))
                    .filter(|t| t.is_tagged())
                    .collect();
                tags.sort_by_key(|t| t.0);
                tags.dedup();
                if !tags.is_empty() {
                    out.push_str("  已知来源:\n");
                    for t in tags {
                        if let Some(o) = table.origin(t) {
                            out.push_str(&format!("    - {}\n", o.long_label()));
                        }
                    }
                }
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
                    let tag = entry.reg_tags[i as usize];
                    if let Some(label) = self.tag_label(tag) {
                        out.push_str(&format!("[{}]", label));
                    }
                    first = false;
                }
            }
            for m in &entry.mem_snapshot {
                if !first { out.push_str(", "); }
                out.push_str(&format!("mem:0x{:x}", m));
                // Resolve tag preferentially from the entry's per-mem tag
                // list; fall back to the tag table for ConstMem / payload.
                let tag = entry
                    .mem_tags
                    .iter()
                    .find_map(|&(a, t)| if a == *m { Some(t) } else { None })
                    .unwrap_or(TAG_UNTAGGED);
                let tag = if tag.is_tagged() {
                    tag
                } else {
                    self.tag_table
                        .as_ref()
                        .and_then(|t| t.tag_for_mem(*m))
                        .unwrap_or(TAG_UNTAGGED)
                };
                if let Some(label) = self.tag_label(tag) {
                    out.push_str(&format!("[{}]", label));
                }
                first = false;
            }
            out.push_str("}\n\n");
        }
        out
    }
}
