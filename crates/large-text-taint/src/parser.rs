//! xgtrace log parser.
//!
//! Operates on raw byte slices (typically an mmap from FileReader). The output
//! retains `file_offset` / `line_len` so the viewer can map results back to
//! their original lines without re-parsing.

use memchr::memchr;
use memchr::memmem;

use crate::reg::{parse_reg_name, RegId, REG_INVALID};
use crate::trace::{classify_mnemonic, InsnCategory, TraceLine};

/// Truncates to the low 64 bits when input has more than 16 hex digits
/// (xgtrace can emit 128-bit Q-register values).
fn parse_hex_safe(s: &[u8]) -> u64 {
    let start = if s.len() > 16 { s.len() - 16 } else { 0 };
    let mut val: u64 = 0;
    for &c in &s[start..] {
        let digit = match c {
            b'0'..=b'9' => (c - b'0') as u64,
            b'a'..=b'f' => (c - b'a' + 10) as u64,
            b'A'..=b'F' => (c - b'A' + 10) as u64,
            _ => break,
        };
        val = (val << 4) | digit;
    }
    val
}

/// xgtrace (QBDI) instruction line — `module.so!offset 0xabs: "asm" snap`.
/// The `.so!` token in the first 64 bytes is the discriminator.
fn is_instruction_line(buf: &[u8]) -> bool {
    if buf.len() < 5 {
        return false;
    }
    let cap = buf.len().min(64);
    memmem::find(&buf[..cap], b".so!").is_some()
}

/// `-> libc.so!malloc(1440) ret: 0x78d7d22d20` 或 `-> libc.so!free`
/// 形式的外部函数调用行。xgtrace 用 `->` 前缀标记"跳到了一个未
/// trace 的外部函数",后面可能带参数和返回值。
fn is_external_call_line(buf: &[u8]) -> bool {
    // 最短形式: "-> x" = 4 bytes
    if buf.len() < 4 {
        return false;
    }
    // 跳过行首空格
    let trimmed = match buf.iter().position(|&b| b != b' ' && b != b'\t') {
        Some(p) => &buf[p..],
        None => return false,
    };
    trimmed.starts_with(b"-> ")
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse the raw byte dump after `]: ` into a little-endian u64 (up to 8 bytes).
fn parse_mem_value(buf: &[u8]) -> u64 {
    let pos = match memmem::find(buf, b"]: ") {
        Some(p) => p + 3,
        None => return 0,
    };
    let mut val: u64 = 0;
    let mut byte_idx: u32 = 0;
    let mut i = pos;
    while i < buf.len() && byte_idx < 8 {
        if buf[i] == b' ' {
            if i + 1 >= buf.len() || buf[i + 1] == b' ' {
                break;
            }
            i += 1;
            continue;
        }
        if i + 1 >= buf.len() {
            break;
        }
        match (hex_val(buf[i]), hex_val(buf[i + 1])) {
            (Some(h), Some(l)) => {
                val |= ((h << 4 | l) as u64) << (byte_idx * 8);
                byte_idx += 1;
                i += 2;
            }
            _ => break,
        }
    }
    val
}

/// Standalone `MEM R/W 0x<addr> [N bytes]: ...` line. Returns (rw, addr, value).
fn parse_mem_line(buf: &[u8]) -> Option<(u8, u64, u64)> {
    if buf.len() < 6 {
        return None;
    }
    if &buf[..3] != b"MEM" || buf[3] != b' ' {
        return None;
    }
    let rw = buf[4];
    if (rw != b'R' && rw != b'W') || buf[5] != b' ' {
        return None;
    }
    let mut k = 6;
    while k < buf.len() && buf[k] == b' ' {
        k += 1;
    }
    if k + 2 > buf.len() || buf[k] != b'0' || buf[k + 1] != b'x' {
        return None;
    }
    k += 2;
    let hex_start = k;
    while k < buf.len() {
        let c = buf[k];
        if c.is_ascii_hexdigit() {
            k += 1;
        } else {
            break;
        }
    }
    if k == hex_start {
        return None;
    }
    let addr = parse_hex_safe(&buf[hex_start..k]);
    let val = parse_mem_value(buf);
    Some((rw, addr, val))
}

/// Extract a leading alphanumeric token (matches C++ extract_token).
fn extract_token(s: &[u8], out: &mut [u8; 8]) -> usize {
    let mut i = 0;
    while i < s.len() && i < out.len() - 1 {
        let c = s[i];
        if c.is_ascii_alphanumeric() {
            out[i] = c;
            i += 1;
        } else {
            break;
        }
    }
    i
}

#[derive(Default)]
pub struct TraceParser {
    lines: Vec<TraceLine>,
}

impl TraceParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn lines(&self) -> &[TraceLine] {
        &self.lines
    }

    pub fn len(&self) -> usize {
        self.lines.len()
    }

    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Parse the entire byte slice. `bytes` is borrowed only for the duration
    /// of the call; nothing is retained, so callers can keep the original
    /// (e.g. an mmap) without paying a copy.
    pub fn load_from_bytes(&mut self, bytes: &[u8]) {
        self.load_range(bytes, u32::MAX, u64::MAX);
    }

    /// Parse `bytes`, stopping when either the next instruction would exceed
    /// `max_line` (1-based input line number) or its starting offset would
    /// exceed `max_offset`. Pass `u32::MAX` / `u64::MAX` for "no limit".
    pub fn load_range(&mut self, bytes: &[u8], max_line: u32, max_offset: u64) {
        self.lines.clear();
        self.lines.reserve(1024);

        let mut line_number: u32 = 0;
        let mut cur_offset: u64 = 0;

        let mut pending_idx: Option<usize> = None;
        let mut pending_reads: u8 = 0;
        let mut pending_writes: u8 = 0;

        let mut i = 0usize;
        while i < bytes.len() {
            if line_number >= max_line || cur_offset > max_offset {
                break;
            }
            let line_start = cur_offset;
            let nl = memchr(b'\n', &bytes[i..])
                .map(|p| i + p)
                .unwrap_or(bytes.len());
            let mut end = nl;
            // strip trailing \r
            if end > i && bytes[end - 1] == b'\r' {
                end -= 1;
            }
            // strip trailing \r left over when the line itself ends with \r without \n
            let raw_end = if nl < bytes.len() { nl + 1 } else { nl };
            let line = &bytes[i..end];
            let raw_len = (raw_end - i) as u64;

            line_number += 1;
            cur_offset += raw_len;

            i = raw_end;

            if line.is_empty() {
                continue;
            }

            // !! `-> libc.so!malloc(...)` 检查必须在 `is_instruction_line`
            // 之前,因为 `->` 行包含 `.so!`(例如 `libc.so!malloc`),
            // 会被 `is_instruction_line` 误判为指令行;`parse_line` 随
            // 后失败 → 行被丢弃 → ExternalCall 永远不生成。
            if is_external_call_line(line) {
                if let Some(prev) = pending_idx {
                    apply_pair_inference(&mut self.lines[prev]);
                }
                let tl = TraceLine {
                    line_number,
                    file_offset: line_start,
                    line_len: line.len() as u32,
                    category: InsnCategory::ExternalCall,
                    dst_regs: [crate::reg::REG_X0, 0, 0, 0],
                    num_dst: 1,
                    ..Default::default()
                };
                self.lines.push(tl);
                pending_idx = None;
                pending_reads = 0;
                pending_writes = 0;
                continue;
            }

            if is_instruction_line(line) {
                // flush inference for the previous pending instruction
                if let Some(prev) = pending_idx {
                    apply_pair_inference(&mut self.lines[prev]);
                }
                let mut tl = TraceLine::default();
                if Self::parse_line(line, line_number, line_start, &mut tl) {
                    self.lines.push(tl);
                    pending_idx = Some(self.lines.len() - 1);
                    pending_reads = 0;
                    pending_writes = 0;
                } else {
                    pending_idx = None;
                }
                continue;
            }

            if let Some(idx) = pending_idx {
                if let Some((rw, addr, val)) = parse_mem_line(line) {
                    attach_mem(
                        &mut self.lines[idx],
                        rw,
                        addr,
                        val,
                        &mut pending_reads,
                        &mut pending_writes,
                    );
                    continue;
                }
            }
        }
        // flush inference for the final pending instruction
        if let Some(prev) = pending_idx {
            apply_pair_inference(&mut self.lines[prev]);
        }
    }

    /// Parse a single candidate instruction line and attach any `MEM R/W`
    /// follow-up lines present in `bytes`. Returns `None` when the first
    /// line isn't a parseable xgtrace instruction.
    ///
    /// Callers that already have a multi-line byte range (e.g. the mmap
    /// window around the clicked line) should pass a slice that starts at
    /// the instruction line and extends a few KB further — the `MEM R/W`
    /// lines that sit below the instruction will be picked up and written
    /// into `mem_read_addr` / `mem_write_addr` / ... on the returned
    /// [`TraceLine`]. Passing just a single-line slice still works but the
    /// memory-operand fields will stay empty, and any UI that relies on
    /// them (e.g. the right-click "trace mem:0x..." menu entry) will miss
    /// the mem targets.
    pub fn parse_single_line(bytes: &[u8], line_number: u32, offset: u64) -> Option<TraceLine> {
        // Run the full parser over the slice so MEM R/W lines following
        // the instruction get attached. We only look at the first parsed
        // instruction; cap to a small line-count so a slice accidentally
        // containing many instructions doesn't waste time.
        let mut p = Self::new();
        p.load_range(bytes, 8, bytes.len() as u64);
        let mut tl = p.lines.into_iter().next()?;
        // Override with the caller-supplied identity so UI code that tracks
        // a specific trace-file line number / byte offset sees consistent
        // values regardless of the slice's internal position.
        tl.line_number = line_number;
        tl.file_offset = offset;
        Some(tl)
    }

    /// Parse one xgtrace instruction line. Returns true on success.
    fn parse_line(buf: &[u8], line_number: u32, offset: u64, out: &mut TraceLine) -> bool {
        out.line_number = line_number;
        out.file_offset = offset;
        out.line_len = buf.len() as u32;

        let bang = match memchr(b'!', buf) {
            Some(p) => p,
            None => return false,
        };
        let mut i = bang + 1;

        // 2) rel_addr: hex until space
        let hex_start = i;
        while i < buf.len() && buf[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i == hex_start {
            return false;
        }
        out.rel_addr = parse_hex_safe(&buf[hex_start..i]);
        while i < buf.len() && buf[i] == b' ' {
            i += 1;
        }

        // 3) skip "0x<abs>:"
        if i + 2 < buf.len() && buf[i] == b'0' && buf[i + 1] == b'x' {
            i += 2;
            while i < buf.len() && buf[i] != b':' && buf[i] != b' ' {
                i += 1;
            }
            if i < buf.len() && buf[i] == b':' {
                i += 1;
            }
        }
        while i < buf.len() && buf[i] == b' ' {
            i += 1;
        }

        // 4) double-quoted asm
        if i >= buf.len() || buf[i] != b'"' {
            return false;
        }
        let asm_start = i + 1;
        let asm_end = match buf[asm_start..].iter().position(|&b| b == b'"') {
            Some(p) => asm_start + p,
            None => return false,
        };

        // 5) trim leading tab/space, read mnemonic
        let mut a = asm_start;
        while a < asm_end && (buf[a] == b' ' || buf[a] == b'\t') {
            a += 1;
        }
        let mnem_start = a;
        while a < asm_end && buf[a] != b' ' && buf[a] != b'\t' {
            a += 1;
        }
        let mnem = &buf[mnem_start..a];
        if mnem.is_empty() {
            return false;
        }

        out.category = classify_mnemonic(mnem);
        if out.category == InsnCategory::Compare {
            out.sets_flags = true;
        } else if mnem.len() >= 4 && *mnem.last().unwrap() == b's' {
            match mnem {
                b"adds" | b"subs" | b"ands" | b"bics" | b"adcs" | b"sbcs" | b"negs" | b"ngcs" => {
                    out.sets_flags = true;
                }
                _ => {}
            }
        }

        // 6) operands
        while a < asm_end && (buf[a] == b' ' || buf[a] == b'\t') {
            a += 1;
        }
        let mut ops_end = asm_end;
        while ops_end > a && (buf[ops_end - 1] == b' ' || buf[ops_end - 1] == b'\t') {
            ops_end -= 1;
        }

        let ops_slice = &buf[a..ops_end];
        Self::parse_operands(mnem, ops_slice, out);
        // xgtrace attaches memory addresses via standalone `MEM R/W` lines;
        // record the hint now, but apply inference later once MEM lines for
        // this instruction have all been seen.
        out.pair_reg_size = pair_reg_size_for(mnem, ops_slice);
        true
    }

    fn parse_operands(mnem: &[u8], ops: &[u8], out: &mut TraceLine) {
        if ops.is_empty() {
            return;
        }
        let is_store = out.category == InsnCategory::Store;
        let is_compare = out.category == InsnCategory::Compare;
        let is_branch = out.category == InsnCategory::Branch;
        let is_ldp = matches!(mnem, b"ldp" | b"ldpsw");
        let is_stp = mnem == b"stp";

        // Split on commas; commas inside [..] are part of one operand.
        struct Operand {
            start: usize,
            len: usize,
            is_mem: bool,
            /// Base register is writeback (pre-index `[reg, #imm]!` or
            /// post-index `[reg], #imm`). Only valid on mem operands.
            writeback: bool,
        }
        let mut operands: [Operand; 8] = std::array::from_fn(|_| Operand {
            start: 0,
            len: 0,
            is_mem: false,
            writeback: false,
        });
        let mut num_ops = 0usize;
        let mut bracket = 0i32;
        let mut seg_start = 0usize;

        let mut i = 0usize;
        while i <= ops.len() && num_ops < 8 {
            let c = if i < ops.len() { ops[i] } else { 0 };
            if c == b'[' {
                bracket += 1;
            }
            if c == b']' {
                bracket -= 1;
            }
            if (c == b',' && bracket == 0) || c == 0 {
                if i > seg_start {
                    let mut s = seg_start;
                    while s < i && (ops[s] == b' ' || ops[s] == b'\t') {
                        s += 1;
                    }
                    let mut e = i;
                    while e > s && (ops[e - 1] == b' ' || ops[e - 1] == b'\t') {
                        e -= 1;
                    }
                    if e > s {
                        let mem = ops[s..e].contains(&b'[');
                        // Pre-index writeback: [reg, #imm]! (trailing '!').
                        let pre_wb = mem && ops[e - 1] == b'!';
                        operands[num_ops] = Operand {
                            start: s,
                            len: e - s,
                            is_mem: mem,
                            writeback: pre_wb,
                        };
                        num_ops += 1;
                    }
                }
                seg_start = i + 1;
            }
            i += 1;
        }

        if num_ops == 0 {
            return;
        }

        // Post-index writeback: a mem operand that is NOT the last operand
        // (e.g. `ldr x0, [x1], #8` or `str x0, [x1], x2`). Only applies to
        // load/store; for other categories a trailing operand after a mem
        // operand would be a shift/extend modifier, not a writeback offset.
        let is_ldst = matches!(
            out.category,
            InsnCategory::Load | InsnCategory::Store
        );
        if is_ldst {
            for (idx, op) in operands.iter_mut().enumerate().take(num_ops) {
                if op.is_mem && !op.writeback && idx + 1 < num_ops {
                    op.writeback = true;
                }
            }
        }

        let mut tok = [0u8; 8];

        if is_branch {
            for op in &operands[..num_ops] {
                let n = extract_token(&ops[op.start..op.start + op.len], &mut tok);
                let rid = parse_reg_name(&tok[..n]);
                if rid != REG_INVALID && (out.num_src as usize) < 8 {
                    out.src_regs[out.num_src as usize] = rid;
                    out.num_src += 1;
                }
            }
            return;
        }

        if is_compare {
            for op in &operands[..num_ops] {
                let segment = &ops[op.start..op.start + op.len];
                if segment[0] == b'#' {
                    continue;
                }
                let n = extract_token(segment, &mut tok);
                let rid = parse_reg_name(&tok[..n]);
                if rid != REG_INVALID && (out.num_src as usize) < 8 {
                    out.src_regs[out.num_src as usize] = rid;
                    out.num_src += 1;
                }
            }
            return;
        }

        if is_store {
            for op in &operands[..num_ops] {
                let segment = &ops[op.start..op.start + op.len];
                if op.is_mem {
                    let base = extract_mem_regs(segment, out);
                    if op.writeback && base != REG_INVALID && (out.num_dst as usize) < 4 {
                        out.dst_regs[out.num_dst as usize] = base;
                        out.num_dst += 1;
                        out.has_writeback_base = true;
                    }
                } else {
                    let n = extract_token(segment, &mut tok);
                    let rid = parse_reg_name(&tok[..n]);
                    if rid != REG_INVALID && (out.num_src as usize) < 8 {
                        out.src_regs[out.num_src as usize] = rid;
                        out.num_src += 1;
                    }
                }
            }
            return;
        }

        // Generic: first (or first two for LDP/STP) is destination, rest are sources.
        for (idx, op) in operands[..num_ops].iter().enumerate() {
            let segment = &ops[op.start..op.start + op.len];
            if op.is_mem {
                let base = extract_mem_regs(segment, out);
                if op.writeback && base != REG_INVALID && (out.num_dst as usize) < 4 {
                    out.dst_regs[out.num_dst as usize] = base;
                    out.num_dst += 1;
                    out.has_writeback_base = true;
                }
                continue;
            }
            if segment[0] == b'#' {
                continue;
            }
            let n = extract_token(segment, &mut tok);
            // shift / extend modifiers
            let toks = &tok[..n];
            if matches!(
                toks,
                b"lsl" | b"lsr" | b"asr" | b"ror" | b"sxtb" | b"sxth" | b"sxtw" | b"sxtx"
                    | b"uxtb" | b"uxth" | b"uxtw" | b"uxtx"
            ) {
                continue;
            }
            let rid = parse_reg_name(toks);
            if rid == REG_INVALID {
                continue;
            }
            let is_dst = idx == 0 || ((is_ldp || is_stp) && idx == 1);
            if is_dst {
                if (out.num_dst as usize) < 4 {
                    out.dst_regs[out.num_dst as usize] = rid;
                    out.num_dst += 1;
                }
            } else if (out.num_src as usize) < 8 {
                out.src_regs[out.num_src as usize] = rid;
                out.num_src += 1;
            }
        }
    }

    pub fn find_by_line(&self, line_number: u32) -> Option<usize> {
        // lines_ is sorted by line_number ascending.
        let mut lo = 0i64;
        let mut hi = self.lines.len() as i64 - 1;
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            let v = self.lines[mid as usize].line_number;
            match v.cmp(&line_number) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid - 1,
                std::cmp::Ordering::Equal => return Some(mid as usize),
            }
        }
        // closest >= line_number
        let lo = lo as usize;
        if lo < self.lines.len() {
            Some(lo)
        } else {
            None
        }
    }

    pub fn find_by_offset(&self, byte_offset: u64) -> Option<usize> {
        let mut lo = 0i64;
        let mut hi = self.lines.len() as i64 - 1;
        while lo <= hi {
            let mid = lo + (hi - lo) / 2;
            let v = self.lines[mid as usize].file_offset;
            match v.cmp(&byte_offset) {
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid - 1,
                std::cmp::Ordering::Equal => return Some(mid as usize),
            }
        }
        let lo = lo as usize;
        if lo < self.lines.len() {
            Some(lo)
        } else {
            None
        }
    }

    pub fn find_by_rel_addr(&self, rel_addr: u64) -> Option<usize> {
        self.lines.iter().position(|l| l.rel_addr == rel_addr)
    }
}

/// Read the original raw text of an instruction line out of a backing byte
/// slice (typically the same buffer that was parsed). Returns an empty string
/// if `tl` points outside `bytes`.
pub fn read_raw_line(bytes: &[u8], tl: &TraceLine) -> String {
    let off = tl.file_offset as usize;
    let len = tl.line_len as usize;
    if off.saturating_add(len) > bytes.len() {
        return String::new();
    }
    String::from_utf8_lossy(&bytes[off..off + len]).into_owned()
}

/// Parse the output value of a specific register from a raw trace line.
///
/// Trace format: `... "asm" REG=val, REG=val => REG=val, REG=val`
///
/// This function finds the `=>` separator and then searches for `REGNAME=0xVAL`
/// in the output section. Returns `None` if the register is not found or the
/// line doesn't have an `=>` section.
///
/// `target_reg` is a normalized register ID (e.g. 27 for x27/w27).
pub fn parse_output_reg_val(raw_line: &[u8], target_reg: crate::reg::RegId) -> Option<u64> {
    // Find "=>" separator
    let arrow_pos = memmem::find(raw_line, b"=>")?;
    let after_arrow = &raw_line[arrow_pos + 2..];
    parse_reg_val_in(after_arrow, target_reg)
}

/// Parse the input value of a specific register from a raw trace line.
///
/// Searches in the section BEFORE `=>` for `REGNAME=0xVAL`.
pub fn parse_input_reg_val(raw_line: &[u8], target_reg: crate::reg::RegId) -> Option<u64> {
    // Find closing quote, then search between quote and "=>"
    let quote_pos = memchr(b'"', raw_line)
        .and_then(|first| memchr(b'"', &raw_line[first + 1..]).map(|p| first + 1 + p))?;
    let after_quote = &raw_line[quote_pos + 1..];
    let arrow_pos = memmem::find(after_quote, b"=>").unwrap_or(after_quote.len());
    let input_section = &after_quote[..arrow_pos];
    parse_reg_val_in(input_section, target_reg)
}

/// Search for `REGNAME=0xVAL` or `REGNAME=VAL` in `section` and return the
/// value if the register matches `target_reg` (after normalization).
fn parse_reg_val_in(section: &[u8], target_reg: crate::reg::RegId) -> Option<u64> {
    let target_norm = crate::reg::normalize(target_reg) as usize;
    let mut i = 0;
    while i < section.len() {
        // Skip to a letter that could start a register name
        if !section[i].is_ascii_alphabetic() {
            i += 1;
            continue;
        }
        // Extract token until '='
        let tok_start = i;
        while i < section.len() && section[i] != b'=' {
            if section[i] == b',' || section[i] == b' ' || section[i] == b'\n' {
                break;
            }
            i += 1;
        }
        if i >= section.len() || section[i] != b'=' {
            i += 1;
            continue;
        }
        let tok = &section[tok_start..i];
        i += 1; // skip '='
        // Skip optional "0x" prefix
        let val_start = if i + 1 < section.len() && section[i] == b'0' && section[i + 1] == b'x' {
            i + 2
        } else {
            i
        };
        // Read hex digits
        let mut val_end = val_start;
        while val_end < section.len() && section[val_end].is_ascii_hexdigit() {
            val_end += 1;
        }
        if val_end == val_start {
            continue;
        }
        // Check if this register matches our target
        let rid = parse_reg_name(tok);
        if rid != crate::reg::REG_INVALID && crate::reg::normalize(rid) as usize == target_norm {
            return Some(parse_hex_safe(&section[val_start..val_end]));
        }
        i = val_end;
    }
    None
}

/// Extract register operands from a `[...]` memory operand segment.
/// Returns the base register (first register found) or `REG_INVALID` if none.
///
/// Only `[` and `,` start a new token; internal whitespace does NOT — the
/// old per-char trigger would double-push on formats like `[x27, x8]`
/// because both `,` and the following space each triggered a fresh
/// extract_token on "x8".
fn extract_mem_regs(segment: &[u8], out: &mut TraceLine) -> RegId {
    let mut base = REG_INVALID;
    let mut tok = [0u8; 8];
    let mut j = 0usize;
    while j < segment.len() {
        let c = segment[j];
        if c == b'[' || c == b',' {
            j += 1;
            while j < segment.len() && (segment[j] == b' ' || segment[j] == b'\t') {
                j += 1;
            }
            if j < segment.len() && segment[j] != b'#' && segment[j] != b']' {
                let n = extract_token(&segment[j..], &mut tok);
                let rid = parse_reg_name(&tok[..n]);
                if rid != REG_INVALID && (out.num_src as usize) < 8 {
                    if base == REG_INVALID {
                        base = rid;
                    }
                    out.src_regs[out.num_src as usize] = rid;
                    out.num_src += 1;
                }
                j += n.max(1);
            }
            // If segment[j] is '#' or ']' or end, fall through — outer
            // while will advance past them.
        } else {
            j += 1;
        }
    }
    base
}

/// Inspect the mnemonic + first operand to decide whether this is a paired
/// memory access (STP/LDP/...). When it is, return the register size in bytes
/// (used later to infer the second memory address if only one is observed).
/// Returns 0 when not a pair instruction.
fn pair_reg_size_for(mnem: &[u8], ops: &[u8]) -> u8 {
    let is_stp = matches!(mnem, b"stp" | b"stxp" | b"stlxp" | b"stnp");
    let is_ldp = matches!(
        mnem,
        b"ldp" | b"ldpsw" | b"ldxp" | b"ldaxp" | b"ldnp"
    );
    if !(is_stp || is_ldp) {
        return 0;
    }
    if ops.is_empty() {
        return 8;
    }
    match ops[0] {
        b'w' | b'W' => 4,
        b's' | b'S' => 4,
        b'd' | b'D' => 8,
        b'q' | b'Q' => 16,
        _ => 8,
    }
}

/// Apply the pair inference recorded on `pair_reg_size` if only one memory
/// address was observed. Called right before flushing a pending xgtrace
/// instruction when the next one arrives (or at EOF).
fn apply_pair_inference(tl: &mut TraceLine) {
    if tl.pair_reg_size == 0 {
        return;
    }
    let size = tl.pair_reg_size as u64;
    // STP family (Store) — infer second write; LDP family (Load) — infer second read.
    match tl.category {
        InsnCategory::Store => {
            if tl.has_mem_write && !tl.has_mem_write2 {
                tl.has_mem_write2 = true;
                tl.mem_write_addr2 = tl.mem_write_addr.wrapping_add(size);
            }
        }
        InsnCategory::Load => {
            if tl.has_mem_read && !tl.has_mem_read2 {
                tl.has_mem_read2 = true;
                tl.mem_read_addr2 = tl.mem_read_addr.wrapping_add(size);
            }
        }
        _ => {}
    }
}

fn attach_mem(tl: &mut TraceLine, rw: u8, addr: u64, val: u64, reads: &mut u8, writes: &mut u8) {
    if rw == b'R' {
        if *reads == 0 {
            tl.has_mem_read = true;
            tl.mem_read_addr = addr;
            tl.mem_read_val = val;
        } else if *reads == 1 {
            tl.has_mem_read2 = true;
            tl.mem_read_addr2 = addr;
            tl.mem_read_val2 = val;
        }
        *reads += 1;
    } else if rw == b'W' {
        if *writes == 0 {
            tl.has_mem_write = true;
            tl.mem_write_addr = addr;
            tl.mem_write_val = val;
        } else if *writes == 1 {
            tl.has_mem_write2 = true;
            tl.mem_write_addr2 = addr;
            tl.mem_write_val2 = val;
        }
        *writes += 1;
    }
}
