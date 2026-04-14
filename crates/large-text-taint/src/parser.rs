//! xgtrace log parser.
//!
//! Operates on raw byte slices (typically an mmap from FileReader). The output
//! retains `file_offset` / `line_len` so the viewer can map results back to
//! their original lines without re-parsing.

use crate::reg::{parse_reg_name, REG_INVALID};
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

/// Which trace format a line looks like. Traces produced by upstream GumTrace
/// (`[module] 0xabs!0xrel mnem ops ; mem_r=... mem_w=...`) inline the snapshot
/// on the same line, while xgtrace (`module.so!offset 0x...: "asm" snap`)
/// emits standalone `MEM R/W` lines for reads/writes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LineFormat {
    Xgtrace,
    Gumtrace,
}

fn detect_line_format(buf: &[u8]) -> Option<LineFormat> {
    if buf.is_empty() {
        return None;
    }
    // GumTrace starts with `[module]`
    if buf[0] == b'[' {
        // must actually close the bracket within a reasonable window to avoid
        // mistaking a `[mem:0x...]` header for an instruction
        let cap = buf.len().min(64);
        if buf[..cap].contains(&b']') {
            return Some(LineFormat::Gumtrace);
        }
    }
    // xgtrace: `.so!` somewhere in the first 64 bytes
    if buf.len() >= 5 {
        let cap = buf.len().min(64);
        let needle = b".so!";
        if cap >= needle.len() {
            for i in 0..=cap - needle.len() {
                if &buf[i..i + needle.len()] == needle {
                    return Some(LineFormat::Xgtrace);
                }
            }
        }
    }
    None
}

fn is_instruction_line(buf: &[u8]) -> bool {
    detect_line_format(buf).is_some()
}

/// Standalone `MEM R/W 0x<addr> [N bytes]: ...` line. Returns (rw, addr).
fn parse_mem_line(buf: &[u8]) -> Option<(u8, u64)> {
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
    Some((rw, parse_hex_safe(&buf[hex_start..k])))
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
            // find newline
            let nl = bytes[i..]
                .iter()
                .position(|&b| b == b'\n')
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
                if let Some((rw, addr)) = parse_mem_line(line) {
                    attach_mem(
                        &mut self.lines[idx],
                        rw,
                        addr,
                        &mut pending_reads,
                        &mut pending_writes,
                    );
                    continue;
                }
            }
            // ignore other lines (`-> libc.so!...`, headers, etc.)
        }
        // flush inference for the final pending instruction
        if let Some(prev) = pending_idx {
            apply_pair_inference(&mut self.lines[prev]);
        }
    }

    /// Parse a single candidate instruction line in isolation (no MEM R/W
    /// follow-up lines are attached). Returns `None` when the line is not an
    /// xgtrace instruction line. Useful for UI previews that need to know
    /// which registers a single line touches without loading the whole file.
    pub fn parse_single_line(bytes: &[u8], line_number: u32, offset: u64) -> Option<TraceLine> {
        let mut tl = TraceLine::default();
        // strip trailing newline/cr so parse_line sees just the content
        let mut end = bytes.len();
        while end > 0 && (bytes[end - 1] == b'\n' || bytes[end - 1] == b'\r') {
            end -= 1;
        }
        if Self::parse_line(&bytes[..end], line_number, offset, &mut tl) {
            Some(tl)
        } else {
            None
        }
    }

    /// Parse one instruction line. Returns true if parsing succeeded.
    fn parse_line(buf: &[u8], line_number: u32, offset: u64, out: &mut TraceLine) -> bool {
        match detect_line_format(buf) {
            Some(LineFormat::Xgtrace) => Self::parse_line_xgtrace(buf, line_number, offset, out),
            Some(LineFormat::Gumtrace) => Self::parse_line_gumtrace(buf, line_number, offset, out),
            None => false,
        }
    }

    fn parse_line_xgtrace(
        buf: &[u8],
        line_number: u32,
        offset: u64,
        out: &mut TraceLine,
    ) -> bool {
        out.line_number = line_number;
        out.file_offset = offset;
        out.line_len = buf.len() as u32;

        // 1) find '!'
        let bang = match buf.iter().position(|&b| b == b'!') {
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

        classify_and_flags(mnem, out);

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

    /// Upstream GumTrace native format:
    ///   `[libtiny.so] 0x76fed9fdc8!0x178dc8 stp x29, x30, [sp, #-0x60]! ; mem_w=0x... regs=...`
    ///   `[libmetasec_ov.so] 0x7984...!0x... ldrsw x19, [x1, #4]; x19=0x... x1=0x... mem_r=0x... -> x19=0x...`
    fn parse_line_gumtrace(
        buf: &[u8],
        line_number: u32,
        offset: u64,
        out: &mut TraceLine,
    ) -> bool {
        out.line_number = line_number;
        out.file_offset = offset;
        out.line_len = buf.len() as u32;

        // 1) skip [module]
        let mut i = 1usize;
        while i < buf.len() && buf[i] != b']' {
            i += 1;
        }
        if i >= buf.len() {
            return false;
        }
        i += 1; // skip ']'
        while i < buf.len() && buf[i] == b' ' {
            i += 1;
        }

        // 2) 0x<abs>!0x<rel>
        if i + 2 >= buf.len() || buf[i] != b'0' || buf[i + 1] != b'x' {
            return false;
        }
        i += 2;
        while i < buf.len() && buf[i] != b'!' {
            i += 1;
        }
        if i >= buf.len() {
            return false;
        }
        i += 1; // skip '!'
        if i + 2 >= buf.len() || buf[i] != b'0' || buf[i + 1] != b'x' {
            return false;
        }
        i += 2;
        let hex_start = i;
        while i < buf.len() && buf[i] != b' ' {
            i += 1;
        }
        out.rel_addr = parse_hex_safe(&buf[hex_start..i]);
        while i < buf.len() && buf[i] == b' ' {
            i += 1;
        }

        // 3) mnemonic
        let mnem_start = i;
        while i < buf.len() && buf[i] != b' ' && buf[i] != b'\t' {
            i += 1;
        }
        let mnem = &buf[mnem_start..i];
        if mnem.is_empty() {
            return false;
        }
        classify_and_flags(mnem, out);

        while i < buf.len() && buf[i] == b' ' {
            i += 1;
        }

        // 4) split operands vs reg_info
        // Preferred delimiter: `; ` on the rest of the line. If absent, split
        // at the first `<word>=0x` pattern that follows the mnemonic.
        let tail = &buf[i..];
        let (ops_slice, info_slice) = split_operands_and_info(tail);

        Self::parse_operands(mnem, ops_slice, out);
        out.pair_reg_size = pair_reg_size_for(mnem, ops_slice);

        // 5) parse mem_r= / mem_w= embedded in the rest of the line
        if !info_slice.is_empty() {
            parse_gumtrace_mem_info(info_slice, out);
        }
        // GumTrace ships the whole snapshot on one line, so inference can be
        // applied immediately.
        apply_pair_inference(out);
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
        }
        let mut operands: [Operand; 8] = std::array::from_fn(|_| Operand {
            start: 0,
            len: 0,
            is_mem: false,
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
                        operands[num_ops] = Operand {
                            start: s,
                            len: e - s,
                            is_mem: mem,
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
                    extract_mem_regs(segment, out);
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
                extract_mem_regs(segment, out);
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

fn extract_mem_regs(segment: &[u8], out: &mut TraceLine) {
    let mut tok = [0u8; 8];
    for j in 0..segment.len() {
        let c = segment[j];
        if c == b'[' || c == b',' || c == b' ' {
            let mut k = j + 1;
            while k < segment.len() && segment[k] == b' ' {
                k += 1;
            }
            if k < segment.len() && segment[k] != b'#' && segment[k] != b']' {
                let n = extract_token(&segment[k..], &mut tok);
                let rid = parse_reg_name(&tok[..n]);
                if rid != REG_INVALID && (out.num_src as usize) < 8 {
                    out.src_regs[out.num_src as usize] = rid;
                    out.num_src += 1;
                }
            }
        }
    }
}

fn classify_and_flags(mnem: &[u8], out: &mut TraceLine) {
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
}

/// For a GumTrace-native line (everything after the mnemonic), separate the
/// operand list from the trailing register snapshot / `mem_r=` / `mem_w=` /
/// `-> reg=...` info.
///
/// Preferred delimiter is `; ` (inserted by GumTrace when there IS a snapshot).
/// When missing we look for the first `<ident>=0x` that is not inside
/// brackets — that marks the start of the snapshot.
fn split_operands_and_info(tail: &[u8]) -> (&[u8], &[u8]) {
    // Try `; ` first.
    for j in 0..tail.len().saturating_sub(1) {
        if tail[j] == b';' && tail[j + 1] == b' ' {
            let ops = trim_trailing_spaces(&tail[..j]);
            return (ops, &tail[j + 2..]);
        }
    }
    // Fallback: find a `<ident>=0x` pattern outside `[...]`.
    let mut bracket = 0i32;
    let mut j = 0usize;
    while j + 2 < tail.len() {
        let c = tail[j];
        if c == b'[' {
            bracket += 1;
        } else if c == b']' {
            bracket -= 1;
        } else if bracket <= 0 && c == b'=' && tail[j + 1] == b'0' && tail[j + 2] == b'x' {
            // rewind to the start of the identifier
            let mut k = j;
            while k > 0 {
                let b = tail[k - 1];
                if b.is_ascii_alphanumeric() || b == b'_' {
                    k -= 1;
                } else {
                    break;
                }
            }
            if k < j {
                let ops = trim_trailing_spaces(&tail[..k]);
                return (ops, &tail[k..]);
            }
        }
        j += 1;
    }
    (trim_trailing_spaces(tail), &[])
}

fn trim_trailing_spaces(s: &[u8]) -> &[u8] {
    let mut end = s.len();
    while end > 0 && (s[end - 1] == b' ' || s[end - 1] == b'\t') {
        end -= 1;
    }
    &s[..end]
}

/// Scan the register snapshot / info tail for `mem_r=0x...` and `mem_w=0x...`
/// patterns. Multiple occurrences feed the second read/write slots.
fn parse_gumtrace_mem_info(info: &[u8], out: &mut TraceLine) {
    let mut reads = 0u8;
    let mut writes = 0u8;
    if out.has_mem_read {
        reads = 1;
    }
    if out.has_mem_read2 {
        reads = 2;
    }
    if out.has_mem_write {
        writes = 1;
    }
    if out.has_mem_write2 {
        writes = 2;
    }
    let mut j = 0usize;
    while j + 8 <= info.len() {
        let rest = &info[j..];
        let is_read = rest.starts_with(b"mem_r=0x");
        let is_write = rest.starts_with(b"mem_w=0x");
        if is_read || is_write {
            let addr_start = j + 8;
            let mut k = addr_start;
            while k < info.len() && info[k].is_ascii_hexdigit() {
                k += 1;
            }
            if k > addr_start {
                let addr = parse_hex_safe(&info[addr_start..k]);
                let rw = if is_read { b'R' } else { b'W' };
                attach_mem(out, rw, addr, &mut reads, &mut writes);
                j = k;
                continue;
            }
        }
        j += 1;
    }
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
/// address was observed. Called after MEM attachment finishes for this line
/// (end of GumTrace parse_line, or right before flushing a xgtrace pending
/// instruction when the next one arrives).
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

fn attach_mem(tl: &mut TraceLine, rw: u8, addr: u64, reads: &mut u8, writes: &mut u8) {
    if rw == b'R' {
        if *reads == 0 {
            tl.has_mem_read = true;
            tl.mem_read_addr = addr;
        } else if *reads == 1 {
            tl.has_mem_read2 = true;
            tl.mem_read_addr2 = addr;
        }
        *reads += 1;
    } else if rw == b'W' {
        if *writes == 0 {
            tl.has_mem_write = true;
            tl.mem_write_addr = addr;
        } else if *writes == 1 {
            tl.has_mem_write2 = true;
            tl.mem_write_addr2 = addr;
        }
        *writes += 1;
    }
}
