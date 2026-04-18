use large_text_taint::engine::{StopReason, TaintEngine, TaintSource, TrackMode};
use large_text_taint::parser::TraceParser;
use large_text_taint::reg::parse_reg_name;
use large_text_taint::trace::InsnCategory;

const FIXTURE: &str = "\
libtiny.so!178dc8 0x76fed9fdc8: \"\tstp\tx29, x30, [sp, #-0x60]!\" FP=0x77ac225ba0, LR=0x2a, SP=0x77ac225b20 => SP=0x77ac225ac0
MEM W 0x77ac225ac0 [8 bytes]: a0 5b 22 ac 77 00 00 00  .[\".w...
MEM W 0x77ac225ac8 [8 bytes]: 2a 00 00 00 00 00 00 00  *.......
libtiny.so!178de0 0x76fed9fde0: \"\tmov\tx29, sp\" SP=0x77ac225ac0 => FP=0x77ac225ac0
libtiny.so!178dec 0x76fed9fdec: \"\tmov\tx19, sp\" SP=0x77ac2226a0 => X19=0x77ac2226a0
libtiny.so!178df0 0x76fed9fdf0: \"\tldr\tx0, [x19, #0x10]\" X19=0x77ac2226a0 => X0=0x12345
MEM R 0x77ac2226b0 [8 bytes]: 45 23 01 00 00 00 00 00  E#......
libtiny.so!178df4 0x76fed9fdf4: \"\tadd\tx1, x0, #0x8\" X0=0x12345 => X1=0x1234d
libtiny.so!178df8 0x76fed9fdf8: \"\tstr\tx1, [x19, #0x20]\" X1=0x1234d, X19=0x77ac2226a0
MEM W 0x77ac2226c0 [8 bytes]: 4d 23 01 00 00 00 00 00  M#......
libtiny.so!178dfc 0x76fed9fdfc: \"\tmov\tx2, #0x0\" => X2=0x0
";

fn parse_fixture() -> TraceParser {
    let mut p = TraceParser::new();
    p.load_from_bytes(FIXTURE.as_bytes());
    p
}

#[test]
fn parses_instruction_lines_and_attaches_mem() {
    let p = parse_fixture();
    let lines = p.lines();
    assert_eq!(lines.len(), 7, "should parse 7 instruction lines");

    // stp: 2 dst (x29, x30 -> normalized fp/lr), 1 src (sp), two MEM W attached
    let stp = &lines[0];
    assert_eq!(stp.category, InsnCategory::Store);
    assert!(stp.has_mem_write && stp.has_mem_write2);
    assert_eq!(stp.mem_write_addr, 0x77ac225ac0);
    assert_eq!(stp.mem_write_addr2, 0x77ac225ac8);

    // ldr: 1 dst (x0), 1 src (x19), MEM R attached
    let ldr = &lines[3];
    assert_eq!(ldr.category, InsnCategory::Load);
    assert_eq!(ldr.num_dst, 1);
    assert_eq!(ldr.dst_regs[0], parse_reg_name(b"x0"));
    assert_eq!(ldr.src_regs[0], parse_reg_name(b"x19"));
    assert!(ldr.has_mem_read);
    assert_eq!(ldr.mem_read_addr, 0x77ac2226b0);

    // add: dst=x1, src=x0, no mem
    let add = &lines[4];
    assert_eq!(add.category, InsnCategory::Arithmetic);
    assert_eq!(add.dst_regs[0], parse_reg_name(b"x1"));
    assert_eq!(add.src_regs[0], parse_reg_name(b"x0"));
    assert!(!add.has_mem_read && !add.has_mem_write);

    // mov #0x0 -> imm load category, no src register
    let mov_imm = &lines[6];
    assert_eq!(mov_imm.category, InsnCategory::DataMove);
    assert_eq!(mov_imm.num_src, 0);
}

#[test]
fn classify_handles_branch_with_dot() {
    let mut p = TraceParser::new();
    p.load_from_bytes(b"libtiny.so!100 0x76fed9f100: \"\tb.eq\t#0x100\"\n");
    assert_eq!(p.lines()[0].category, InsnCategory::Branch);
}

#[test]
fn forward_taints_through_load_and_arith() {
    let p = parse_fixture();
    // Taint the mem the LDR reads -> should propagate into x0 then x1, then into mem written by STR.
    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Forward);
    e.set_source(TaintSource::from_mem(0x77ac2226b0));
    // Start one line BEFORE the ldr — forward only propagates on lines after start_index.
    let ldr_idx = p
        .lines()
        .iter()
        .position(|l| l.category == InsnCategory::Load)
        .unwrap();
    e.run(p.lines(), ldr_idx - 1);

    let results = e.results();
    // start + ldr/add/str all involved -> at least 4 entries (start record + 3 propagations)
    assert!(
        results.len() >= 4,
        "expected at least 4 results, got {}",
        results.len()
    );
    // After STR, the mem 0x77ac2226c0 should be tainted in the last propagation snapshot
    let last = results.last().unwrap();
    assert!(last.mem_snapshot.contains(&0x77ac2226c0));
}

#[test]
fn forward_stops_when_all_taint_cleared() {
    let p = parse_fixture();
    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Forward);
    // Source register that nothing else uses → taint dies immediately on its only def-line being absent.
    e.set_source(TaintSource::from_reg(parse_reg_name(b"x0")));
    // Start from a mov-imm that overwrites x2 (no propagation), forward shouldn't crash.
    let last_idx = p.lines().len() - 1;
    e.run(p.lines(), last_idx);
    // No instructions follow the last index → end-of-trace, exactly one record (start).
    assert_eq!(e.results().len(), 1);
    assert_eq!(e.stop_reason(), StopReason::EndOfTrace);
}

#[test]
fn backward_walks_back_to_source() {
    let p = parse_fixture();
    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Backward);
    // Want to know "where did x1 come from at the str line?"
    e.set_source(TaintSource::from_reg(parse_reg_name(b"x1")));
    let str_idx = p
        .lines()
        .iter()
        .enumerate()
        .filter(|(_, l)| l.category == InsnCategory::Store)
        .last()
        .unwrap()
        .0;
    e.run(p.lines(), str_idx);

    // Should walk back through add (which defined x1) and ldr (which defined x0).
    let categories: Vec<_> = e
        .results()
        .iter()
        .map(|r| p.lines()[r.index].category)
        .collect();
    assert!(categories.contains(&InsnCategory::Arithmetic));
    assert!(categories.contains(&InsnCategory::Load));
}

#[test]
fn xgtrace_stp_infers_second_mem_write_when_only_one_mem_line() {
    // Mimic xgtrace output where the second MEM W line was truncated/missing.
    // Without inference, the engine would drop x30's propagation into memory.
    let fixture = "\
libtiny.so!1000 0x7000: \"\tstp\tx29, x30, [sp]\" SP=0x77aca000
MEM W 0x77aca000 [8 bytes]: a0 5b 22 ac 77 00 00 00  .[\".w...
libtiny.so!1004 0x7004: \"\tmov\tx0, sp\" SP=0x77aca000 => X0=0x77aca000
";
    let mut p = TraceParser::new();
    p.load_from_bytes(fixture.as_bytes());
    let stp = &p.lines()[0];
    assert_eq!(stp.category, InsnCategory::Store);
    assert!(stp.has_mem_write);
    assert_eq!(stp.mem_write_addr, 0x77aca000);
    // Only one MEM W was observed but stp x29,x30 should infer the second.
    assert!(stp.has_mem_write2, "stp with only 1 MEM W should be inferred");
    assert_eq!(stp.mem_write_addr2, 0x77aca008);
}

#[test]
fn xgtrace_stp_keeps_both_observations_when_both_present() {
    // Both MEM W lines present → no inference should overwrite them.
    let p = parse_fixture();
    let stp = &p.lines()[0];
    assert_eq!(stp.mem_write_addr, 0x77ac225ac0);
    assert_eq!(stp.mem_write_addr2, 0x77ac225ac8); // observed, not inferred
}

#[test]
fn format_result_includes_header_and_lines() {
    let p = parse_fixture();
    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Forward);
    e.set_source(TaintSource::from_reg(parse_reg_name(b"x19")));
    e.run(p.lines(), 0);
    let s = e.format_result(p.lines(), FIXTURE.as_bytes());
    assert!(s.starts_with("=== Taint Forward Tracking ==="));
    assert!(s.contains("Source: x19"));
    assert!(s.contains("tainted: {"));
}

/// Backward tracking a Load's destination register follows ONLY the
/// data chain through memory (like GumTrace's original design).
/// Address registers are NOT tracked — that's a separate operation
/// via "向后追踪地址来源".
///
/// When no Store to the memory address exists in the trace, only
/// the ldr itself is in the result (the memory source is reported
/// as a boundary taint).
#[test]
fn backward_load_tracks_data_only() {
    let input = b"\
libtiny.so!71c0a0 0x76ff3430a0: \"\tcsel\tx8, x11, x10, lo\" X11=0x6b0, X10=0x3210, FLAGS=0x80000000 => X8=0x6b0
libtiny.so!71c0a4 0x76ff3430a4: \"\tldr\tx8, [x27, x8]\" X8=0x6b0, X27=0x76ff3bb960 => X8=0x76a00ec25c
MEM R 0x76ff3bc010 [8 bytes]: 5c c2 0e a0 76 00 00 00  v
";
    let mut p = TraceParser::new();
    p.load_from_bytes(input);
    let lines = p.lines();
    assert_eq!(lines.len(), 2);

    let x8 = parse_reg_name(b"x8");
    let mut engine = TaintEngine::new();
    engine.set_mode(TrackMode::Backward);
    engine.set_source(TaintSource::from_reg(x8));
    engine.set_max_scan_distance(1000);
    engine.run_with_bytes(lines, 1, input);

    // No Store to 0x76ff3bc010 → only the ldr itself is hit.
    // csel is NOT included because address registers are not tracked.
    assert_eq!(engine.results().len(), 1, "data-only: only ldr hit");
    assert_eq!(engine.results()[0].index, 1);
}

/// Backward tracking an *address-source register* of a Load using
/// `from_reg_as_source` should skip the Load propagation on the starting
/// line and track the register directly, so that the csel writing x8
/// (used as address offset) is found.
///
/// Scenario (execution order):
///   line 0: csel  x8, x11, x10, lo  → x8 = 0x6b0 (address offset)
///   line 1: ldr   x8, [x27, x8]     → x8 = mem[x27+x8]
///
/// "向后追踪地址来源 x8" from line 1:
///   - skip propagate_backward on ldr, keep x8 tainted
///   - csel writes x8 → hit! propagate to x11, x10
#[test]
fn backward_load_addr_source_tracks_register() {
    let input = b"\
libtiny.so!71c0a0 0x76ff3430a0: \"\tcsel\tx8, x11, x10, lo\" X11=0x6b0, X10=0x3210, FLAGS=0x80000000 => X8=0x6b0
libtiny.so!71c0a4 0x76ff3430a4: \"\tldr\tx8, [x27, x8]\" X8=0x6b0, X27=0x76ff3bb960 => X8=0x76a00ec25c
MEM R 0x76ff3bc010 [8 bytes]: 5c c2 0e a0 76 00 00 00  v
";
    let mut p = TraceParser::new();
    p.load_from_bytes(input);
    let lines = p.lines();
    assert_eq!(lines.len(), 2);

    let x8 = parse_reg_name(b"x8");
    let mut engine = TaintEngine::new();
    engine.set_mode(TrackMode::Backward);
    engine.set_source(TaintSource::from_reg_as_source(x8));
    engine.set_max_scan_distance(1000);
    engine.run(lines, 1);

    let results = engine.results();
    eprintln!("addr-source results: {}", results.len());
    for r in results {
        eprintln!("  hit index={} (line {})", r.index, lines[r.index].line_number);
    }

    assert!(
        results.len() >= 2,
        "addr-source tracking should hit csel + ldr; got {}",
        results.len()
    );
    assert_eq!(results[0].index, 0, "first hit = csel");
    assert_eq!(results[1].index, 1, "second hit = ldr");
}

/// Value-sensitive backward tracking: when the tracked register is
/// overwritten with a DIFFERENT value, those writes should be skipped.
///
///   line 0: mov w8, #0xAA   → x8 = 0xAA (wrong)
///   line 1: mov w8, #0xCC   → x8 = 0xCC (wrong)
///   line 2: mov w8, #0xBB   → x8 = 0xBB (correct)
///   line 3: add x0, x8, x1  → uses x8=0xBB
///
/// Tracking x8=0xBB backward from line 3 should only hit line 2.
#[test]
fn backward_value_sensitive_skips_wrong_values() {
    // Three instructions all write x8, but with different values.
    // Only line 2 writes x8=0xBB which is what we're looking for.
    let input = b"\
libtiny.so!1000 0x70001000: \"\tmov\tw8, #0xAA\" => W8=0xAA
libtiny.so!1004 0x70001004: \"\tmov\tw8, #0xCC\" => W8=0xCC
libtiny.so!1008 0x70001008: \"\tmov\tw8, #0xBB\" => W8=0xBB
libtiny.so!100c 0x7000100c: \"\tadd\tx0, x8, x1\" X8=0xBB, X1=0x10 => X0=0xCB
";
    let mut p = TraceParser::new();
    p.load_from_bytes(input);
    let lines = p.lines();
    assert_eq!(lines.len(), 4);

    let x8 = parse_reg_name(b"x8");

    let no_val_count = {
        let mut e = TaintEngine::new();
        e.set_mode(TrackMode::Backward);
        e.set_source(TaintSource::from_reg(x8));
        e.set_max_scan_distance(1000);
        e.run(lines, 3);
        e.results().len()
    };

    // WITH value-sensitive: from_reg_as_source + expected_val = track x8=0xBB
    let mut engine2 = TaintEngine::new();
    engine2.set_mode(TrackMode::Backward);
    engine2.set_source(TaintSource::from_reg_as_source_with_val(x8, 0xBB));
    engine2.set_max_scan_distance(1000);
    engine2.run_with_bytes(lines, 3, input);

    let results = engine2.results();
    eprintln!("value-sensitive results: {}", results.len());
    for r in results {
        eprintln!("  hit index={} (line {})", r.index, lines[r.index].line_number);
    }
    // Only line 2 (mov w8, #0xBB) should match, plus the starting line
    // Line 0 (0xAA) and line 1 (0xCC) should be skipped
    assert!(
        results.iter().any(|r| r.index == 2),
        "should hit mov w8, #0xBB"
    );
    assert!(
        !results.iter().any(|r| r.index == 0),
        "should NOT hit mov w8, #0xAA"
    );
    assert!(
        !results.iter().any(|r| r.index == 1),
        "should NOT hit mov w8, #0xCC"
    );
    let _ = no_val_count; // suppress unused warning
}

/// Value-sensitive tracking should survive stp/ldp save-restore pairs.
/// When x27 is saved to the stack and restored, the expected value should
/// propagate through: ldp → taint mem → stp → taint x27 with mem_write_val.
/// After the pair, wrong-value writes to x27 should still be skipped.
///
///   line 0: adrp  x27, #0x1000          → x27 = 0xAA (WRONG)
///   line 1: mov   x27, x10              → x27 = 0xBB (correct source)
///   line 2: stp   x28, x27, [sp, #0x10] → save x27=0xBB to stack
///   line 3: adrp  x27, #0x2000          → x27 = 0xCC (clobber in callee)
///   line 4: ldp   x28, x27, [sp, #0x10] → restore x27=0xBB from stack
///   line 5: add   x0, x27, x1           → uses x27=0xBB
#[test]
fn value_sensitive_survives_stp_ldp() {
    let input = b"\
libtiny.so!1000 0x70001000: \"\tadrp\tx27, #0x1000\" => X27=0xAA
libtiny.so!1004 0x70001004: \"\tmov\tx27, x10\" X10=0xBB => X27=0xBB
libtiny.so!1008 0x70001008: \"\tstp\tx28, x27, [sp, #0x10]\" X28=0xDD, X27=0xBB, SP=0x1000
MEM W 0x1010 [8 bytes]: dd 00 00 00 00 00 00 00  ........
MEM W 0x1018 [8 bytes]: bb 00 00 00 00 00 00 00  ........
libtiny.so!100c 0x7000100c: \"\tadrp\tx27, #0x2000\" => X27=0xCC
libtiny.so!1010 0x70001010: \"\tldp\tx28, x27, [sp, #0x10]\" SP=0x1000 => X28=0xDD, X27=0xBB
MEM R 0x1010 [8 bytes]: dd 00 00 00 00 00 00 00  ........
MEM R 0x1018 [8 bytes]: bb 00 00 00 00 00 00 00  ........
libtiny.so!1014 0x70001014: \"\tadd\tx0, x27, x1\" X27=0xBB, X1=0x10 => X0=0xCB
";
    let mut p = TraceParser::new();
    p.load_from_bytes(input);
    let lines = p.lines();
    eprintln!("parsed {} lines", lines.len());
    for (i, tl) in lines.iter().enumerate() {
        eprintln!("  [{}] line {} cat={:?} dst={} src={}", i, tl.line_number,
            tl.category, tl.num_dst, tl.num_src);
    }

    // Track x27=0xBB backward from the add (last instruction)
    let x27 = parse_reg_name(b"x27");
    let mut engine = TaintEngine::new();
    engine.set_mode(TrackMode::Backward);
    engine.set_source(TaintSource::from_reg_as_source_with_val(x27, 0xBB));
    engine.set_max_scan_distance(1000);
    engine.run_with_bytes(lines, lines.len() - 1, input);

    let results = engine.results();
    eprintln!("results: {}", results.len());
    for r in results {
        eprintln!("  hit index={} (line {})", r.index, lines[r.index].line_number);
    }

    // Should hit: add (start), ldp (restore), stp (save), mov (real source)
    // Should NOT hit: adrp x27 #0x1000 (0xAA), adrp x27 #0x2000 (0xCC)
    assert!(
        results.iter().any(|r| r.index == 1),
        "should hit mov x27, x10 (real source)"
    );
    assert!(
        !results.iter().any(|r| r.index == 0),
        "should NOT hit adrp x27 #0x1000 (wrong value 0xAA)"
    );
    assert!(
        !results.iter().any(|r| r.index == 3),
        "should NOT hit adrp x27 #0x2000 (wrong value 0xCC)"
    );
}

// ─────────────── regressions for recent bug fixes ───────────────

/// Pre-index writeback (`stp x29, x30, [sp, #-0x60]!`) must mark `sp` as dst
/// so forward taint sees SP being redefined and backward tracking can chain
/// through it.
#[test]
fn writeback_pre_index_adds_base_as_dst() {
    let mut p = TraceParser::new();
    p.load_from_bytes(
        b"libtiny.so!100 0x76fed9f100: \"\tstp\tx29, x30, [sp, #-0x60]!\" \
          FP=0x0, LR=0x0, SP=0x1000 => SP=0xfa0\n",
    );
    let tl = &p.lines()[0];
    assert!(tl.has_writeback_base, "stp ...]! must set has_writeback_base");
    // Store fixture: sp is the last dst (writeback base).
    assert!(
        (0..tl.num_dst as usize).any(|j| tl.dst_regs[j] == parse_reg_name(b"sp")),
        "sp must be in dst_regs for pre-index stp"
    );
}

/// Post-index writeback (`ldr x0, [x1], #8`) must mark `x1` as dst.
#[test]
fn writeback_post_index_adds_base_as_dst() {
    let mut p = TraceParser::new();
    p.load_from_bytes(
        b"libtiny.so!100 0x76fed9f100: \"\tldr\tx0, [x1], #8\" X1=0x1000 => X0=0x0, X1=0x1008\n",
    );
    let tl = &p.lines()[0];
    assert!(
        tl.has_writeback_base,
        "ldr [x1], #imm must set has_writeback_base"
    );
    // LDR writeback: dst = [x0, x1], x1 (writeback base) is dst[1].
    assert_eq!(tl.num_dst, 2);
    assert_eq!(tl.dst_regs[0], parse_reg_name(b"x0"));
    assert_eq!(tl.dst_regs[1], parse_reg_name(b"x1"));
}

/// Same-reg load without `!` (e.g. `ldr x0, [x0, #8]`) must NOT be flagged as
/// writeback — otherwise the writeback handling would wrongly treat x0 as
/// depending only on itself.
#[test]
fn same_reg_load_without_bang_is_not_writeback() {
    let mut p = TraceParser::new();
    p.load_from_bytes(
        b"libtiny.so!100 0x76fed9f100: \"\tldr\tx0, [x0, #8]\" X0=0x1000 => X0=0x5\n",
    );
    let tl = &p.lines()[0];
    assert!(
        !tl.has_writeback_base,
        "no `!` and no post-index offset — not a writeback"
    );
}

/// Bug 1 regression: backward tracking from a memory source used to return
/// only the start line (mem_preds was never consulted). Now it must chain
/// back to the store that last wrote that address.
#[test]
fn backward_mem_source_chains_to_prior_store() {
    let src = "\
libtiny.so!100 0x76fed9f100: \"\tmov\tx0, #0xabc\" => X0=0xabc\n\
libtiny.so!104 0x76fed9f104: \"\tmov\tx1, sp\" SP=0x2000 => X1=0x2000\n\
libtiny.so!108 0x76fed9f108: \"\tstr\tx0, [x1]\" X0=0xabc, X1=0x2000\n\
MEM W 0x2000 [8 bytes]: bc 0a 00 00 00 00 00 00  ........\n\
libtiny.so!10c 0x76fed9f10c: \"\tldr\tx2, [x1]\" X1=0x2000 => X2=0xabc\n\
MEM R 0x2000 [8 bytes]: bc 0a 00 00 00 00 00 00  ........\n";
    let mut p = TraceParser::new();
    p.load_from_bytes(src.as_bytes());
    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Backward);
    e.set_source(TaintSource::from_mem(0x2000));
    // Start from the ldr (reads mem:0x2000); expect to reach the str.
    let ldr_idx = p.lines().iter().position(|l| l.category == InsnCategory::Load).unwrap();
    e.run(p.lines(), ldr_idx);
    let results = e.results();
    assert!(
        results.len() >= 2,
        "backward mem-source must chain to prior store, got {} entries",
        results.len()
    );
    let str_idx = p.lines().iter().position(|l| l.category == InsnCategory::Store).unwrap();
    assert!(
        results.iter().any(|r| r.index == str_idx),
        "must visit the str that wrote mem:0x2000"
    );
}

/// Bug 3 regression: forward CondSelect must observe NZCV-taint, even when no
/// data-reg src is tainted.
#[test]
fn forward_condselect_follows_nzcv_taint() {
    // `start_index` is only recorded, not propagated; use a nop as the
    // starting anchor so cmp actually runs.
    let src = "\
libtiny.so!0fc 0x76fed9f0fc: \"\tnop\"\n\
libtiny.so!100 0x76fed9f100: \"\tcmp\tx5, x6\" X5=0x1, X6=0x2\n\
libtiny.so!104 0x76fed9f104: \"\tcsel\tx0, x1, x2, eq\" X1=0xaa, X2=0xbb => X0=0xbb\n";
    let mut p = TraceParser::new();
    p.load_from_bytes(src.as_bytes());
    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Forward);
    // Taint x5 so cmp taints NZCV. csel then must taint x0 through NZCV.
    e.set_source(TaintSource::from_reg(parse_reg_name(b"x5")));
    e.run(p.lines(), 0);
    let csel_idx = p.lines().iter().position(|l| l.category == InsnCategory::CondSelect).unwrap();
    let csel_entry = e.results().iter().find(|r| r.index == csel_idx)
        .expect("csel should be recorded as involved");
    let x0_nid = large_text_taint::reg::normalize(parse_reg_name(b"x0")) as usize;
    assert!(
        csel_entry.reg_snapshot[x0_nid],
        "csel must taint x0 when NZCV is tainted"
    );
}

/// Bug 4 regression: ExternalCall must clear LR and q0..q7 (AAPCS64
/// caller-saved).
#[test]
fn external_call_clears_lr_and_q0() {
    use large_text_taint::reg::{normalize, REG_LR, REG_Q0};
    let src = "\
libtiny.so!100 0x76fed9f100: \"\tmov\tx19, x0\" X0=0x1 => X19=0x1\n\
libtiny.so!104 0x76fed9f104: \"\tbl\t#0x200\" => LR=0x108\n\
 -> libc.so!malloc(1024) ret: 0x7800\n\
libtiny.so!108 0x76fed9f108: \"\tmov\tx20, x0\" X0=0x7800 => X20=0x7800\n";
    let mut p = TraceParser::new();
    p.load_from_bytes(src.as_bytes());
    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Forward);
    // Taint LR and q0 — both must be cleared after ExternalCall.
    e.set_source(TaintSource::from_reg(REG_LR));
    e.run(p.lines(), 0);
    // After the external call the LR taint must be gone.
    let last = e.results().last().expect("at least start entry");
    assert!(
        !last.reg_snapshot[normalize(REG_LR) as usize],
        "LR must be cleared by ExternalCall"
    );

    let mut e2 = TaintEngine::new();
    e2.set_mode(TrackMode::Forward);
    e2.set_source(TaintSource::from_reg(REG_Q0));
    e2.run(p.lines(), 0);
    let last2 = e2.results().last().expect("at least start entry");
    assert!(
        !last2.reg_snapshot[normalize(REG_Q0) as usize],
        "q0 must be cleared by ExternalCall"
    );
}
