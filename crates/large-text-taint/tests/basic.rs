use large_text_taint::engine::{StopReason, TaintEngine, TaintSource, TrackMode};
use large_text_taint::parser::TraceParser;
use large_text_taint::reg::parse_reg_name;
use large_text_taint::tag::TaintOrigin;
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

/// Regression: `[x27, x8]` must parse to src = [x27, x8], not
/// [x27, x8, x8]. The old extract_mem_regs triggered on every space
/// between operands, causing the same register to be pushed twice.
#[test]
fn mem_operand_with_space_no_duplicate_src() {
    let mut p = TraceParser::new();
    p.load_from_bytes(
        b"libtiny.so!100 0x76fed9f100: \"\tldr\tx8, [x27, x8]\" X27=0x1000, X8=0x10 => X8=0x5\n",
    );
    let tl = &p.lines()[0];
    assert_eq!(tl.num_src, 2, "src regs should be [x27, x8] (no duplicate)");
    assert_eq!(tl.src_regs[0], parse_reg_name(b"x27"));
    assert_eq!(tl.src_regs[1], parse_reg_name(b"x8"));
    assert_eq!(
        tl.mem_base_reg,
        parse_reg_name(b"x27"),
        "mem base is the first register inside the brackets"
    );
}

/// Regression: SP-relative memory operands must set mem_base_reg to sp
/// so the engine can recognise stack-spill slots.
#[test]
fn sp_relative_store_sets_mem_base_to_sp() {
    let mut p = TraceParser::new();
    p.load_from_bytes(
        b"libtiny.so!100 0x76fed9f100: \"\tstr\tx2, [sp, #0x60]\" X2=0x123, SP=0x1000\n\
MEM W 0x1060 [8 bytes]: 23 01 00 00 00 00 00 00  ........\n",
    );
    let tl = &p.lines()[0];
    assert_eq!(tl.mem_base_reg, large_text_taint::reg::REG_SP);
}

/// Regression (bug reported at line 7658469 of the xhs xgtrace): address-
/// source backward tracing used to chase writers of SP-relative slots,
/// turning the result into a 64-depth spill-reload loop of unrelated
/// registers. With `stop_at_sp_spill` on, the trace stops at the spill
/// boundary and records the slot as a boundary mem-taint.
#[test]
fn stop_at_sp_spill_prevents_stack_chasing() {
    // Scenario:
    //   str x9, [sp, #0x60]          (line 0 — sets up spill slot)
    //   ... unrelated code ...
    //   ldr x11, [sp, #0x60]         (line 2 — reload into x11)
    //   ldr x8,  [x27, x11]          (line 3 — uses x11 as address index)
    // Address-source backward tracing from `x11` on line 3 should:
    //   - stop_at_sp_spill ON  → NOT visit line 0 (str x9, [sp, #0x60])
    //   - stop_at_sp_spill OFF → DO  visit line 0 (old behaviour)
    let src = "\
libtiny.so!100 0x76fed9f100: \"\tstr\tx9, [sp, #0x60]\" X9=0x99, SP=0x1000\n\
MEM W 0x1060 [8 bytes]: 99 00 00 00 00 00 00 00  ........\n\
libtiny.so!104 0x76fed9f104: \"\tmov\tx0, x0\" X0=0x0 => X0=0x0\n\
libtiny.so!108 0x76fed9f108: \"\tldr\tx11, [sp, #0x60]\" SP=0x1000 => X11=0x99\n\
MEM R 0x1060 [8 bytes]: 99 00 00 00 00 00 00 00  ........\n\
libtiny.so!10c 0x76fed9f10c: \"\tldr\tx8, [x27, x11]\" X27=0x2000, X11=0x99 => X8=0x1\n\
MEM R 0x2099 [8 bytes]: 01 00 00 00 00 00 00 00  ........\n";
    let mut p = TraceParser::new();
    p.load_from_bytes(src.as_bytes());
    let ldr_x8_idx = p
        .lines()
        .iter()
        .rposition(|l| l.category == InsnCategory::Load)
        .unwrap();
    let str_spill_idx = p
        .lines()
        .iter()
        .position(|l| l.category == InsnCategory::Store)
        .unwrap();
    let x11 = parse_reg_name(b"x11");

    // OFF: the old behaviour — str x9 (the spill writer) shows up.
    {
        let mut e = TaintEngine::new();
        e.set_mode(TrackMode::Backward);
        e.set_source(TaintSource::from_reg_as_source(x11));
        e.run(p.lines(), ldr_x8_idx);
        assert!(
            e.results().iter().any(|r| r.index == str_spill_idx),
            "without stop_at_sp_spill the str x9 spill writer must be reached"
        );
    }

    // ON: the new behaviour — do NOT cross into the spill writer.
    {
        let mut e = TaintEngine::new();
        e.set_mode(TrackMode::Backward);
        e.set_source(TaintSource::from_reg_as_source(x11));
        e.set_stop_at_sp_spill(true);
        e.run(p.lines(), ldr_x8_idx);
        assert!(
            !e.results().iter().any(|r| r.index == str_spill_idx),
            "stop_at_sp_spill must not chase into the sp-relative spill writer"
        );
        // The spill slot surfaces as a boundary taint instead.
        let rem = e.remaining_taint().expect("should report boundary taint");
        assert!(
            rem.mems.contains(&0x1060),
            "spill slot address must appear in boundary mems"
        );
    }
}

/// Regression: the start-line entry's snapshot in backward mode must
/// show the SOURCE register (what the user clicked), not the boundary
/// pre-image. Forward mode records each entry after propagation (dst
/// side); backward must match that directionality, otherwise the user
/// clicks x8 and sees `{mem:0x...}` on the start line with no x8 at
/// all — confusing and reported as a bug.
#[test]
fn backward_start_entry_snapshot_shows_source_register() {
    // ldr x0 reads mem:0x2000. Tracing x0 backward from that ldr, the
    // start line's snapshot must contain x0 — not just mem:0x2000.
    let src = "\
libtiny.so!100 0x76fed9f100: \"\tmov\tx1, sp\" SP=0x2000 => X1=0x2000\n\
libtiny.so!104 0x76fed9f104: \"\tldr\tx0, [x1]\" X1=0x2000 => X0=0x5\n\
MEM R 0x2000 [8 bytes]: 05 00 00 00 00 00 00 00  ........\n";
    let mut p = TraceParser::new();
    p.load_from_bytes(src.as_bytes());
    let ldr_idx = p.lines().iter().position(|l| l.category == InsnCategory::Load).unwrap();

    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Backward);
    e.set_source(TaintSource::from_reg(parse_reg_name(b"x0")));
    e.run(p.lines(), ldr_idx);
    let start_entry = e
        .results()
        .iter()
        .find(|r| r.index == ldr_idx)
        .expect("start line should be in results");
    let x0_nid = large_text_taint::reg::normalize(parse_reg_name(b"x0")) as usize;
    assert!(
        start_entry.reg_snapshot[x0_nid],
        "backward start-line snapshot must contain the source register x0"
    );
    // mem:0x2000 is the pre-image (boundary); it must surface in
    // remaining_taint, not leak into the start-line snapshot.
    assert!(
        !start_entry.mem_snapshot.contains(&0x2000),
        "start-line snapshot must not contain the boundary mem address"
    );
    let rem = e.remaining_taint().expect("should have boundary taint");
    assert!(rem.mems.contains(&0x2000), "boundary taint must carry mem:0x2000");
}

// ─────────── Phase 1 semantic-tag regressions ───────────

const PHASE1_FIXTURE: &str = "\
libtiny.so!0fc 0x76fed9f0fc: \"\tmov\tx19, x0\" X0=0x100 => X19=0x100\n\
 -> libc.so!rand() ret: 0xdeadbeef\n\
libtiny.so!104 0x76fed9f104: \"\tmov\tx1, x0\" X0=0xdeadbeef => X1=0xdeadbeef\n\
libtiny.so!108 0x76fed9f108: \"\tldr\tx2, [x8]\" X8=0x2000 => X2=0x41\n\
MEM R 0x2000 [8 bytes]: 41 00 00 00 00 00 00 00  A.......\n\
 -> libc.so!free(0x3000=\"phone=15965566655\") ret: 0x0\n\
libtiny.so!10c 0x76fed9f10c: \"\tldr\tx3, [x5]\" X5=0x3000 => X3=0x313539\n\
MEM R 0x3000 [8 bytes]: 31 35 39 36 35 35 36 36  15965566\n\
";

#[test]
fn tag_table_detects_external_call_ret() {
    let mut p = TraceParser::new();
    p.load_from_bytes(PHASE1_FIXTURE.as_bytes());
    let table = p.build_tag_table(PHASE1_FIXTURE.as_bytes());

    // Walk every origin and collect ExternalCall callees.
    let callees: Vec<String> = table
        .iter_origins()
        .filter_map(|(_, o)| match o {
            TaintOrigin::ExternalCallRet { callee, .. } => Some(callee.clone()),
            _ => None,
        })
        .collect();
    assert!(
        callees.iter().any(|c| c == "libc.so!rand"),
        "rand should be tagged as an external call; got: {:?}",
        callees
    );
    assert!(
        callees.iter().any(|c| c == "libc.so!free"),
        "free should be tagged; got: {:?}",
        callees
    );
}

#[test]
fn tag_table_extracts_payload_content() {
    let mut p = TraceParser::new();
    p.load_from_bytes(PHASE1_FIXTURE.as_bytes());
    let table = p.build_tag_table(PHASE1_FIXTURE.as_bytes());

    // PayloadByte range [0x3000, 0x3000 + len) must be registered and the
    // lookup must succeed on an address inside it.
    let tag = table
        .tag_for_mem(0x3000)
        .expect("payload address 0x3000 should be tagged");
    match table.origin(tag).expect("tag must resolve") {
        TaintOrigin::PayloadByte {
            addr_lo,
            content_preview,
            ..
        } => {
            assert_eq!(*addr_lo, 0x3000);
            assert!(
                content_preview.starts_with(b"phone="),
                "payload content should start with 'phone=', got {:?}",
                String::from_utf8_lossy(content_preview)
            );
        }
        other => panic!("expected PayloadByte, got {:?}", other),
    }
}

#[test]
fn tag_table_detects_const_mem() {
    let mut p = TraceParser::new();
    p.load_from_bytes(PHASE1_FIXTURE.as_bytes());
    let table = p.build_tag_table(PHASE1_FIXTURE.as_bytes());

    // 0x2000 is read once via `ldr x2, [x8]` and never written in the
    // fixture → must appear as a ConstMem range.
    let tag = table
        .tag_for_mem(0x2000)
        .expect("0x2000 should be const-tagged");
    assert!(matches!(
        table.origin(tag).unwrap(),
        TaintOrigin::ConstMem { .. }
    ));
}

#[test]
fn external_call_x0_gets_tag_when_upstream_tainted() {
    // Trace: x0 is tainted (source), enters bl foo (ExternalCall). After
    // the call x0 should still be tainted AND carry the ExternalCallRet
    // tag, because the callee consumed our upstream taint and its return
    // value carries that input's semantics forward.
    let fixture = "\
libtiny.so!100 0x76fed9f100: \"\tmov\tx0, x9\" X9=0x1 => X0=0x1\n\
 -> libc.so!rand() ret: 0xdeadbeef\n\
libtiny.so!108 0x76fed9f108: \"\tmov\tx2, x0\" X0=0xdeadbeef => X2=0xdeadbeef\n\
";
    let mut p = TraceParser::new();
    p.load_from_bytes(fixture.as_bytes());
    let table = std::sync::Arc::new(p.build_tag_table(fixture.as_bytes()));

    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Forward);
    e.set_source(TaintSource::from_reg(parse_reg_name(b"x9")));
    e.set_tag_table(table.clone());
    e.run(p.lines(), 0);

    // Find the ExternalCall entry in results.
    let ext_idx = p
        .lines()
        .iter()
        .position(|l| l.category == InsnCategory::ExternalCall)
        .unwrap();
    let ext_entry = e
        .results()
        .iter()
        .find(|r| r.index == ext_idx)
        .expect("external call should be recorded (upstream taint flowed in)");
    let x0_nid = large_text_taint::reg::normalize(parse_reg_name(b"x0")) as usize;
    assert!(
        ext_entry.reg_snapshot[x0_nid],
        "x0 must be re-tainted after the ExternalCall"
    );
    let tag = ext_entry.reg_tags[x0_nid];
    assert!(
        tag.is_tagged(),
        "x0 must carry an ExternalCallRet tag after the call"
    );
    match table.origin(tag).unwrap() {
        TaintOrigin::ExternalCallRet { callee, .. } => {
            assert_eq!(callee, "libc.so!rand");
        }
        other => panic!("expected ExternalCallRet on x0, got {:?}", other),
    }
}

/// Row-scoped snapshots: every backward result row must expose ONLY the
/// dst/mem-write this instruction contributes to the downstream chain
/// — not the engine's full active set at the time of rebuild. Without
/// this rule, unrelated upstream registers (e.g. `x2` loaded 60 rows
/// earlier) would cling to every intermediate row's taint set.
#[test]
fn backward_snapshot_is_row_scoped_not_global() {
    // Chain (all data-flow via mov; no loads, so the "Load doesn't follow
    // address registers" rule can't prune us out):
    //   ldr x2, [x9]               ← x2 loaded from unrelated mem (decoy)
    //   mov x10, x9                ← x10 = x9
    //   mov x3, x10                ← x3 = x10
    //   mov x4, x3                 ← x4 = x3
    //   mov w11, #0x1              ← unrelated imm load; dead branch
    //   mov x0, x4                 ← final consumer — trace x0 backward
    // Tracing x0 backward:
    //   - chain: mov x0 → mov x4 → mov x3 → mov x10 → (x9 boundary)
    //   - x2 must NOT appear on any row; the ldr x2 decoy is pruned.
    //   - each row's snapshot must be EXACTLY {dst}, not {dst, src, ...}.
    let src = "\
libtiny.so!100 0x76fed9f100: \"\tldr\tx2, [x9]\" X9=0x5000 => X2=0xdead\n\
MEM R 0x5000 [8 bytes]: ad de 00 00 00 00 00 00  ........\n\
libtiny.so!104 0x76fed9f104: \"\tmov\tx10, x9\" X9=0x5000 => X10=0x5000\n\
libtiny.so!108 0x76fed9f108: \"\tmov\tx3, x10\" X10=0x5000 => X3=0x5000\n\
libtiny.so!10c 0x76fed9f10c: \"\tmov\tx4, x3\" X3=0x5000 => X4=0x5000\n\
libtiny.so!110 0x76fed9f110: \"\tmov\tw11, #0x1\" => W11=0x1\n\
libtiny.so!114 0x76fed9f114: \"\tmov\tx0, x4\" X4=0x5000 => X0=0x5000\n\
";
    let mut p = TraceParser::new();
    p.load_from_bytes(src.as_bytes());
    let start_idx = p
        .lines()
        .iter()
        .rposition(|l| l.num_dst >= 1 && l.dst_regs[0] == parse_reg_name(b"x0"))
        .unwrap();

    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Backward);
    e.set_source(TaintSource::from_reg(parse_reg_name(b"x0")));
    e.run(p.lines(), start_idx);

    let x0 = large_text_taint::reg::normalize(parse_reg_name(b"x0")) as usize;
    let x2 = large_text_taint::reg::normalize(parse_reg_name(b"x2")) as usize;
    let x3 = large_text_taint::reg::normalize(parse_reg_name(b"x3")) as usize;
    let x4 = large_text_taint::reg::normalize(parse_reg_name(b"x4")) as usize;
    let x10 = large_text_taint::reg::normalize(parse_reg_name(b"x10")) as usize;
    let x11 = large_text_taint::reg::normalize(parse_reg_name(b"x11")) as usize;

    // Which rows ended up in the result?
    // Each row's snapshot must equal EXACTLY the set we expect (row-scoped).
    let mut by_line: std::collections::HashMap<u32, &large_text_taint::engine::ResultEntry> =
        std::collections::HashMap::new();
    for r in e.results() {
        let tl = &p.lines()[r.index];
        by_line.insert(tl.line_number, r);
    }

    // The x2-decoy line must be pruned entirely (x2 is unrelated to x0).
    assert!(
        !by_line.iter().any(|(_, r)| r.reg_snapshot[x2]),
        "x2 is a decoy and must never appear in any row's taint set"
    );

    // Start line: mov x0, x4 — snapshot must contain x0 (the source).
    let start_row = by_line
        .iter()
        .find_map(|(_, r)| {
            if r.index == start_idx {
                Some(*r)
            } else {
                None
            }
        })
        .expect("start line should be present");
    assert!(start_row.reg_snapshot[x0], "start row must show x0");
    assert!(
        !start_row.reg_snapshot[x4],
        "start row must NOT carry x4 (x4 is a src here, not produced)"
    );

    // mov x4, x3 — row snapshot must be exactly {x4, x3} (dst + src)
    let mov_x4 = by_line
        .values()
        .find(|r| {
            let tl = &p.lines()[r.index];
            tl.num_dst >= 1 && tl.dst_regs[0] == parse_reg_name(b"x4")
        })
        .expect("mov x4, x3 row expected");
    assert!(mov_x4.reg_snapshot[x4], "mov x4 row must contain x4 (dst)");
    assert!(mov_x4.reg_snapshot[x3], "mov x4 row must contain x3 (src feeding x4)");
    assert!(!mov_x4.reg_snapshot[x0], "mov x4 row must NOT carry x0 downstream");

    // mov x3, x10 — row snapshot must be exactly {x3, x10}
    let mov_x3 = by_line
        .values()
        .find(|r| {
            let tl = &p.lines()[r.index];
            tl.num_dst >= 1 && tl.dst_regs[0] == parse_reg_name(b"x3")
        })
        .expect("mov x3, x10 row expected");
    assert!(mov_x3.reg_snapshot[x3], "mov x3 row must contain x3 (dst)");
    assert!(
        mov_x3.reg_snapshot[x10],
        "mov x3 row must contain x10 (src feeding x3)"
    );
    assert!(
        !mov_x3.reg_snapshot[x4],
        "mov x3 row must NOT carry x4 from the overall active set"
    );

    // The unrelated mov w11, #1 line must be pruned (not in results).
    assert!(
        !by_line.iter().any(|(_, r)| r.reg_snapshot[x11]),
        "unrelated mov w11 row must not appear — nothing downstream uses w11"
    );
}

#[test]
fn boundary_report_lists_named_origins_for_const_mem() {
    // Backward from a register that was last defined by a Load from a
    // never-written address. The boundary should surface both the
    // memory address AND its ConstMem tag so the report is self-
    // explanatory.
    let fixture = "\
libtiny.so!100 0x76fed9f100: \"\tmov\tx5, x8\" X8=0x2000 => X5=0x2000\n\
libtiny.so!104 0x76fed9f104: \"\tldr\tx0, [x5]\" X5=0x2000 => X0=0xaa\n\
MEM R 0x2000 [8 bytes]: aa 00 00 00 00 00 00 00  ........\n\
";
    let mut p = TraceParser::new();
    p.load_from_bytes(fixture.as_bytes());
    let table = std::sync::Arc::new(p.build_tag_table(fixture.as_bytes()));

    let ldr_idx = p
        .lines()
        .iter()
        .position(|l| l.category == InsnCategory::Load)
        .unwrap();

    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Backward);
    e.set_source(TaintSource::from_reg(parse_reg_name(b"x0")));
    e.set_tag_table(table.clone());
    e.run(p.lines(), ldr_idx);

    let rem = e
        .remaining_taint()
        .expect("boundary taint expected when load's mem is rodata");
    assert!(rem.mems.contains(&0x2000));
    let (_, tag) = rem
        .mem_tags
        .iter()
        .find(|&&(a, _)| a == 0x2000)
        .expect("mem_tags must include 0x2000");
    assert!(tag.is_tagged(), "boundary mem must carry ConstMem tag");
    assert!(matches!(
        table.origin(*tag).unwrap(),
        TaintOrigin::ConstMem { .. }
    ));
}

/// Regression: in address-source (skip_start_propagation) mode,
/// rebuild_snapshots must not run Load/Store propagation on the start
/// line itself. Otherwise the start line's own mem_read_addr would leak
/// into the boundary taint, making the report misleading.
#[test]
fn rebuild_skips_start_line_propagate_for_address_source() {
    let src = "\
libtiny.so!100 0x76fed9f100: \"\tmov\tx8, #0x10\" => X8=0x10\n\
libtiny.so!104 0x76fed9f104: \"\tldr\tx8, [x27, x8]\" X27=0x2000, X8=0x10 => X8=0xabc\n\
MEM R 0x2010 [8 bytes]: bc 0a 00 00 00 00 00 00  ........\n";
    let mut p = TraceParser::new();
    p.load_from_bytes(src.as_bytes());
    let ldr_idx = p
        .lines()
        .iter()
        .position(|l| l.category == InsnCategory::Load)
        .unwrap();

    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Backward);
    e.set_source(TaintSource::from_reg_as_source(parse_reg_name(b"x8")));
    e.run(p.lines(), ldr_idx);

    // Start line (ldr) reads mem:0x2010 — but we're tracing x8's source,
    // not x8's data, so 0x2010 must NOT appear as a boundary mem.
    if let Some(rem) = e.remaining_taint() {
        assert!(
            !rem.mems.contains(&0x2010),
            "start line's mem_read must not leak into address-source boundary"
        );
    }
}
