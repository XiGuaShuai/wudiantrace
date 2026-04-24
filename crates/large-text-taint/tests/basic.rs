use large_text_taint::engine::{MemRange, StopReason, TaintEngine, TaintSource, TrackMode};
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
fn parses_current_xgtrace_register_display_format() {
    let fixture = "\
libtiny.so!178e08 0x7ac2d9ae08: \"\tmov\tw9, #0x5f30\" => X9=0x5f30
libtiny.so!178e0c 0x7ac2d9ae0c: \"\tadd\tx10, x10, w11, sxtw\" X10=0x7ac6aee6a8, X11=0xfc2c8270 => X10=0x7ac2db6918
libtiny.so!178df8 0x7ac2d9adf8: \"\tmrs\tx8, TPIDR_EL0\" => X8=0x7b70e35000
libtiny.so!543644 0x7ac3165644: \"\tushr\tv1.2s, v0.2s, #0x11\" Q0=0x80000000 => Q1=0x4000
libtiny.so!543630 0x7ac3165630: \"\tldur\td0, [x20, #-0x8]\" X20=0x7b70e25850 => Q0=0x0
MEM R 0x7b70e25848 [8 bytes]: 00 00 00 00 00 00 00 00  ........
";
    let mut p = TraceParser::new();
    p.load_from_bytes(fixture.as_bytes());
    let lines = p.lines();
    assert_eq!(lines.len(), 5);

    let mov_w = &lines[0];
    assert_eq!(mov_w.dst_regs[0], parse_reg_name(b"x9"));
    assert_eq!(mov_w.num_src, 0);

    let add_sxtw = &lines[1];
    assert_eq!(add_sxtw.dst_regs[0], parse_reg_name(b"x10"));
    assert_eq!(add_sxtw.src_regs[0], parse_reg_name(b"x10"));
    assert_eq!(add_sxtw.src_regs[1], parse_reg_name(b"x11"));

    let mrs = &lines[2];
    assert_eq!(mrs.dst_regs[0], parse_reg_name(b"x8"));
    assert_eq!(mrs.num_src, 0);

    let ushr = &lines[3];
    assert_eq!(ushr.dst_regs[0], parse_reg_name(b"q1"));
    assert_eq!(ushr.src_regs[0], parse_reg_name(b"q0"));

    let ldur_d = &lines[4];
    assert_eq!(
        large_text_taint::reg::normalize(ldur_d.dst_regs[0]),
        parse_reg_name(b"q0")
    );
    assert_eq!(ldur_d.src_regs[0], parse_reg_name(b"x20"));
    assert!(ldur_d.has_mem_read);
}

#[test]
fn parse_register_aliases_used_by_xgtrace_ui() {
    assert_eq!(parse_reg_name(b"FLAGS"), parse_reg_name(b"nzcv"));
    assert_eq!(parse_reg_name(b"NZCV"), parse_reg_name(b"nzcv"));
    assert_eq!(parse_reg_name(b"SP"), parse_reg_name(b"sp"));
    assert_eq!(parse_reg_name(b"LR"), parse_reg_name(b"lr"));
    assert_eq!(
        large_text_taint::reg::normalize(parse_reg_name(b"D0")),
        parse_reg_name(b"q0")
    );
    assert_eq!(
        large_text_taint::reg::normalize(parse_reg_name(b"S31")),
        parse_reg_name(b"q31")
    );
}

#[test]
fn forward_store_tracks_full_mem_range() {
    let fixture = "\
libtiny.so!1000 0x7000: \"\tnop\"
libtiny.so!1004 0x7004: \"\tstr\tq0, [x19]\" Q0=0x100f0e0d0c0b0a090807060504030201, X19=0x0000000000001000
MEM W 0x1000 [16 bytes]: 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10  ................
";
    let mut p = TraceParser::new();
    p.load_from_bytes(fixture.as_bytes());

    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Forward);
    e.set_source(TaintSource::from_reg(parse_reg_name(b"q0")));
    e.run(p.lines(), 0);

    let last = e.results().last().unwrap();
    assert!(last.mem_snapshot.contains(&MemRange::new(0x1000, 16)));
}

#[test]
fn backward_store_from_inner_mem_range_taints_source_reg() {
    let fixture = "\
libtiny.so!1004 0x7004: \"\tstr\tq0, [x19]\" Q0=0x100f0e0d0c0b0a090807060504030201, X19=0x0000000000001000
MEM W 0x1000 [16 bytes]: 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10  ................
";
    let mut p = TraceParser::new();
    p.load_from_bytes(fixture.as_bytes());

    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Backward);
    e.set_source(TaintSource::from_mem(0x100f));
    e.run(p.lines(), 0);

    let last = e.results().last().unwrap();
    assert!(last.reg_snapshot[parse_reg_name(b"q0") as usize]);
}

#[test]
fn backward_load_taints_mem_read_range() {
    let fixture = "\
libtiny.so!1004 0x7004: \"\tldr\tq0, [x19]\" X19=0x0000000000002000 => Q0=0x100f0e0d0c0b0a090807060504030201
MEM R 0x2000 [16 bytes]: 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10  ................
";
    let mut p = TraceParser::new();
    p.load_from_bytes(fixture.as_bytes());

    let mut e = TaintEngine::new();
    e.set_mode(TrackMode::Backward);
    e.set_source(TaintSource::from_reg(parse_reg_name(b"q0")));
    e.run(p.lines(), 0);

    let last = e.results().last().unwrap();
    assert!(last.mem_snapshot.contains(&MemRange::new(0x2000, 16)));
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
    assert!(last
        .mem_snapshot
        .iter()
        .any(|range| range.overlaps(MemRange::new(0x77ac2226c0, 8))));
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
    assert!(
        stp.has_mem_write2,
        "stp with only 1 MEM W should be inferred"
    );
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
