//! 逐条对比原始 trace 文件,验证污点追踪结果的行号、汇编、地址
//! 是否和文件内容完全一致。
//!
//! 100 个均匀采样点 × 寄存器 + 内存追踪,每条命中都回到原始字节
//! 重新读那一行,assert 行号/模块/地址/ASM 全部匹配。

use large_text_taint::engine::{TaintEngine, TaintSource, TrackMode};
use large_text_taint::parser::{read_raw_line, TraceParser};
use large_text_taint::reg::{reg_name, REG_INVALID};
use std::path::Path;

const TRACE_PATH: &str = r"C:\Users\pzx\Desktop\xhs\xgtrace_0x76fed9fdc8_20260414_134433.txt";
const LOCAL_TRACE_PATH: &str =
    r"D:\study\attd\large-text-viewer\tracelog\xgtrace_0x76fed9fdc8_20260414_134433.txt";
const NUM_SAMPLES: usize = 100;
const WINDOW_BYTES: u64 = 10_000_000; // 10 MB per window
const SCAN_LIMIT: u32 = 10_000;

fn open_trace() -> Option<memmap2::Mmap> {
    let path = Path::new(TRACE_PATH);
    if !path.exists() {
        eprintln!("[skip] xgtrace file not found");
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    unsafe { memmap2::Mmap::map(&file).ok() }
}

/// 从原始字节里按 line_number 数 \n 找到那一行的起始偏移,
/// 然后读到下一个 \n,返回那一行的文本。
/// 这是独立于 parser 的"ground truth"读取方式。
fn read_line_from_bytes_by_number(bytes: &[u8], line_number: u32) -> Option<String> {
    if line_number == 0 {
        return None;
    }
    // line_number 是 1-based;找到第 (line_number - 1) 个 '\n' 后面的内容
    let mut newlines_seen = 0u32;
    let target_newlines = line_number - 1;
    let mut start = 0usize;

    if target_newlines == 0 {
        start = 0;
    } else {
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'\n' {
                newlines_seen += 1;
                if newlines_seen == target_newlines {
                    start = i + 1;
                    break;
                }
            }
        }
        if newlines_seen < target_newlines {
            return None; // line not found
        }
    }

    // Find end of line
    let end = bytes[start..]
        .iter()
        .position(|&b| b == b'\n')
        .map(|p| start + p)
        .unwrap_or(bytes.len());

    let line = &bytes[start..end];
    let text = String::from_utf8_lossy(line);
    Some(text.trim_end_matches('\r').to_string())
}

/// 核心验证:对一次追踪的每条命中,回到原始文件验证行号对应的
/// 原始文本和 parser 给出的 raw_line 完全一致。
fn verify_run(
    engine: &TaintEngine,
    lines: &[large_text_taint::trace::TraceLine],
    window_bytes: &[u8],
    label: &str,
) -> (usize, usize) {
    // (checked_count, error_count)
    let results = engine.results();
    let mut checked = 0usize;
    let mut errors = 0usize;

    for (i, entry) in results.iter().enumerate() {
        assert!(
            entry.index < lines.len(),
            "{label}: result[{i}].index={} out of bounds (len={})",
            entry.index,
            lines.len()
        );
        let tl = &lines[entry.index];
        let line_number = tl.line_number;

        // 1) 通过 read_raw_line(parser 方式)拿到文本
        let parser_raw = read_raw_line(window_bytes, tl);
        let parser_raw = parser_raw.trim_end_matches(['\n', '\r']);

        // 2) 通过独立方式(数 \n)拿到同一行号的原始文本
        let ground_truth = read_line_from_bytes_by_number(window_bytes, line_number);

        match ground_truth {
            Some(ref gt) => {
                // 两者必须完全一致
                if parser_raw != gt.as_str() {
                    eprintln!(
                        "  ✗ {label} result[{i}] line={line_number}: MISMATCH!"
                    );
                    eprintln!("    parser:  {}", &parser_raw[..parser_raw.len().min(120)]);
                    eprintln!("    ground:  {}", &gt[..gt.len().min(120)]);
                    errors += 1;
                }

                // 3) 如果是指令行,验证 module!offset 和 address 能在 ground truth 里找到
                if let Some(addr_hex) = extract_address(parser_raw) {
                    assert!(
                        gt.contains(&addr_hex),
                        "{label} result[{i}] line={line_number}: address {addr_hex} not found in ground truth"
                    );
                }
            }
            None => {
                eprintln!(
                    "  ✗ {label} result[{i}] line={line_number}: could not find line in raw bytes!"
                );
                errors += 1;
            }
        }

        // 4) 行号单调性(已在 bulk_taint 测试覆盖,这里再验一次)
        if i > 0 {
            let prev_ln = lines[results[i - 1].index].line_number;
            assert!(
                line_number >= prev_ln,
                "{label}: line numbers not monotonic: {} > {} at result[{i}]",
                prev_ln,
                line_number
            );
        }

        checked += 1;
    }
    (checked, errors)
}

/// 从 "libtiny.so!178e00 0x76fed9fe00: ..." 中提取 "0x76fed9fe00"
fn extract_address(line: &str) -> Option<String> {
    // 找 "0x" 开头的 hex 段
    let idx = line.find("0x")?;
    let rest = &line[idx..];
    let end = rest
        .find(|c: char| c == ':' || c == ' ' || c == '"')
        .unwrap_or(rest.len());
    if end > 2 {
        Some(rest[..end].to_string())
    } else {
        None
    }
}

#[test]
fn verify_100_samples_against_raw_file() {
    let Some(mmap) = open_trace() else { return };
    let file_size = mmap.len();
    let bytes = &mmap[..];

    println!(
        "xgtrace: {:.2} GB, {} bytes",
        file_size as f64 / 1e9,
        file_size
    );

    let step = file_size / NUM_SAMPLES;
    let mut total_checked = 0usize;
    let mut total_errors = 0usize;
    let mut total_runs = 0usize;

    for sample_i in 0..NUM_SAMPLES {
        let window_start = sample_i * step;
        let window_end = (window_start as u64 + WINDOW_BYTES).min(file_size as u64) as usize;
        if window_start >= file_size {
            break;
        }

        let window = &bytes[window_start..window_end];
        let mut parser = TraceParser::new();
        parser.load_range(window, u32::MAX, WINDOW_BYTES);
        let lines = parser.lines();
        if lines.is_empty() {
            continue;
        }

        // 在这个窗口中间挑一条指令
        let mid_idx = lines.len() / 2;
        let tl = &lines[mid_idx];

        // --- 寄存器反向 ---
        if tl.num_dst > 0 && tl.dst_regs[0] != REG_INVALID {
            let reg = tl.dst_regs[0];
            let mut engine = TaintEngine::new();
            engine.set_mode(TrackMode::Backward);
            engine.set_source(TaintSource::from_reg(reg));
            engine.set_max_scan_distance(SCAN_LIMIT);
            engine.run(lines, mid_idx);

            let label = format!(
                "S{:03} Bwd reg={} line={}",
                sample_i,
                reg_name(reg),
                tl.line_number
            );
            let (c, e) = verify_run(&engine, lines, window, &label);
            total_checked += c;
            total_errors += e;
            total_runs += 1;

            if e == 0 && c > 0 {
                print!(".");
            } else if e > 0 {
                print!("✗");
            }
        }

        // --- 寄存器正向 ---
        if tl.num_src > 0 && tl.src_regs[0] != REG_INVALID {
            let reg = tl.src_regs[0];
            let mut engine = TaintEngine::new();
            engine.set_mode(TrackMode::Forward);
            engine.set_source(TaintSource::from_reg(reg));
            engine.set_max_scan_distance(SCAN_LIMIT);
            engine.run(lines, mid_idx);

            let label = format!(
                "S{:03} Fwd reg={} line={}",
                sample_i,
                reg_name(reg),
                tl.line_number
            );
            let (c, e) = verify_run(&engine, lines, window, &label);
            total_checked += c;
            total_errors += e;
            total_runs += 1;

            if e == 0 && c > 0 {
                print!(".");
            } else if e > 0 {
                print!("✗");
            }
        }

        // --- 内存反向 ---
        if tl.has_mem_read && tl.mem_read_addr != 0 {
            let mut engine = TaintEngine::new();
            engine.set_mode(TrackMode::Backward);
            engine.set_source(TaintSource::from_mem(tl.mem_read_addr));
            engine.set_max_scan_distance(SCAN_LIMIT);
            engine.run(lines, mid_idx);

            let label = format!(
                "S{:03} Bwd mem:0x{:x} line={}",
                sample_i, tl.mem_read_addr, tl.line_number
            );
            let (c, e) = verify_run(&engine, lines, window, &label);
            total_checked += c;
            total_errors += e;
            total_runs += 1;

            if e == 0 && c > 0 {
                print!(".");
            } else if e > 0 {
                print!("✗");
            }
        }

        // --- 内存正向 ---
        if tl.has_mem_write && tl.mem_write_addr != 0 {
            let mut engine = TaintEngine::new();
            engine.set_mode(TrackMode::Forward);
            engine.set_source(TaintSource::from_mem(tl.mem_write_addr));
            engine.set_max_scan_distance(SCAN_LIMIT);
            engine.run(lines, mid_idx);

            let label = format!(
                "S{:03} Fwd mem:0x{:x} line={}",
                sample_i, tl.mem_write_addr, tl.line_number
            );
            let (c, e) = verify_run(&engine, lines, window, &label);
            total_checked += c;
            total_errors += e;
            total_runs += 1;

            if e == 0 && c > 0 {
                print!(".");
            } else if e > 0 {
                print!("✗");
            }
        }
    }

    println!();
    println!("==================================================");
    println!("采样点: {}", NUM_SAMPLES);
    println!("追踪运行次数: {}", total_runs);
    println!("逐行校验命中数: {}", total_checked);
    println!("行号/内容不匹配数: {}", total_errors);
    println!("==================================================");

    if total_errors > 0 {
        panic!(
            "发现 {} 处行号与原始文件内容不匹配!详见上方 ✗ 标记。",
            total_errors
        );
    }
    println!("✅ 全部 {} 条命中逐行对比原始文件,行号/ASM/地址 100% 一致。", total_checked);
}

/// Ad-hoc diagnostic: reverse-track x8 at line 7658469
/// (`ldr x8, [x27, x8]` — typical jump-table dispatch pattern).
/// Prints both "data" and "address-source" backward traces so we can see
/// what the engine actually produces.
///
/// Run manually:
///   cargo test -p large-text-taint --release --test verify_against_file \
///     -- --ignored --nocapture debug_bwd_x8_at_7658469
#[test]
#[ignore]
fn debug_bwd_x8_at_7658469() {
    use large_text_taint::engine::{StopReason, TrackMode};
    use large_text_taint::reg::parse_reg_name;

    let path = std::path::Path::new(LOCAL_TRACE_PATH);
    assert!(path.exists(), "local trace missing: {}", LOCAL_TRACE_PATH);
    let file = std::fs::File::open(path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file).unwrap() };
    let bytes = &mmap[..];

    let target_line: u32 = 7_658_469;

    println!("parsing up to line {} ...", target_line + 10);
    let t0 = std::time::Instant::now();
    let mut parser = TraceParser::new();
    // Parse a bit past the target so start_index has successors for
    // completeness; backward dep-graph build is bounded by start_index,
    // so parsing the whole prefix is unavoidable.
    parser.load_range(bytes, target_line + 10, u64::MAX);
    let lines = parser.lines();
    println!(
        "parsed {} TraceLines in {:.2}s",
        lines.len(),
        t0.elapsed().as_secs_f64()
    );

    let idx = parser.find_by_line(target_line).expect("target not parsed");
    let tl = &lines[idx];
    println!(
        "\ntarget: line={} cat={:?} dst={:?} src={:?} has_mem_read={} mem_read_addr=0x{:x} has_wb={}",
        tl.line_number,
        tl.category,
        &tl.dst_regs[..tl.num_dst as usize],
        &tl.src_regs[..tl.num_src as usize],
        tl.has_mem_read,
        tl.mem_read_addr,
        tl.has_writeback_base,
    );
    println!("raw: {}", read_raw_line(bytes, tl).trim_end_matches(['\r', '\n']));

    let x8 = parse_reg_name(b"x8");

    // Build the Phase 1 semantic tag table once; both modes reuse it.
    let t_tag = std::time::Instant::now();
    let tag_table = std::sync::Arc::new(parser.build_tag_table(bytes));
    println!(
        "\ntag table: {} origins, {} ext-call tags, {} mem ranges (built in {:.2}s)",
        tag_table.origins_len(),
        tag_table.ext_call_entries().len(),
        tag_table.mem_ranges().len(),
        t_tag.elapsed().as_secs_f64()
    );

    fn fmt_snapshot(entry: &large_text_taint::engine::ResultEntry) -> String {
        let mut regs = Vec::new();
        for i in 0..256usize {
            if entry.reg_snapshot[i] {
                regs.push(large_text_taint::reg::reg_name(i as u8).to_string());
            }
        }
        let mems: Vec<String> = entry.mem_snapshot.iter().map(|a| format!("mem:0x{:x}", a)).collect();
        format!("{{{}}}", [regs, mems].concat().join(", "))
    }

    // Mode A: "data" backward — the default right-click "向后追踪起点… x8".
    // For `ldr x8, [x27, x8]` this should ONLY walk the data chain through
    // memory (mem_read_addr). Since that address is a read-only constant
    // (never written in this trace), the result is expected to be 1 hit
    // with a boundary taint on the mem address.
    {
        let mut e = TaintEngine::new();
        e.set_mode(TrackMode::Backward);
        e.set_source(TaintSource::from_reg(x8));
        e.set_max_scan_distance(200_000);
        e.set_max_depth(64);
        e.set_tag_table(tag_table.clone());
        let t = std::time::Instant::now();
        e.run(lines, idx);
        println!(
            "\n[Mode A — data] run {:.2}s, {} hits, stop={:?}",
            t.elapsed().as_secs_f64(),
            e.results().len(),
            e.stop_reason()
        );
        for r in e.results().iter().take(10) {
            let tl = &lines[r.index];
            println!(
                "  line={} {}",
                tl.line_number,
                read_raw_line(bytes, tl)
                    .trim_end_matches(['\r', '\n'])
                    .chars()
                    .take(120)
                    .collect::<String>()
            );
        }
        if let Some(start_entry) = e.results().iter().find(|r| r.index == idx) {
            println!("  START-LINE snapshot: {}", fmt_snapshot(start_entry));
        }
        if let Some(rem) = e.remaining_taint() {
            println!("  boundary taint regs: {:?}", rem.regs);
            let tagged_mems: Vec<String> = rem
                .mem_tags
                .iter()
                .map(|&(a, tag)| {
                    let label = tag_table
                        .origin(tag)
                        .map(|o| o.short_label())
                        .unwrap_or_default();
                    if label.is_empty() {
                        format!("0x{:x}", a)
                    } else {
                        format!("0x{:x}[{}]", a, label)
                    }
                })
                .collect();
            println!("  boundary taint mems: {:?}", tagged_mems);
        }
        assert_eq!(e.stop_reason(), StopReason::EndOfTrace);
    }

    // Mode B: "address-source" backward — the `collect_addr_source_targets`
    // menu. Uses skip_start_propagation=true so the engine tracks x8 (the
    // OLD value used to form the address) all the way back to the csel
    // that produced it, and then to the cmp that set NZCV.
    {
        let mut e = TaintEngine::new();
        e.set_mode(TrackMode::Backward);
        e.set_source(TaintSource::from_reg_as_source(x8));
        e.set_max_scan_distance(200_000);
        e.set_max_depth(64);
        e.set_stop_at_sp_spill(true); // matches the UI path for address-source menu
        e.set_tag_table(tag_table.clone());
        let t = std::time::Instant::now();
        e.run(lines, idx);
        println!(
            "\n[Mode B — address source] run {:.2}s, {} hits, stop={:?}",
            t.elapsed().as_secs_f64(),
            e.results().len(),
            e.stop_reason()
        );
        // Dump first/last few hits WITH their snapshots so we can audit
        // whether each row's taint set matches the instruction's data flow.
        let total = e.results().len();
        let show_head = 15usize.min(total);
        let show_tail = 10usize.min(total.saturating_sub(show_head));
        for (n, r) in e.results().iter().enumerate() {
            if n >= show_head && n < total - show_tail {
                if n == show_head {
                    println!("  ... ({} middle rows elided) ...", total - show_head - show_tail);
                }
                continue;
            }
            let tl = &lines[r.index];
            let raw = read_raw_line(bytes, tl)
                .trim_end_matches(['\r', '\n'])
                .chars()
                .take(96)
                .collect::<String>();
            println!("  line={} {}", tl.line_number, raw);
            println!("    tainted: {}", fmt_snapshot(r));
        }
        if let Some(start_entry) = e.results().iter().find(|r| r.index == idx) {
            println!("  START-LINE snapshot: {}", fmt_snapshot(start_entry));
        }
        if let Some(rem) = e.remaining_taint() {
            println!("  boundary taint regs: {:?}", rem.regs);
            let tagged_mems: Vec<String> = rem
                .mem_tags
                .iter()
                .map(|&(a, tag)| {
                    let label = tag_table
                        .origin(tag)
                        .map(|o| o.short_label())
                        .unwrap_or_default();
                    if label.is_empty() {
                        format!("0x{:x}", a)
                    } else {
                        format!("0x{:x}[{}]", a, label)
                    }
                })
                .collect();
            println!("  boundary taint mems: {:?}", tagged_mems);
        }
    }
}
