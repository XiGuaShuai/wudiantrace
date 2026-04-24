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
                    eprintln!("  ✗ {label} result[{i}] line={line_number}: MISMATCH!");
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
    println!(
        "✅ 全部 {} 条命中逐行对比原始文件,行号/ASM/地址 100% 一致。",
        total_checked
    );
}
