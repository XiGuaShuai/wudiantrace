//! 内存污点追踪详细验证:打印完整追踪链,人工可对账。

use large_text_taint::engine::{TaintEngine, TaintSource, TrackMode};
use large_text_taint::parser::{read_raw_line, TraceParser};
use large_text_taint::reg::reg_name;
use std::path::Path;

const TRACE_PATH: &str = r"C:\Users\pzx\Desktop\xhs\xgtrace_0x76fed9fdc8_20260414_134433.txt";

fn open_trace() -> Option<memmap2::Mmap> {
    let path = Path::new(TRACE_PATH);
    if !path.exists() {
        eprintln!("[skip] xgtrace file not found");
        return None;
    }
    let file = std::fs::File::open(path).ok()?;
    unsafe { memmap2::Mmap::map(&file).ok() }
}

fn print_results(
    engine: &TaintEngine,
    lines: &[large_text_taint::trace::TraceLine],
    bytes: &[u8],
) {
    let results = engine.results();
    println!("  命中 {} 条, stop={:?}", results.len(), engine.stop_reason());
    for (i, entry) in results.iter().enumerate() {
        let tl = &lines[entry.index];
        let raw = read_raw_line(bytes, tl).trim_end().to_string();
        // 收集当前 tainted 寄存器
        let mut regs: Vec<String> = Vec::new();
        for r in 0..256u16 {
            if entry.reg_snapshot[r as usize] {
                regs.push(reg_name(r as u8).to_string());
            }
        }
        let mut mems: Vec<String> = entry
            .mem_snapshot
            .iter()
            .map(|a| format!("mem:0x{:x}", a))
            .collect();
        mems.sort();
        let tainted = if regs.is_empty() && mems.is_empty() {
            "{}".to_string()
        } else {
            let mut all = regs;
            all.extend(mems);
            format!("{{{}}}", all.join(", "))
        };
        // 截断 raw 到 80 字符可读
        let display_raw = if raw.len() > 100 {
            format!("{}…", &raw[..100])
        } else {
            raw
        };
        println!("  [{:>3}] [{}] {}", i, tl.line_number, display_raw);
        println!("        tainted: {}", tainted);
    }
}

/// 在前 200 行里找内存追踪的案例,详细打印。
#[test]
fn mem_taint_detail_first_200_lines() {
    let Some(mmap) = open_trace() else { return };
    let bytes = &mmap[..];

    // 解析前 200 行(足够覆盖 stp/str/ldr 序列)
    let mut parser = TraceParser::new();
    parser.load_range(bytes, 200, u64::MAX);
    let lines = parser.lines();
    println!("前 200 行共解析出 {} 条指令\n", lines.len());

    // ========================================================
    // 案例 1: line 32 = ldr x8, [x8, #0x28]
    //   MEM R 0x77ac231028 → x8 = 0x6243bc6b2b1678f7
    //   正向追踪这个内存地址:看它的值后来流到了哪
    // ========================================================
    println!("===== 案例 1: Forward mem:0x77ac231028 from line 32 (ldr x8, [x8, #0x28]) =====");
    if let Some(idx) = lines.iter().position(|tl| tl.line_number == 32) {
        let tl = &lines[idx];
        assert!(tl.has_mem_read, "line 32 should have mem_read");
        println!("  起点: line {} addr=0x{:x}", tl.line_number, tl.mem_read_addr);

        let mut engine = TaintEngine::new();
        engine.set_mode(TrackMode::Forward);
        engine.set_source(TaintSource::from_mem(tl.mem_read_addr));
        engine.set_max_scan_distance(50_000);
        engine.run(lines, idx);
        print_results(&engine, lines, bytes);
    } else {
        println!("  (line 32 not found in parsed instructions, skip)");
    }

    // ========================================================
    // 案例 2: line 47 = str x8, [x19, #0x8]
    //   MEM W 0x77ac2226a8 ← x8 = 0x76fedaf84c
    //   反向追踪这个内存地址:看这个地址的值从哪来
    // ========================================================
    println!("\n===== 案例 2: Backward mem:0x77ac2226a8 from line 47 (str x8, [x19, #0x8]) =====");
    if let Some(idx) = lines.iter().position(|tl| tl.line_number == 47) {
        let tl = &lines[idx];
        assert!(tl.has_mem_write, "line 47 should have mem_write");
        println!("  起点: line {} addr=0x{:x}", tl.line_number, tl.mem_write_addr);

        let mut engine = TaintEngine::new();
        engine.set_mode(TrackMode::Backward);
        engine.set_source(TaintSource::from_mem(tl.mem_write_addr));
        engine.set_max_scan_distance(50_000);
        engine.run(lines, idx);
        print_results(&engine, lines, bytes);
    } else {
        println!("  (line 47 not found, skip)");
    }

    // ========================================================
    // 案例 3: line 49 = ldr x0, [x19, #0x8]
    //   MEM R 0x77ac2226a8 → x0 = 0x76fedaf84c
    //   反向追踪 x0:应该看到 x0 ← mem ← x8 ← ... 的链
    // ========================================================
    println!("\n===== 案例 3: Backward x0 from line 49 (ldr x0, [x19, #0x8]) =====");
    if let Some(idx) = lines.iter().position(|tl| tl.line_number == 49) {
        let mut engine = TaintEngine::new();
        engine.set_mode(TrackMode::Backward);
        engine.set_source(TaintSource::from_reg(lines[idx].dst_regs[0]));
        engine.set_max_scan_distance(50_000);
        engine.run(lines, idx);
        print_results(&engine, lines, bytes);
    } else {
        println!("  (line 49 not found, skip)");
    }

    // ========================================================
    // 案例 4: line 24 = stp x3, x0, [x19, #0xb8]
    //   MEM W 0x77ac222758 ← x3, MEM W 0x77ac222760 ← x0
    //   正向追踪第一个写入地址:看 x3 存到内存后谁读了它
    // ========================================================
    println!("\n===== 案例 4: Forward mem:0x77ac222758 from line 24 (stp x3, x0, [x19, #0xb8]) =====");
    if let Some(idx) = lines.iter().position(|tl| tl.line_number == 24) {
        let tl = &lines[idx];
        assert!(tl.has_mem_write, "line 24 should have mem_write");
        println!(
            "  起点: line {} addr1=0x{:x} addr2=0x{:x}",
            tl.line_number, tl.mem_write_addr, tl.mem_write_addr2
        );

        let mut engine = TaintEngine::new();
        engine.set_mode(TrackMode::Forward);
        engine.set_source(TaintSource::from_mem(tl.mem_write_addr));
        engine.set_max_scan_distance(50_000);
        engine.run(lines, idx);
        print_results(&engine, lines, bytes);
    } else {
        println!("  (line 24 not found, skip)");
    }

    // ========================================================
    // 案例 5: 大范围 — 在文件 50% 处取一段,找一个 ldr 做反向内存追踪
    // ========================================================
    println!("\n===== 案例 5: 文件 50% 位置的内存反向追踪 =====");
    let mid = mmap.len() / 2;
    let window_end = (mid + 20_000_000).min(mmap.len());
    let window = &mmap[mid..window_end];
    let mut mid_parser = TraceParser::new();
    mid_parser.load_range(window, u32::MAX, 20_000_000);
    let mid_lines = mid_parser.lines();
    println!("  50% 位置解析出 {} 条指令", mid_lines.len());

    // 找第一个有 mem_read 的指令
    if let Some(idx) = mid_lines.iter().position(|tl| tl.has_mem_read && tl.mem_read_addr != 0) {
        let tl = &mid_lines[idx];
        let raw = read_raw_line(window, tl).trim_end().to_string();
        println!(
            "  选中: [line {}] {} (mem_read=0x{:x})",
            tl.line_number, &raw[..raw.len().min(80)], tl.mem_read_addr
        );

        let mut engine = TaintEngine::new();
        engine.set_mode(TrackMode::Backward);
        engine.set_source(TaintSource::from_mem(tl.mem_read_addr));
        engine.set_max_scan_distance(50_000);
        engine.run(mid_lines, idx);
        print_results(&engine, mid_lines, window);
    }

    // ========================================================
    // 案例 6: 文件 80% 处找一个 str 做正向内存追踪
    // ========================================================
    println!("\n===== 案例 6: 文件 80% 位置的内存正向追踪 =====");
    let pos80 = mmap.len() * 8 / 10;
    let end80 = (pos80 + 20_000_000).min(mmap.len());
    let win80 = &mmap[pos80..end80];
    let mut p80 = TraceParser::new();
    p80.load_range(win80, u32::MAX, 20_000_000);
    let l80 = p80.lines();
    println!("  80% 位置解析出 {} 条指令", l80.len());

    if let Some(idx) = l80.iter().position(|tl| tl.has_mem_write && tl.mem_write_addr != 0) {
        let tl = &l80[idx];
        let raw = read_raw_line(win80, tl).trim_end().to_string();
        println!(
            "  选中: [line {}] {} (mem_write=0x{:x})",
            tl.line_number, &raw[..raw.len().min(80)], tl.mem_write_addr
        );

        let mut engine = TaintEngine::new();
        engine.set_mode(TrackMode::Forward);
        engine.set_source(TaintSource::from_mem(tl.mem_write_addr));
        engine.set_max_scan_distance(50_000);
        engine.run(l80, idx);
        print_results(&engine, l80, win80);
    }

    println!("\n✅ 内存污点追踪详细测试全部完成");
}
