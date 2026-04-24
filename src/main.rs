mod app;
mod taint;

use app::TextViewerApp;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1600.0, 900.0])
            .with_title("西瓜污点分析")
            .with_icon(watermelon_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "西瓜污点分析",
        options,
        Box::new(|cc| {
            install_cjk_fonts(&cc.egui_ctx);
            tune_scroll_speed(&cc.egui_ctx);
            Ok(Box::new(TextViewerApp::default()))
        }),
    )
}

/// 调慢鼠标滚轮滚动速度。
///
/// egui 0.31 的默认 `line_scroll_speed = 40`(参考
/// <https://github.com/emilk/egui/issues/461>)—— Windows 滚轮一格
/// 默认发 3 线 LineDelta,乘起来一次 ≈120 点 ≈ 8 行。对文本查看器
/// 来说跳太远了,尤其大文件里一点点滚动就飞出视口。改成 15 → 一格
/// ≈45 点 ≈ 3 行,贴近常见编辑器手感。
fn tune_scroll_speed(ctx: &egui::Context) {
    ctx.options_mut(|opts| {
        opts.line_scroll_speed = 15.0;
    });
}

/// Install a CJK-capable font so Chinese UI text renders as glyphs instead of
/// tofu boxes. Tries common Windows system fonts first, falls back to macOS /
/// Linux locations. If none found, egui's default (ASCII-only) font is kept.
fn install_cjk_fonts(ctx: &egui::Context) {
    const CANDIDATES: &[&str] = &[
        // Windows
        r"C:\Windows\Fonts\msyh.ttc",   // Microsoft YaHei
        r"C:\Windows\Fonts\msyhbd.ttc", // Microsoft YaHei Bold
        r"C:\Windows\Fonts\simhei.ttf", // SimHei
        r"C:\Windows\Fonts\simsun.ttc", // SimSun
        // macOS
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Medium.ttc",
        // Linux
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ];

    let Some(bytes) = CANDIDATES.iter().find_map(|p| std::fs::read(p).ok()) else {
        eprintln!("[fonts] no CJK font found; Chinese UI will show as tofu");
        return;
    };

    let mut fonts = egui::FontDefinitions::default();
    fonts
        .font_data
        .insert("cjk".to_owned(), egui::FontData::from_owned(bytes).into());
    // Put CJK font after the default one for Proportional (keeps egui icons),
    // and append to Monospace as a fallback so Han characters fall back to it.
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(1, "cjk".to_owned());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .push("cjk".to_owned());
    ctx.set_fonts(fonts);
}

/// Draw a 128×128 watermelon-slice icon into raw RGBA pixels at load time.
/// Done procedurally rather than shipping a PNG asset so the binary stays
/// self-contained (no `include_bytes!`, no `image` decode at startup) and
/// the icon matches the "西瓜污点分析" branding exactly.
///
/// Geometry is a half-disc with the flat cut at the top and the curve at
/// the bottom — the classic 🍉 slice silhouette. Layered from outer rim
/// inward:
///   1. dark-green rind, 2. light-green stripe, 3. thin pale-yellow pith,
///   4. red flesh, 5. a handful of black seeds overlaid on the flesh.
fn watermelon_icon() -> egui::IconData {
    const SIZE: u32 = 128;
    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];

    let cx = SIZE as f32 / 2.0;
    // Shift the disc center slightly above the image center so the
    // half-slice sits near the vertical middle of the framebuffer.
    let cy = SIZE as f32 / 2.0 - 8.0;
    let radius = SIZE as f32 * 0.46;

    const RED: [u8; 4] = [232, 70, 80, 255];
    const PITH: [u8; 4] = [242, 232, 208, 255];
    const GREEN_DARK: [u8; 4] = [46, 110, 55, 255];
    const GREEN_LIGHT: [u8; 4] = [132, 192, 100, 255];
    const SEED: [u8; 4] = [30, 30, 35, 255];

    // Seed layout in (dx, dy) relative to (cx, cy). Scattered asymmetrically
    // so the icon doesn't look templated; all dy values are positive so the
    // seeds land inside the lower (visible) half.
    let seeds: &[(f32, f32)] = &[
        (-22.0, 16.0),
        (18.0, 12.0),
        (-4.0, 32.0),
        (14.0, 30.0),
        (-30.0, 26.0),
        (28.0, 24.0),
        (-12.0, 9.0),
        (5.0, 45.0),
    ];

    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 - cx;
            let dy = y as f32 - cy;
            let r = (dx * dx + dy * dy).sqrt();
            let idx = ((y * SIZE + x) * 4) as usize;

            // Half-disc: only the lower half (dy > 0) of the circle is drawn.
            if dy < 0.0 || r > radius {
                rgba[idx..idx + 4].copy_from_slice(&[0, 0, 0, 0]);
                continue;
            }

            let mut is_flesh = false;
            let mut color = if r > radius - 6.0 {
                GREEN_DARK
            } else if r > radius - 11.0 {
                GREEN_LIGHT
            } else if r > radius - 15.0 {
                PITH
            } else {
                is_flesh = true;
                RED
            };

            if is_flesh {
                for &(sx, sy) in seeds {
                    let ddx = dx - sx;
                    // Squash vertically so seeds are teardrop-shaped, not circular.
                    let ddy = (dy - sy) * 1.7;
                    if ddx * ddx + ddy * ddy < 5.5 {
                        color = SEED;
                    }
                }
            }

            rgba[idx..idx + 4].copy_from_slice(&color);
        }
    }

    egui::IconData {
        rgba,
        width: SIZE,
        height: SIZE,
    }
}
