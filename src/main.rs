mod app;
mod taint;

use app::TextViewerApp;
use eframe::egui;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1600.0, 900.0])
            .with_title("Large Text Viewer"),
        ..Default::default()
    };

    eframe::run_native(
        "Large Text Viewer",
        options,
        Box::new(|cc| {
            install_cjk_fonts(&cc.egui_ctx);
            Ok(Box::new(TextViewerApp::default()))
        }),
    )
}

/// Install a CJK-capable font so Chinese UI text renders as glyphs instead of
/// tofu boxes. Tries common Windows system fonts first, falls back to macOS /
/// Linux locations. If none found, egui's default (ASCII-only) font is kept.
fn install_cjk_fonts(ctx: &egui::Context) {
    const CANDIDATES: &[&str] = &[
        // Windows
        r"C:\Windows\Fonts\msyh.ttc",     // Microsoft YaHei
        r"C:\Windows\Fonts\msyhbd.ttc",   // Microsoft YaHei Bold
        r"C:\Windows\Fonts\simhei.ttf",   // SimHei
        r"C:\Windows\Fonts\simsun.ttc",   // SimSun
        // macOS
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Medium.ttc",
        // Linux
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ];

    let Some(bytes) = CANDIDATES
        .iter()
        .find_map(|p| std::fs::read(p).ok())
    else {
        eprintln!("[fonts] no CJK font found; Chinese UI will show as tofu");
        return;
    };

    let mut fonts = egui::FontDefinitions::default();
    fonts
        .font_data
        .insert("cjk".to_owned(), egui::FontData::from_owned(bytes));
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
