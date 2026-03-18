mod app;

use app::TextViewerApp;
use eframe::egui;
use std::path::Path;

fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    for (font_name, font_path) in [
        ("cjk-simhei", "C:\\Windows\\Fonts\\simhei.ttf"),
        ("cjk-deng", "C:\\Windows\\Fonts\\Deng.ttf"),
        ("cjk-simsunb", "C:\\Windows\\Fonts\\simsunb.ttf"),
    ] {
        if let Ok(bytes) = std::fs::read(Path::new(font_path)) {
            fonts.font_data.insert(
                font_name.to_owned(),
                egui::FontData::from_owned(bytes).into(),
            );
            fonts
                .families
                .entry(egui::FontFamily::Proportional)
                .or_default()
                .insert(0, font_name.to_owned());
            fonts
                .families
                .entry(egui::FontFamily::Monospace)
                .or_default()
                .insert(0, font_name.to_owned());
            ctx.set_fonts(fonts);
            return;
        }
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title("Taint Rev Trace"),
        ..Default::default()
    };

    eframe::run_native(
        "Taint Rev Trace",
        options,
        Box::new(|cc| {
            configure_fonts(&cc.egui_ctx);
            Ok(Box::new(TextViewerApp::default()))
        }),
    )
}
