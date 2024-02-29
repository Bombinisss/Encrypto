#![warn(clippy::all, rust_2018_idioms)]
#![cfg_attr(debug_assertions, windows_subsystem = "console")]
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")] // hide console window on Windows in release
fn main() -> eframe::Result<()> {
    env_logger::init(); // Log to stderr (if you run with `RUST_LOG=debug`).

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([700.0, 500.0])
            .with_min_inner_size([600.0, 420.0])
            .with_transparent(true)
            .with_decorations(false) // Hide the OS-specific "chrome" around the window
            .with_icon(
                eframe::icon_data::from_png_bytes(&include_bytes!("../assets/icon-1024.png")[..])
                    .unwrap(),
            )
            .with_resizable(true),
        follow_system_theme:
            true,
        ..Default::default()
    };
    eframe::run_native(
        "Encrypto",
        native_options,
        Box::new(|cc| Box::new(encrypto::EncryptoInterface::new(cc))),
    )
}
