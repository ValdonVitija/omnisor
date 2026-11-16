mod ui;

use gpui::{
    App, AppContext, Application, Bounds, KeyBinding, WindowBounds, WindowOptions, point, px, size,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args_os().len() > 1 {
        return Err("Usage: omnisor".into());
    }
    Application::new().run(move |cx: &mut App| {
        ui::init(cx);
        cx.bind_keys([
            KeyBinding::new("escape", ui::ShowLauncher, None),
            KeyBinding::new("cmd-1", ui::OpenDeviceHealth, None),
            KeyBinding::new("cmd-q", ui::Quit, None),
            KeyBinding::new("cmd-enter", ui::StartCollection, None),
        ]);
        cx.on_window_closed(|cx| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        let bounds = Bounds::centered(None, size(px(1280.), px(820.)), cx);
        if let Err(error) = cx.open_window(
            WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                window_min_size: Some(size(px(900.), px(600.))),
                titlebar: Some(gpui::TitlebarOptions {
                    title: Some("Omnisor".into()),
                    appears_transparent: true,
                    traffic_light_position: Some(point(px(12.), px(10.))),
                }),
                ..Default::default()
            },
            |window, cx| cx.new(|cx| ui::Workbench::new(window, cx)),
        ) {
            eprintln!("Cannot open Omnisor window: {error}");
            cx.quit();
        }
        cx.activate(true);
    });
    Ok(())
}
