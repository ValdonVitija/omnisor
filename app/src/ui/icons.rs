use app::launcher::MiniApp;
use gpui::{IntoElement, PathBuilder, canvas, point, prelude::*, px, rgb};

/// Small code-native line icons. All paths use the same 24-unit grid/stroke.
pub(super) fn tool_icon(app: MiniApp, color: u32, size: f32) -> impl IntoElement {
    let paths: &[&[(f32, f32)]] = match app {
        MiniApp::DeviceHealth => &[&[
            (2., 12.),
            (7., 12.),
            (10., 5.),
            (14., 19.),
            (17., 12.),
            (22., 12.),
        ]],
        MiniApp::ConfigurationCompare => &[
            &[(8., 3.), (4., 3.), (4., 21.), (8., 21.)],
            &[(16., 3.), (20., 3.), (20., 21.), (16., 21.)],
            &[(8., 9.), (16., 9.)],
            &[(12., 5.), (12., 13.)],
            &[(8., 17.), (16., 17.)],
        ],
        MiniApp::IpTools => &[
            &[(3., 4.), (9., 4.), (9., 10.), (3., 10.), (3., 4.)],
            &[(15., 14.), (21., 14.), (21., 20.), (15., 20.), (15., 14.)],
            &[(9., 7.), (18., 7.), (18., 14.)],
            &[(6., 10.), (6., 17.), (15., 17.)],
        ],
        MiniApp::ProtocolInspector => &[
            &[(3., 4.), (21., 4.), (21., 20.), (3., 20.), (3., 4.)],
            &[(7., 9.), (10., 12.), (7., 15.)],
            &[(13., 15.), (17., 15.)],
        ],
    };
    canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let mut builder = PathBuilder::stroke(px(1.6));
            for path in paths {
                for (index, (x, y)) in path.iter().enumerate() {
                    let point = point(
                        bounds.origin.x + px(*x * size / 24.),
                        bounds.origin.y + px(*y * size / 24.),
                    );
                    if index == 0 {
                        builder.move_to(point);
                    } else {
                        builder.line_to(point);
                    }
                }
            }
            if let Ok(path) = builder.build() {
                window.paint_path(path, rgb(color));
            }
        },
    )
    .w(px(size))
    .h(px(size))
}
