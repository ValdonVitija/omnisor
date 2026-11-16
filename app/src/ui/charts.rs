use super::*;
use collection::store::{Point, statistics};
use gpui::{PathBuilder, canvas, point};

pub(super) fn utilization_card(
    label: &str,
    ratio: Option<f64>,
    description: &str,
    color: u32,
) -> Div {
    let ratio = ratio.filter(|value| value.is_finite() && (0.0..=1.0).contains(value));
    let ring = canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let stroke = 8.;
            let radius =
                (f32::from(bounds.size.width).min(f32::from(bounds.size.height)) - stroke) / 2.;
            let center = bounds.center();
            let arc = |fraction: f64| {
                let mut path = PathBuilder::stroke(px(stroke));
                path.move_to(point(center.x, center.y - px(radius)));
                let mut angle = -std::f64::consts::FRAC_PI_2;
                let mut remaining = fraction * std::f64::consts::TAU;
                // Two half-circle arcs also render a complete 100% ring.
                while remaining > f64::EPSILON {
                    let sweep = remaining.min(std::f64::consts::PI);
                    angle += sweep;
                    path.arc_to(
                        point(px(radius), px(radius)),
                        px(0.),
                        false,
                        true,
                        point(
                            center.x + px(radius * angle.cos() as f32),
                            center.y + px(radius * angle.sin() as f32),
                        ),
                    );
                    remaining -= sweep;
                }
                path.build()
            };
            if let Ok(track) = arc(1.) {
                window.paint_path(track, rgb(SELECTED));
            }
            if let Some(ratio) = ratio.filter(|value| *value > 0.)
                && let Ok(progress) = arc(ratio)
            {
                window.paint_path(progress, rgb(color));
            }
        },
    )
    .absolute()
    .top_0()
    .left_0()
    .size_full();

    div()
        .flex_1()
        .min_w_0()
        .p_4()
        .rounded_lg()
        .bg(rgb(PANEL))
        .border_1()
        .border_color(rgb(BORDER))
        .child(
            div()
                .text_size(px(10.))
                .text_color(rgb(MUTED))
                .child(label.to_owned()),
        )
        .child(
            div().mt_3().flex().justify_center().child(
                div()
                    .relative()
                    .size(px(112.))
                    .flex_shrink_0()
                    .child(ring)
                    .child(
                        div()
                            .absolute()
                            .top_0()
                            .left_0()
                            .size_full()
                            .flex()
                            .flex_col()
                            .items_center()
                            .justify_center()
                            .gap_1()
                            .child(
                                div().text_size(px(23.)).child(
                                    ratio
                                        .map(|value| format!("{:.1}%", value * 100.))
                                        .unwrap_or_else(|| "—".into()),
                                ),
                            )
                            .child(div().text_size(px(9.)).text_color(rgb(MUTED)).child(
                                if ratio.is_some() {
                                    "utilization"
                                } else {
                                    "no reading"
                                },
                            )),
                    ),
            ),
        )
        .child(
            div()
                .mt_3()
                .text_size(px(10.))
                .text_color(rgb(MUTED))
                .child(description.to_owned()),
        )
}

/// Fixed-point budget, real time x-axis, and explicit breaks across missed scrapes.
pub(super) fn trend(
    title: &str,
    subtitle: &str,
    points: Vec<Point>,
    unit: &str,
    color: u32,
    range: (u64, u64),
    interval: u64,
) -> Div {
    let values = statistics(&points);
    let stats = values
        .as_ref()
        .map(|s| {
            format!(
                "Min {}  ·  Sample avg {}  ·  Max {}  ·  {} samples",
                value(s.min, unit),
                value(s.sample_mean, unit),
                value(s.max, unit),
                s.count
            )
        })
        .unwrap_or_else(|| "Waiting for samples".into());
    let scale = if unit == "%" {
        1.
    } else {
        points.iter().map(|p| p.value).fold(1., f64::max) * 1.1
    };
    let current = points
        .last()
        .map(|p| value(p.value, unit))
        .unwrap_or_else(|| "—".into());
    let count = points.len();
    let plot = canvas(
        |_, _, _| (),
        move |bounds, _, window, _| {
            let width = f32::from(bounds.size.width);
            let height = f32::from(bounds.size.height);
            let mut grid = PathBuilder::stroke(px(1.));
            for level in [0., 0.5, 1.] {
                grid.move_to(point(bounds.left(), bounds.top() + px(height * level)));
                grid.line_to(point(bounds.right(), bounds.top() + px(height * level)));
            }
            if let Ok(path) = grid.build() {
                window.paint_path(path, rgb(BORDER));
            }
            let mut line = PathBuilder::stroke(px(1.8));
            let duration = range.1.saturating_sub(range.0).max(1) as f64;
            let mut previous = None;
            for sample in &points {
                let x = ((sample.at.saturating_sub(range.0) as f64 / duration).clamp(0., 1.)
                    as f32)
                    * width;
                let y = (1. - (sample.value / scale).clamp(0., 1.) as f32) * height;
                let position = point(bounds.left() + px(x), bounds.top() + px(y));
                if previous.is_none_or(|at| sample.at.saturating_sub(at) > interval * 1_500_000_000)
                {
                    line.move_to(position);
                } else {
                    line.line_to(position);
                }
                // A single reading has a visible marker and no invented history.
                if count == 1 {
                    line.move_to(point(position.x - px(2.), position.y));
                    line.line_to(point(position.x + px(2.), position.y));
                }
                previous = Some(sample.at);
            }
            if let Ok(path) = line.build() {
                window.paint_path(path, rgb(color));
            }
        },
    )
    .flex_1()
    .min_w_0()
    .h(px(116.));
    let plot = div()
        .flex()
        .gap_2()
        .child(
            div()
                .w(px(52.))
                .h(px(116.))
                .flex_shrink_0()
                .flex()
                .flex_col()
                .justify_between()
                .text_size(px(9.))
                .text_color(rgb(MUTED))
                .child(value(scale, unit))
                .child(value(scale / 2., unit))
                .child(value(0., unit)),
        )
        .child(plot);
    div()
        .flex_1()
        .min_w_0()
        .p_5()
        .rounded_lg()
        .bg(rgb(PANEL))
        .border_1()
        .border_color(rgb(BORDER))
        .child(
            div()
                .flex()
                .items_start()
                .justify_between()
                .gap_2()
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(div().text_sm().child(title.to_owned()))
                        .child(
                            div()
                                .text_size(px(10.))
                                .text_color(rgb(MUTED))
                                .child(subtitle.to_owned()),
                        ),
                )
                .child(div().text_lg().text_color(rgb(color)).child(current)),
        )
        .child(div().mt_4().relative().child(plot).when(count < 2, |view| {
            view.child(
                div()
                    .absolute()
                    .top_4()
                    .left_2()
                    .text_xs()
                    .text_color(rgb(MUTED))
                    .child(if count == 0 {
                        "No samples in this window"
                    } else {
                        "One sample · collecting history…"
                    }),
            )
        }))
        .child(
            div()
                .mt_2()
                .flex()
                .justify_between()
                .text_size(px(9.))
                .text_color(rgb(MUTED))
                .child(clock(range.0))
                .child(clock(range.1)),
        )
        .child(
            div()
                .mt_3()
                .text_size(px(10.))
                .text_color(rgb(MUTED))
                .child(stats),
        )
}
pub(super) fn value(number: f64, unit: &str) -> String {
    match unit {
        "%" => format!("{:.1}%", number * 100.),
        "bit/s" if number >= 1e9 => format!("{:.2} Gb/s", number / 1e9),
        "bit/s" if number >= 1e6 => format!("{:.2} Mb/s", number / 1e6),
        "bit/s" if number >= 1e3 => format!("{:.1} kb/s", number / 1e3),
        _ => format!("{number:.1} {unit}"),
    }
}
fn clock(at: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp((at / 1_000_000_000) as i64, 0)
        .map(|t| t.format("%H:%M:%S UTC").to_string())
        .unwrap_or_default()
}
