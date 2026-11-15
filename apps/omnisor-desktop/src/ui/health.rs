use super::*;
use chrono::{DateTime, Utc};
use omnisor_desktop::health::Utilization;

impl Workbench {
    pub(super) fn health(&self, _cx: &mut Context<Self>) -> Div {
        let interfaces = &self.summary.interfaces;
        let mut overview =
            div()
                .flex()
                .flex_col()
                .gap_5()
                .child(
                    div()
                        .flex()
                        .items_center()
                        .justify_between()
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap_1()
                                .child(div().text_lg().child("Recorded snapshot"))
                                .child(
                                    div().text_xs().text_color(rgb(MUTED)).child(
                                        "Historical readings · Not a live device connection",
                                    ),
                                ),
                        )
                        .child(badge("RECORDED", MUTED)),
                )
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(utilization_card(
                            "CPU UTILIZATION",
                            self.summary.cpu.as_ref(),
                            "Most utilized processor",
                            (0.8, 0.9),
                        ))
                        .child(utilization_card(
                            "MEMORY UTILIZATION",
                            self.summary.memory.as_ref(),
                            "Most utilized memory pool",
                            (0.85, 0.95),
                        ))
                        .child(
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
                                        .text_size(px(10.))
                                        .text_color(rgb(MUTED))
                                        .child("INTERFACES"),
                                )
                                .child(
                                    div()
                                        .mt_3()
                                        .flex()
                                        .items_baseline()
                                        .gap_2()
                                        .child(div().text_size(px(36.)).child(
                                            if interfaces.total == 0 {
                                                "—".into()
                                            } else {
                                                interfaces.up.to_string()
                                            },
                                        ))
                                        .child(
                                            div().text_sm().text_color(rgb(MUTED)).child(format!(
                                                "up / {} observed",
                                                interfaces.total
                                            )),
                                        ),
                                )
                                .child(
                                    div()
                                        .mt_3()
                                        .text_xs()
                                        .text_color(rgb(if interfaces.down > 0 {
                                            WARNING
                                        } else {
                                            MUTED
                                        }))
                                        .child(format!("{} operationally down", interfaces.down)),
                                )
                                .child(
                                    div()
                                        .mt_3()
                                        .text_size(px(11.))
                                        .text_color(rgb(MUTED))
                                        .child(format!(
                                            "{} admin down · {} unknown",
                                            interfaces.admin_down, interfaces.unknown
                                        )),
                                ),
                        ),
                )
                .child(
                    div()
                        .flex()
                        .gap_4()
                        .child(
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
                                        .text_size(px(10.))
                                        .text_color(rgb(MUTED))
                                        .child("EVIDENCE"),
                                )
                                .child(div().mt_3().text_sm().child(format!(
                                    "{} observations",
                                    self.summary.observation_count
                                )))
                                .child(
                                    div()
                                        .mt_2()
                                        .text_xs()
                                        .text_color(rgb(MUTED))
                                        .child("Original values and provenance in Observations"),
                                ),
                        )
                        .child(
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
                                        .text_size(px(10.))
                                        .text_color(rgb(MUTED))
                                        .child("COLLECTION"),
                                )
                                .child(div().mt_3().text_sm().child("Stopped"))
                                .child(
                                    div()
                                        .mt_2()
                                        .text_xs()
                                        .text_color(rgb(MUTED))
                                        .child("No exporters or collectors are running"),
                                ),
                        ),
                );
        if let Some(capture) = &self.workspace.capture {
            let observations = self.workspace.observations();
            let first = observations
                .iter()
                .filter_map(|o| o.observed_at_unix_nano.parse::<u64>().ok())
                .min();
            let last = observations
                .iter()
                .filter_map(|o| o.observed_at_unix_nano.parse::<u64>().ok())
                .max();
            let range = match (first, last) {
                (Some(first), Some(last)) if first != last => {
                    format!("{} — {}", timestamp(first), timestamp(last))
                }
                (_, Some(last)) => timestamp(last),
                _ => "No observation timestamps".into(),
            };
            overview = overview.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .text_size(px(11.))
                    .text_color(rgb(MUTED))
                    .child(format!("Observed: {range}"))
                    .child(format!("Source: {}", self.workspace.source))
                    .child(capture.description.clone()),
            );
        }
        overview
    }
}

fn timestamp(nanos: u64) -> String {
    DateTime::<Utc>::from_timestamp(
        (nanos / 1_000_000_000) as i64,
        (nanos % 1_000_000_000) as u32,
    )
    .map(|time| time.format("%d %b %Y, %H:%M:%S UTC").to_string())
    .unwrap_or_else(|| format!("{nanos} ns since Unix epoch"))
}

fn badge(text: &str, color: u32) -> Div {
    div()
        .text_size(px(10.))
        .text_color(rgb(color))
        .px_2()
        .py_1()
        .rounded_md()
        .bg(rgb(SELECTED))
        .flex_shrink_0()
        .child(text.to_owned())
}

fn utilization_card(
    label: &str,
    utilization: Option<&Utilization>,
    description: &str,
    thresholds: (f64, f64),
) -> Div {
    let ratio = utilization.map(|u| u.ratio);
    let color = match ratio {
        Some(value) if value >= thresholds.1 => CRITICAL,
        Some(value) if value >= thresholds.0 => WARNING,
        _ => ACCENT,
    };
    let mut card = charts::utilization_card(label, ratio, description, color);
    if let Some(utilization) = utilization {
        card = card.child(
            div()
                .mt_1()
                .text_size(px(11.))
                .text_color(rgb(MUTED))
                .child(format!(
                    "{}{}",
                    utilization.entity,
                    utilization
                        .window_seconds
                        .map(|s| format!(" · {s}s average"))
                        .unwrap_or_default()
                )),
        );
    } else {
        card = card.child(
            div()
                .mt_1()
                .text_size(px(11.))
                .text_color(rgb(MUTED))
                .child("No compatible reading"),
        );
    }
    card
}
