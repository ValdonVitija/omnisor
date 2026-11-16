use super::*;
use collection::{
    Phase,
    store::{Point, numeric},
    unix_nanos,
};

impl Workbench {
    pub(super) fn live_health(&self, cx: &mut Context<Self>) -> Div {
        let Some(live) = &self.live else {
            return div();
        };
        let metrics = &live.metrics;
        let now = unix_nanos();
        let requested_start = now.saturating_sub(self.chart_window * 1_000_000_000);
        let first = metrics
            .series
            .values()
            .filter_map(|s| s.points.front().map(|p| p.at))
            .min()
            .unwrap_or(now);
        let start = first
            .min(now.saturating_sub(live.interval_seconds * 1_000_000_000))
            .max(requested_start);
        let state = if live.phase == Phase::Running {
            metrics.scrape_state(now, live.interval_seconds)
        } else {
            live.phase.label()
        };
        let mut controls = div().flex().items_center().gap_2();
        for (index, seconds) in [60, 300, 900].into_iter().enumerate() {
            controls = controls.child(
                div()
                    .id(("chart-window", index))
                    .px_3()
                    .py_1()
                    .rounded_md()
                    .text_xs()
                    .cursor_pointer()
                    .bg(rgb(if self.chart_window == seconds {
                        SELECTED
                    } else {
                        PANEL
                    }))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.chart_window = seconds;
                        cx.notify();
                    }))
                    .child(format!("{}m", seconds / 60)),
            );
        }
        if live.phase.active() {
            controls = controls.child(
                div()
                    .id("stop-collection")
                    .ml_2()
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .bg(rgb(SELECTED))
                    .text_color(rgb(WARNING))
                    .text_xs()
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _, _, cx| this.stop_collection(cx)))
                    .child("Stop collection"),
            );
        }
        let device = &live.device;
        let mut view = div()
            .flex()
            .flex_col()
            .gap_4()
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .gap_1()
                            .child(div().text_size(px(23.)).child(device.name.clone()))
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(if self.collection_fresh {
                                        ACCENT
                                    } else {
                                        WARNING
                                    }))
                                    .child(format!(
                                        "{} · {} · {}s interval",
                                        if live.source == "Synthetic exporter" {
                                            "SIMULATED"
                                        } else {
                                            "DEVICE SESSION"
                                        },
                                        state,
                                        live.interval_seconds
                                    )),
                            ),
                    )
                    .child(controls),
            )
            .child(
                div()
                    .grid()
                    .grid_cols(3)
                    .gap_3()
                    .child(detail("VENDOR", &device.vendor))
                    .child(detail("MODEL", &device.model))
                    .child(detail("DEVICE TYPE", &device.device_type))
                    .child(detail("OPERATING SYSTEM", &device.os))
                    .child(detail("OS VERSION", &device.os_version))
                    .child(detail(
                        "IDENTITY SOURCE",
                        if live.source == "Synthetic exporter" {
                            "Simulation"
                        } else {
                            "Device profile / saved record"
                        },
                    )),
            );
        if !self.collection_fresh {
            view = view.child(note(if live.phase.active() { "Current health is unknown" } else { "Collection is not running" },
                "Resource cards require fresh, successful scrapes. Graphs retain previous measurements with their timestamps; missing values are never filled with zeros."));
        }
        if let Some(error) = &live.error {
            view = view.child(note("Collection failed", error));
        }
        let ifs = &self.summary.interfaces;
        view = view.child(
            div()
                .grid()
                .grid_cols(3)
                .gap_3()
                .child(charts::utilization_card(
                    "CPU",
                    self.summary.cpu.as_ref().map(|u| u.ratio),
                    &self
                        .summary
                        .cpu
                        .as_ref()
                        .and_then(|u| u.window_seconds)
                        .map(|s| format!("{s}s source average"))
                        .unwrap_or_else(|| "Latest source reading".into()),
                    ACCENT,
                ))
                .child(charts::utilization_card(
                    "MEMORY",
                    self.summary.memory.as_ref().map(|u| u.ratio),
                    "Used / (used + free)",
                    0xb4a5d9,
                ))
                .child(stat(
                    "INTERFACES",
                    if self.collection_fresh && ifs.total > 0 {
                        format!("{} / {}", ifs.up, ifs.total)
                    } else {
                        "—".into()
                    },
                    "Operationally up / observed".into(),
                )),
        );
        let points = |name: &str, entity: Option<&str>| -> (String, Vec<Point>) {
            let series = entity
                .and_then(|entity| metrics.series.get(&(name.to_owned(), entity.to_owned())))
                .or_else(|| metrics.latest_series(name));
            (
                series
                    .map(|s| s.latest.entity_id.clone())
                    .unwrap_or_else(|| "No compatible series".into()),
                series
                    .map(|s| s.points.iter().filter(|p| p.at >= start).copied().collect())
                    .unwrap_or_default(),
            )
        };
        let (cpu_entity, cpu_points) = points(
            "device.cpu.utilization",
            self.summary.cpu.as_ref().map(|u| u.entity.as_str()),
        );
        let (pool, memory_points) = points(
            "device.memory.utilization",
            self.summary.memory.as_ref().map(|u| u.entity.as_str()),
        );
        view = view
            .child(
                div()
                    .flex()
                    .gap_4()
                    .child(charts::trend(
                        "CPU utilization",
                        &format!("Processor {cpu_entity} · highest latest reading"),
                        cpu_points,
                        "%",
                        ACCENT,
                        (start, now),
                        live.interval_seconds,
                    ))
                    .child(charts::trend(
                        "Memory utilization",
                        &format!("Pool {pool} · exact-time used/free pairs"),
                        memory_points,
                        "%",
                        0xb4a5d9,
                        (start, now),
                        live.interval_seconds,
                    )),
            )
            .child(
                div()
                    .flex()
                    .gap_4()
                    .child(charts::trend(
                        "Receive traffic",
                        "Sum of observed interface counter rates",
                        metrics.traffic("interface.receive.bits_per_second", start),
                        "bit/s",
                        0x94c7ac,
                        (start, now),
                        live.interval_seconds,
                    ))
                    .child(charts::trend(
                        "Transmit traffic",
                        "Sum of observed interface counter rates",
                        metrics.traffic("interface.transmit.bits_per_second", start),
                        "bit/s",
                        0xe1ba8c,
                        (start, now),
                        live.interval_seconds,
                    )),
            )
            .child(
                div().flex().gap_4().child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .p_4()
                        .rounded_lg()
                        .bg(rgb(PANEL))
                        .border_1()
                        .border_color(rgb(BORDER))
                        .child(div().text_base().child("Interface state"))
                        .child(
                            div()
                                .mt_3()
                                .text_sm()
                                .child(format!("{} up · {} operationally down", ifs.up, ifs.down)),
                        )
                        .child(div().mt_2().text_xs().text_color(rgb(MUTED)).child(format!(
                            "{} administratively disabled · {} unknown",
                            ifs.admin_down, ifs.unknown
                        ))),
                ),
            );
        let mut reported = div().flex().flex_col().gap_2();
        for (name, label, attribute) in [
            ("device.info.name", "Reported hostname", "sysName"),
            (
                "device.info.description",
                "Reported description",
                "sysDescr",
            ),
            ("device.info.object_id", "Reported object ID", "sysObjectID"),
        ] {
            if let Some(series) = metrics.latest_series(name)
                && let Some(value) = series.latest.attributes.get(attribute)
            {
                reported =
                    reported.child(detail(label, &value.chars().take(512).collect::<String>()));
            }
        }
        if let Some(series) = metrics.latest_series("device.uptime.ticks")
            && let Some(ticks) = numeric(&series.latest)
        {
            reported = reported.child(detail(
                "SNMP agent uptime",
                &format!("{:.0} seconds · last observed", ticks / 100.),
            ));
        }
        view.child(reported).child(div().text_size(px(10.)).text_color(rgb(MUTED))
            .child(format!("{} → Collector → authenticated local OTLP · profile {} · 15-minute in-memory history · times in UTC",live.source,live.profile_id)))
    }
}
fn detail(label: &str, value: &str) -> Div {
    div()
        .min_w_0()
        .flex()
        .flex_col()
        .gap_1()
        .child(
            div()
                .text_size(px(9.))
                .text_color(rgb(MUTED))
                .child(label.to_owned()),
        )
        .child(div().text_sm().child(if value.is_empty() {
            "Unknown".into()
        } else {
            value.to_owned()
        }))
}
fn stat(label: &str, value: String, description: String) -> Div {
    div()
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
        .child(div().mt_2().text_size(px(28.)).child(value))
        .child(
            div()
                .mt_2()
                .text_size(px(10.))
                .text_color(rgb(MUTED))
                .child(description),
        )
}
