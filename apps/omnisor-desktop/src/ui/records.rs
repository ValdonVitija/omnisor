use super::*;

impl Workbench {
    pub(super) fn findings(&self, cx: &mut Context<Self>) -> Div {
        let mut view =
            div()
                .flex()
                .flex_col()
                .gap_3()
                .child(div().text_lg().child(if self.live.is_some() {
                    "Session findings"
                } else {
                    "Recorded findings"
                }));
        let findings = self.workspace.findings();
        if findings.is_empty() {
            return view.child(note(
                "No findings in this capture",
                "This does not establish current device health or resolve earlier findings.",
            ));
        }
        view = view.child(self.page_controls(findings.len(), cx));
        for finding in findings
            .into_iter()
            .skip(self.page * ROWS_PER_PAGE)
            .take(ROWS_PER_PAGE)
        {
            view = view.child(
                div()
                    .p_4()
                    .rounded_md()
                    .bg(rgb(PANEL))
                    .border_1()
                    .border_color(rgb(BORDER))
                    .child(
                        div()
                            .text_sm()
                            .text_color(rgb(severity_color(&finding.severity)))
                            .child(format!(
                                "{} · {}",
                                finding.severity.to_uppercase(),
                                finding.entity_id
                            )),
                    )
                    .child(div().mt_2().child(finding.message.clone())),
            );
        }
        view
    }

    pub(super) fn interfaces(&self, cx: &mut Context<Self>) -> Div {
        if self.live.is_some() {
            return self.live_interfaces(cx);
        }
        let mut view = div().flex().flex_col().gap_3()
            .child(note("Interface observations", "Administrative and operational state are separate. Receive-byte counters are cumulative values, not bandwidth estimates."));
        let observations: Vec<_> = self
            .workspace
            .observations()
            .into_iter()
            .filter(|observation| observation.name.starts_with("interface."))
            .collect();
        view = view.child(self.page_controls(observations.len(), cx));
        for observation in observations
            .into_iter()
            .skip(self.page * ROWS_PER_PAGE)
            .take(ROWS_PER_PAGE)
        {
            view = view.child(row(
                &observation.entity_id,
                &observation.name,
                &display_value(observation),
            ));
        }
        view
    }

    pub(super) fn observations(&self, cx: &mut Context<Self>) -> Div {
        let observations = self.workspace.observations();
        let mut view = div()
            .flex()
            .flex_col()
            .gap_3()
            .child(self.page_controls(observations.len(), cx));
        for observation in observations
            .into_iter()
            .skip(self.page * ROWS_PER_PAGE)
            .take(ROWS_PER_PAGE)
        {
            view = view.child(
                div()
                    .p_4()
                    .rounded_md()
                    .bg(rgb(PANEL))
                    .border_1()
                    .border_color(rgb(BORDER))
                    .child(row(
                        &observation.entity_id,
                        &observation.name,
                        &display_value(observation),
                    ))
                    .child(div().mt_2().text_xs().text_color(rgb(MUTED)).child(format!(
                        "Source: {} · Profile: {} / {} · Kind: {}",
                        observation.source_metric,
                        observation.profile_id,
                        observation.profile_revision,
                        observation.kind
                    )))
                    .child(div().mt_1().text_xs().text_color(rgb(MUTED)).child(format!(
                        "Observed at: {} ns since Unix epoch",
                        observation.observed_at_unix_nano
                    ))),
            );
        }
        view
    }

    fn page_controls(&self, total: usize, cx: &mut Context<Self>) -> Div {
        let pages = total.div_ceil(ROWS_PER_PAGE).max(1);
        div()
            .flex()
            .gap_3()
            .items_center()
            .child(div().text_xs().text_color(rgb(MUTED)).child(format!(
                "Page {} of {pages} · {total} records",
                self.page + 1
            )))
            .child(
                div()
                    .id("previous-page")
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .bg(rgb(PANEL))
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.page = this.page.saturating_sub(1);
                        cx.notify();
                    }))
                    .child("Previous"),
            )
            .child(
                div()
                    .id("next-page")
                    .px_3()
                    .py_2()
                    .rounded_md()
                    .bg(rgb(PANEL))
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, _, cx| {
                        if this.page + 1 < pages {
                            this.page += 1;
                            cx.notify();
                        }
                    }))
                    .child("Next"),
            )
    }

    fn live_interfaces(&self, cx: &mut Context<Self>) -> Div {
        use omnisor_collection::store::numeric;
        use std::collections::BTreeSet;
        let snapshot = self.live.as_ref().unwrap();
        let series = &snapshot.metrics.series;
        let entities: BTreeSet<_> = series
            .values()
            .filter(|s| s.latest.name.starts_with("interface."))
            .map(|s| s.latest.entity_id.as_str())
            .collect();
        let total = entities.len();
        let cell =
            |text: String, width: f32| div().w(px(width)).flex_shrink_0().text_xs().child(text);
        let columns = [
            ("Interface", 190.),
            ("Admin", 70.),
            ("Oper", 90.),
            ("Receive", 105.),
            ("Transmit", 105.),
            ("Errors Rx / Tx", 120.),
            ("Drops Rx / Tx", 120.),
        ];
        let mut table = div().min_w(px(900.)).flex().flex_col().gap_1().child(
            div().flex().gap_3().p_3().text_color(rgb(MUTED)).children(
                columns
                    .into_iter()
                    .map(|(label, width)| cell(label.into(), width)),
            ),
        );
        for entity in entities
            .into_iter()
            .skip(self.page * ROWS_PER_PAGE)
            .take(ROWS_PER_PAGE)
        {
            let observation = |name: &str| {
                series
                    .get(&(name.to_owned(), entity.to_owned()))
                    .map(|s| &s.latest)
            };
            let state = |name: &str| {
                observation(name)
                    .map(display_value)
                    .unwrap_or_else(|| "—".into())
            };
            let rate = |name: &str| {
                observation(name)
                    .filter(|o| {
                        let counter_name = name.replace("bits_per_second", "bytes");
                        self.collection_fresh
                            && observation(&counter_name).is_some_and(|counter| {
                                counter.observed_at_unix_nano == o.observed_at_unix_nano
                            })
                            && omnisor_collection::unix_nanos()
                                .saturating_sub(o.observed_at_unix_nano.parse::<u64>().unwrap_or(0))
                                <= snapshot.interval_seconds * 3 * 1_000_000_000
                    })
                    .and_then(numeric)
                    .map(|value| charts::value(value, "bit/s"))
                    .unwrap_or_else(|| "—".into())
            };
            let counter = |name: &str| {
                observation(name)
                    .and_then(numeric)
                    .map(|v| format!("{v:.0}"))
                    .unwrap_or_else(|| "—".into())
            };
            let name = observation("interface.oper_status")
                .and_then(|o| o.attributes.get("ifName"))
                .filter(|n| !n.is_empty())
                .map(|n| format!("{n} ({entity})"))
                .unwrap_or_else(|| entity.to_owned());
            table = table.child(
                div()
                    .flex()
                    .gap_3()
                    .p_3()
                    .rounded_md()
                    .bg(rgb(PANEL))
                    .child(cell(name, 190.))
                    .child(cell(state("interface.admin_status"), 70.))
                    .child(cell(state("interface.oper_status"), 90.))
                    .child(cell(rate("interface.receive.bits_per_second"), 105.))
                    .child(cell(rate("interface.transmit.bits_per_second"), 105.))
                    .child(cell(
                        format!(
                            "{} / {}",
                            counter("interface.receive.errors"),
                            counter("interface.transmit.errors")
                        ),
                        120.,
                    ))
                    .child(cell(
                        format!(
                            "{} / {}",
                            counter("interface.receive.discards"),
                            counter("interface.transmit.discards")
                        ),
                        120.,
                    )),
            );
        }
        div().flex().flex_col().gap_4()
            .child(note("Interface telemetry", "States and counters show the last observed value. Errors/drops are cumulative; traffic is a counter rate and needs two valid samples. Missing metrics remain unavailable."))
            .when(!self.collection_fresh,|view|view.child(note("No fresh successful scrape", "Displayed interface states are historical. Current interface state is unknown.")))
            .child(self.page_controls(total,cx))
            .child(div().id("interface-table-scroll").overflow_x_scroll().child(table))
    }

    pub(super) fn collection(&self) -> Div {
        if let Some(snapshot) = &self.live {
            let mut view = div().flex().flex_col().gap_4()
                .child(note("Collection pipeline", &format!("{} → OpenTelemetry Collector → authenticated loopback OTLP receiver → bounded history",snapshot.source)))
                .child(row("Session", &snapshot.profile_id, snapshot.phase.label()))
                .child(row("Collection interval", "Prometheus scraping", &format!("{} seconds",snapshot.interval_seconds)))
                .child(row("Owned process IDs", "Cleared after children are reaped", &format!("{:?}",snapshot.process_ids)))
                .child(row("Receiver", "Bound only on loopback", &snapshot.receiver_address.map(|a|a.to_string()).unwrap_or_else(||"Stopped".into())))
                .child(note("Session storage", "Configuration is generated into a private temporary directory. Credentials are removed after process shutdown. History is in memory, limited to 15 minutes / 450 points per series / 4096 series. Nothing is sent to a cloud service."));
            if let Some(error) = &snapshot.error {
                view = view.child(note("Collection failed", error));
            }
            if let Some(yaml) = &snapshot.collector_yaml {
                view = view
                    .child(div().text_base().child("Generated Collector configuration"))
                    .child(
                        div()
                            .id("collector-config-preview")
                            .max_h(px(360.))
                            .overflow_y_scroll()
                            .p_4()
                            .bg(rgb(PANEL))
                            .rounded_md()
                            .child(
                                div()
                                    .font_family("Menlo")
                                    .text_size(px(11.))
                                    .child(yaml.clone()),
                            ),
                    );
            }
            if !snapshot.diagnostics.is_empty() {
                view = view
                    .child(
                        div()
                            .text_base()
                            .child("Component diagnostics · credentials redacted"),
                    )
                    .child(div().flex().flex_col().gap_2().children(
                        snapshot.diagnostics.iter().map(|line| {
                            div()
                                .font_family("Menlo")
                                .text_size(px(11.))
                                .text_color(rgb(MUTED))
                                .child(line.clone())
                        }),
                    ));
            }
            return view;
        }
        div().flex().flex_col().gap_4()
            .child(note("Collection is stopped", "This workspace explores recorded evidence. Live collection is not available in this build."))
            .child(note("Prometheus and OpenTelemetry", "The existing examples/telemetry walkthrough exercises real scraping and OTLP delivery outside this desktop shell. The next step is a local runtime that owns those processes."))
            .child(row("Prometheus / SNMP", "Adapter configuration available", "Not running"))
            .child(row("OpenTelemetry", "Collection example available", "Not running"))
            .child(row("SSH diagnostics", "Existing shared library", "Not connected"))
            .child(row("gNMI / structured APIs", "Planned adapters", "Unavailable"))
    }
}
