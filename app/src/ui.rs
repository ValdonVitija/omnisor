use app::health::HealthSummary;
use app::launcher::{LauncherState, MiniApp};
use app::{Tool, Workspace, display_value};
use collection::{Session, SessionSnapshot};
use gpui::{
    Context, Div, FocusHandle, IntoElement, ParentElement, Render, StatefulInteractiveElement,
    Styled, Task, Window, WindowControlArea, actions, div, prelude::*, px, rgb,
};
use std::sync::Arc;

mod charts;
mod connection;
mod engine;
mod icons;
mod input;
mod live_health;
mod navigation;
mod records;

actions!(
    app,
    [
        ShowLauncher,
        OpenDeviceHealth,
        Quit,
        NextField,
        PreviousField,
        StartCollection
    ]
);

pub fn init(cx: &mut gpui::App) {
    input::init(cx);
    connection::init(cx);
}

const BACKGROUND: u32 = 0x161719;
const SIDEBAR: u32 = 0x111214;
const PANEL: u32 = 0x1c1e21;
const BORDER: u32 = 0x2c2f33;
const MUTED: u32 = 0x969ba4;
const ACCENT: u32 = 0x9bc9d2;
const INK: u32 = 0xe7e9ed;
const SELECTED: u32 = 0x272b30;
const WARNING: u32 = 0xe4b580;
const CRITICAL: u32 = 0xe99696;
const ROWS_PER_PAGE: usize = 100;

pub struct Workbench {
    workspace: Workspace,
    summary: HealthSummary,
    page: usize,
    launcher: LauncherState,
    focus: FocusHandle,
    catalog: collection::Catalog,
    saved_devices: collection::access::SavedDevices,
    saved_devices_error: Option<String>,
    setup: Option<connection::ConnectionForm>,
    session: Option<Session>,
    retired_sessions: Vec<Session>,
    live: Option<Arc<SessionSnapshot>>,
    poll_task: Option<Task<()>>,
    collection_fresh: bool,
    chart_window: u64,
}

impl Workbench {
    pub fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let focus = cx.focus_handle();
        focus.focus(window);
        cx.on_app_quit(|this, _| {
            this.shutdown_sessions();
            async {}
        })
        .detach();
        let catalog = collection::Catalog::bundled().expect("valid bundled collection catalog");
        let (saved_devices, saved_devices_error) =
            match collection::access::SavedDevices::discover(&catalog) {
                Ok(devices) => (devices, None),
                Err(error) => (Default::default(), Some(error)),
            };
        Self {
            workspace: Workspace::empty(),
            summary: HealthSummary::default(),
            page: 0,
            launcher: LauncherState::default(),
            focus,
            catalog,
            saved_devices,
            saved_devices_error,
            setup: None,
            session: None,
            retired_sessions: Vec::new(),
            live: None,
            poll_task: None,
            collection_fresh: false,
            chart_window: 300,
        }
    }

    fn open_health(&mut self, cx: &mut Context<Self>) {
        self.open_mini_app(MiniApp::DeviceHealth, cx);
    }

    fn open_mini_app(&mut self, app: MiniApp, cx: &mut Context<Self>) {
        if self.launcher.active() == Some(app) {
            return;
        }
        let Ok(_) = self.launcher.open(app) else {
            return;
        };
        self.page = 0;
        self.workspace.tool = Tool::DeviceHealth;
        // Selecting a mini-app opens setup without starting collection.
        if app == MiniApp::DeviceHealth && self.live.is_none() {
            self.setup = Some(connection::ConnectionForm::new(
                &self.catalog,
                &self.saved_devices,
                self.saved_devices_error.clone(),
                cx,
            ));
        }
        cx.notify();
    }

    fn show_launcher(&mut self, cx: &mut Context<Self>) {
        self.detach_session();
        self.setup = None;
        self.launcher.return_to_launcher();
        self.page = 0;
        cx.notify();
    }

    fn health_tabs(&self, cx: &mut Context<Self>) -> Div {
        let mut tabs = div()
            .flex()
            .gap_5()
            .px_6()
            .border_b_1()
            .border_color(rgb(BORDER));
        for (index, tool) in Tool::ALL.into_iter().enumerate() {
            let selected = self.workspace.tool == tool;
            tabs = tabs.child(
                div()
                    .id(("health-tab", index))
                    .py_3()
                    .text_sm()
                    .cursor_pointer()
                    .border_b_2()
                    .border_color(rgb(if selected { ACCENT } else { BACKGROUND }))
                    .text_color(rgb(if selected { INK } else { MUTED }))
                    .hover(|style| style.text_color(rgb(INK)))
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.workspace.tool = tool;
                        this.page = 0;
                        cx.notify();
                    }))
                    .child(if tool == Tool::DeviceHealth {
                        "Overview"
                    } else {
                        tool.title()
                    }),
            );
        }
        tabs
    }

    fn health_workspace(&self, cx: &mut Context<Self>) -> Div {
        if self.setup.is_some() {
            return self.connection_view(cx);
        }
        let main = div()
            .size_full()
            .flex()
            .flex_col()
            .child(self.workspace_header(cx))
            .child(self.health_tabs(cx));
        let Some(live) = &self.live else {
            return main.child(div().p_6().child(note(
                "No device connected",
                "Connect a device to start a health session.",
            )));
        };
        if self.workspace.capture.is_none() {
            return main.child(div().p_6().child(match &live.error {
                Some(error) => note("Collection failed", error),
                None => note("Waiting for telemetry", "The Collector is starting. Initial CPU/memory graphs need one scrape; traffic rates need two successful scrapes."),
            }));
        }
        let content = match self.workspace.tool {
            Tool::DeviceHealth => self.live_health(cx),
            Tool::Interfaces => self.interfaces(cx),
            Tool::Observations => self.observations(cx),
            Tool::Findings => self.findings(cx),
            Tool::Collection => self.collection(),
        };
        main.child(
            div()
                .id("workspace-content")
                .flex_1()
                .min_h_0()
                .overflow_y_scroll()
                .p_6()
                .child(content),
        )
    }

    fn workspace_header(&self, cx: &mut Context<Self>) -> Div {
        div()
            .flex()
            .items_center()
            .justify_between()
            .px_6()
            .py_5()
            .gap_4()
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(
                        div()
                            .text_size(px(10.))
                            .text_color(rgb(MUTED))
                            .child("WORKSPACE  /  DIAGNOSTICS"),
                    )
                    .child(div().text_size(px(24.)).child("Device health")),
            )
            .child(
                div()
                    .flex()
                    .gap_3()
                    .items_center()
                    .child(
                        div()
                            .id("connect-device")
                            .px_3()
                            .py_2()
                            .rounded_md()
                            .bg(rgb(SELECTED))
                            .cursor_pointer()
                            .on_click(cx.listener(|this, _, _, cx| this.configure_device(cx)))
                            .child("Connect device"),
                    )
                    .child(
                        div().text_xs().text_color(rgb(MUTED)).child(
                            self.live
                                .as_ref()
                                .map(|s| s.phase.label())
                                .unwrap_or("Collection off"),
                        ),
                    ),
            )
    }
}

impl Render for Workbench {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let content = match self.launcher.active() {
            None => self.landing(cx),
            Some(MiniApp::DeviceHealth) => self.health_workspace(cx),
            Some(app) => div().p_6().child(note(
                app.registration().title,
                "This tool is not available in this build.",
            )),
        };
        div()
            .size_full()
            .flex()
            .flex_col()
            .font_family("Helvetica Neue")
            .text_sm()
            .bg(rgb(BACKGROUND))
            .text_color(rgb(INK))
            .track_focus(&self.focus)
            .on_action(cx.listener(|this, _: &ShowLauncher, _, cx| this.show_launcher(cx)))
            .on_action(cx.listener(|this, _: &OpenDeviceHealth, _, cx| this.open_health(cx)))
            .on_action(|_: &Quit, _, cx| cx.quit())
            .on_action(
                cx.listener(|this, _: &NextField, window, cx| this.focus_field(false, window, cx)),
            )
            .on_action(
                cx.listener(|this, _: &PreviousField, window, cx| {
                    this.focus_field(true, window, cx)
                }),
            )
            .on_action(cx.listener(|this, _: &StartCollection, _, cx| this.start_collection(cx)))
            .child(
                div()
                    .h(px(32.))
                    .flex_shrink_0()
                    .bg(rgb(SIDEBAR))
                    .window_control_area(WindowControlArea::Drag),
            )
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.app_sidebar(cx))
                    .child(div().flex_1().min_w_0().h_full().child(content)),
            )
            .child(
                div()
                    .h(px(28.))
                    .flex_shrink_0()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_4()
                    .bg(rgb(SIDEBAR))
                    .border_t_1()
                    .border_color(rgb(BORDER))
                    .text_size(px(10.))
                    .text_color(rgb(MUTED))
                    .child(self.collection_footer())
                    .child(
                        if self.workspace.capture.is_some() && self.launcher.active().is_some() {
                            "Session metrics"
                        } else {
                            "Ready"
                        },
                    ),
            )
    }
}
fn severity_color(severity: &str) -> u32 {
    match severity {
        "critical" => CRITICAL,
        "warning" => WARNING,
        _ => MUTED,
    }
}

fn note(title: &str, body: &str) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_2()
        .p_4()
        .rounded_md()
        .bg(rgb(PANEL))
        .border_1()
        .border_color(rgb(BORDER))
        .child(
            div()
                .text_sm()
                .text_color(rgb(ACCENT))
                .child(title.to_owned()),
        )
        .child(
            div()
                .text_sm()
                .text_color(rgb(MUTED))
                .child(body.to_owned()),
        )
}

fn row(entity: &str, name: &str, value: &str) -> Div {
    div()
        .flex()
        .gap_4()
        .items_center()
        .p_3()
        .rounded_md()
        .bg(rgb(PANEL))
        .child(
            div()
                .w(px(190.))
                .text_sm()
                .text_color(rgb(ACCENT))
                .child(entity.to_owned()),
        )
        .child(div().flex_1().text_sm().child(name.to_owned()))
        .child(div().text_sm().child(value.to_owned()))
}
