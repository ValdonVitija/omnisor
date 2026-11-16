use super::{icons::tool_icon, *};
use app::launcher::MINI_APPS;
use gpui::FontWeight;

impl Workbench {
    pub(super) fn app_sidebar(&self, cx: &mut Context<Self>) -> Div {
        let mut apps = div()
            .id("mini-apps")
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .flex()
            .flex_col()
            .gap_1()
            .px_3();
        for (index, registration) in MINI_APPS.iter().enumerate() {
            let app = registration.id;
            let selected = self.launcher.active() == Some(app);
            let color = if selected { INK } else { MUTED };
            let title = if app == MiniApp::ConfigurationCompare {
                "Config compare"
            } else {
                registration.title
            };
            let mut item = div()
                .id(("mini-app", index))
                .h(px(38.))
                .flex_shrink_0()
                .flex()
                .items_center()
                .gap_2()
                .px_3()
                .rounded_md()
                .bg(rgb(if selected { SELECTED } else { SIDEBAR }))
                .text_size(px(12.))
                .text_color(rgb(color))
                .child(div().flex_shrink_0().child(tool_icon(
                    app,
                    if selected { ACCENT } else { MUTED },
                    18.,
                )))
                .child(div().flex_1().min_w_0().truncate().child(title));
            if registration.available {
                item = item
                    .cursor_pointer()
                    .hover(|style| style.bg(rgb(PANEL)).text_color(rgb(INK)))
                    .on_click(cx.listener(move |this, _, _, cx| this.open_mini_app(app, cx)));
            } else {
                item = item.child(
                    div()
                        .flex_shrink_0()
                        .text_size(px(9.))
                        .text_color(rgb(MUTED))
                        .child("Soon"),
                );
            }
            apps = apps.child(item);
        }
        div()
            .w(px(216.))
            .h_full()
            .flex_shrink_0()
            .flex()
            .flex_col()
            .bg(rgb(SIDEBAR))
            .border_r_1()
            .border_color(rgb(BORDER))
            .child(
                div()
                    .id("workspace-home")
                    .flex()
                    .items_center()
                    .gap_2()
                    .px_6()
                    .pt_3()
                    .pb_8()
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _, _, cx| this.show_launcher(cx)))
                    .child(tool_icon(MiniApp::DeviceHealth, ACCENT, 24.))
                    .child(
                        div()
                            .text_size(px(20.))
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("omnisor"),
                    ),
            )
            .child(
                div()
                    .px_6()
                    .pb_3()
                    .text_size(px(10.))
                    .text_color(rgb(MUTED))
                    .child("TOOLS"),
            )
            .child(apps)
            .child(
                div()
                    .mx_5()
                    .py_4()
                    .border_t_1()
                    .border_color(rgb(BORDER))
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(div().text_xs().text_color(rgb(INK)).child("On this laptop"))
                    .child(
                        div()
                            .text_size(px(10.))
                            .text_color(rgb(MUTED))
                            .child(format!("Omnisor {}", env!("CARGO_PKG_VERSION"))),
                    ),
            )
    }

    pub(super) fn landing(&self, cx: &mut Context<Self>) -> Div {
        div().size_full().flex().flex_col().child(self.workspace_header(cx))
            .child(div().id("start-scroll").flex_1().min_h_0().overflow_y_scroll()
                .child(div().flex().flex_col().items_center().px_6().py_12()
                    .child(div().w_full().max_w(px(700.)).flex().flex_col().gap_5()
                        .child(div().text_size(px(11.)).text_color(rgb(ACCENT)).child("DEVICE HEALTH"))
                        .child(div().text_size(px(32.)).child("See how your device is performing."))
                        .child(div().text_sm().text_color(rgb(MUTED)).child("Connect a device to inspect resource usage, interface state, and traffic over time."))
                        .child(div().p_6().rounded_lg().bg(rgb(PANEL)).border_1().border_color(rgb(BORDER))
                            .child(div().text_lg().child("Start a health session"))
                            .child(div().mt_3().text_sm().text_color(rgb(MUTED)).child("Enter device access details. Omnisor selects and starts the monitoring components when you connect."))
                            .child(div().id("open-device-setup").mt_5().px_4().py_3().rounded_md().bg(rgb(0xd5e3e6)).text_color(rgb(0x182024)).cursor_pointer()
                                .on_click(cx.listener(|this,_,_,cx|this.configure_device(cx))).child("Connect a device  →")))
                        .child(div().flex().gap_4()
                            .child(div().id("live-demo").text_sm().text_color(rgb(ACCENT)).cursor_pointer().on_click(cx.listener(|this,_,_,cx|this.start_demo(cx))).child("Try a simulated device  →")))
                        .child(div().text_xs().text_color(rgb(MUTED)).child("Collection runs on this laptop, only when you start a session.")))))
    }
}
