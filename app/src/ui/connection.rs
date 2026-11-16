use super::{input::TextInput, *};
use collection::{
    Catalog, CollectionPlan, DeviceIdentity, Source,
    access::{Credentials, DeviceTarget, RequiredCredentials, RuntimeTools, SavedDevices},
};
use gpui::{Entity, KeyBinding};

pub(super) struct ConnectionForm {
    saved_id: Option<String>,
    profile: String,
    choosing_device: bool,
    choosing_family: bool,
    required: RequiredCredentials,
    target: Entity<TextInput>,
    username: Entity<TextInput>,
    auth: Entity<TextInput>,
    privacy: Entity<TextInput>,
    access_key: Entity<TextInput>,
    error: Option<String>,
}
impl ConnectionForm {
    pub fn new(
        catalog: &Catalog,
        saved: &SavedDevices,
        error: Option<String>,
        cx: &mut Context<Workbench>,
    ) -> Self {
        let saved_id = saved.devices.first().map(|device| device.id.clone());
        let required = saved_id
            .as_ref()
            .and_then(|id| {
                catalog
                    .credentials_for(&DeviceTarget::Saved(id.clone()), saved)
                    .ok()
            })
            .unwrap_or(RequiredCredentials::None);
        Self {
            saved_id,
            profile: String::new(),
            choosing_device: false,
            choosing_family: false,
            required,
            target: input("", "192.0.2.10 or router.example.com", false, cx),
            username: input("", "Monitoring username", false, cx),
            auth: input("", "Authentication password", true, cx),
            privacy: input("", "Privacy password", true, cx),
            access_key: input("", "Monitoring access credential", true, cx),
            error,
        }
    }
    fn target(&self, cx: &gpui::App) -> DeviceTarget {
        match &self.saved_id {
            Some(id) => DeviceTarget::Saved(id.clone()),
            None => DeviceTarget::New {
                profile_id: self.profile.clone(),
                address: self.target.read(cx).content.to_string(),
            },
        }
    }
    fn fields(&self) -> Vec<&Entity<TextInput>> {
        let mut fields = Vec::new();
        if self.saved_id.is_none() {
            fields.push(&self.target);
        }
        match self.required {
            RequiredCredentials::MonitoringAccount => {
                fields.extend([&self.username, &self.auth, &self.privacy])
            }
            RequiredCredentials::ReadOnlyCommunity | RequiredCredentials::BearerToken => {
                fields.push(&self.access_key)
            }
            RequiredCredentials::None => {}
        }
        fields
    }
    fn reset_credentials(&mut self, cx: &mut Context<Workbench>) {
        for input in [&self.username, &self.auth, &self.privacy, &self.access_key] {
            input.update(cx, |input, cx| {
                input.clear();
                cx.notify();
            });
        }
        self.error = None;
    }
    fn plan(
        &self,
        catalog: &Catalog,
        saved: &SavedDevices,
        cx: &gpui::App,
    ) -> Result<CollectionPlan, String> {
        if self.saved_id.is_none() && self.profile.is_empty() {
            return Err(
                "Choose the device family so Omnisor can determine its connection requirements."
                    .into(),
            );
        }
        let read = |input: &Entity<TextInput>| input.read(cx).content.to_string();
        catalog.plan_device(
            &self.target(cx),
            saved,
            Credentials {
                username: read(&self.username),
                password: read(&self.auth),
                privacy_password: read(&self.privacy),
                access_key: read(&self.access_key),
            },
            &RuntimeTools::discover(),
        )
    }
}

impl Workbench {
    pub(super) fn connection_view(&self, cx: &mut Context<Self>) -> Div {
        let Some(form) = &self.setup else {
            return div();
        };
        let saved = form
            .saved_id
            .as_deref()
            .and_then(|id| self.saved_devices.get(id).ok());
        let mut card = section("DEVICE");
        if !self.saved_devices.devices.is_empty() {
            card = card.child(
                div()
                    .id("choose-device")
                    .flex()
                    .justify_between()
                    .items_center()
                    .px_3()
                    .py_3()
                    .rounded_md()
                    .bg(rgb(PANEL))
                    .border_1()
                    .border_color(rgb(BORDER))
                    .cursor_pointer()
                    .on_click(cx.listener(|this, _, _, cx| {
                        if let Some(form) = &mut this.setup {
                            form.choosing_device = !form.choosing_device;
                        }
                        cx.notify();
                    }))
                    .child(
                        saved
                            .map(|device| device.name.clone())
                            .unwrap_or_else(|| "New device".into()),
                    )
                    .child(div().text_color(rgb(MUTED)).child("⌄")),
            );
            if form.choosing_device {
                let mut choices = div()
                    .id("saved-device-list")
                    .max_h(px(180.))
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap_1();
                for (index, device) in self.saved_devices.devices.iter().enumerate() {
                    let id = device.id.clone();
                    choices = choices.child(
                        div()
                            .id(("saved-choice", index))
                            .px_3()
                            .py_2()
                            .text_sm()
                            .cursor_pointer()
                            .hover(|s| s.bg(rgb(SELECTED)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.choose_connection_device(Some(id.clone()), cx)
                            }))
                            .child(format!("{} · {}", device.name, device.address)),
                    );
                }
                choices = choices.child(
                    div()
                        .id("new-device")
                        .px_3()
                        .py_2()
                        .text_sm()
                        .text_color(rgb(ACCENT))
                        .cursor_pointer()
                        .hover(|s| s.bg(rgb(SELECTED)))
                        .on_click(
                            cx.listener(|this, _, _, cx| this.choose_connection_device(None, cx)),
                        )
                        .child("+ Another device"),
                );
                card = card.child(choices);
            }
        }
        if let Some(device) = saved {
            let label = self
                .catalog
                .resolve(&device.profile_id)
                .ok()
                .and_then(|p| p.device.map(|d| d.label))
                .unwrap_or_default();
            card = card.child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(div().text_sm().child(device.address.clone()))
                    .child(div().text_xs().text_color(rgb(MUTED)).child(label)),
            );
        } else {
            let label = self
                .catalog
                .profiles
                .get(&form.profile)
                .and_then(|p| p.device.as_ref())
                .map(|d| d.label.clone())
                .unwrap_or_else(|| "Select device family".into());
            card = card.child(field("Device address", &form.target)).child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(MUTED))
                            .child("Device family"),
                    )
                    .child(
                        div()
                            .id("choose-family")
                            .flex()
                            .justify_between()
                            .px_3()
                            .py_3()
                            .rounded_md()
                            .bg(rgb(PANEL))
                            .border_1()
                            .border_color(rgb(BORDER))
                            .text_sm()
                            .cursor_pointer()
                            .on_click(cx.listener(|this, _, _, cx| {
                                if let Some(form) = &mut this.setup {
                                    form.choosing_family = !form.choosing_family;
                                }
                                cx.notify();
                            }))
                            .child(label)
                            .child("⌄"),
                    ),
            );
            if form.choosing_family {
                let mut families = div()
                    .id("device-family-list")
                    .max_h(px(180.))
                    .overflow_y_scroll()
                    .flex()
                    .flex_col()
                    .gap_1();
                for (index, profile) in self
                    .catalog
                    .profiles
                    .values()
                    .filter(|p| p.device.is_some())
                    .enumerate()
                {
                    let id = profile.id.clone();
                    families = families.child(
                        div()
                            .id(("family-choice", index))
                            .px_3()
                            .py_2()
                            .text_sm()
                            .cursor_pointer()
                            .hover(|s| s.bg(rgb(SELECTED)))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.choose_connection_family(&id, cx)
                            }))
                            .child(profile.device.as_ref().unwrap().label.clone()),
                    );
                }
                card = card.child(families);
            }
        }
        match form.required {
            RequiredCredentials::MonitoringAccount => {
                card = card
                    .child(field("Monitoring username", &form.username))
                    .child(field("Authentication password", &form.auth))
                    .child(field("Privacy password", &form.privacy))
            }
            RequiredCredentials::ReadOnlyCommunity => {
                card = card.child(field("Read-only monitoring community", &form.access_key))
            }
            RequiredCredentials::BearerToken => {
                card = card.child(field("Monitoring access token", &form.access_key))
            }
            RequiredCredentials::None => {}
        }
        let mut content = div()
            .w_full()
            .max_w(px(580.))
            .flex()
            .flex_col()
            .gap_5()
            .child(div().text_size(px(28.)).child("Connect a device"))
            .child(
                div()
                    .text_sm()
                    .text_color(rgb(MUTED))
                    .child("Provide device access. Omnisor handles metric collection."),
            )
            .child(card);
        if let Some(error) = &form.error {
            content = content.child(note("Check device access", error));
        }
        content = content.child(
            div()
                .flex()
                .justify_between()
                .items_center()
                .gap_4()
                .child(div().flex_1().text_xs().text_color(rgb(MUTED)).child(
                    if form.required == RequiredCredentials::None && saved.is_some() {
                        "Access is configured for this device."
                    } else {
                        "Credentials are used for this session only."
                    },
                ))
                .child(
                    div()
                        .id("start-collection")
                        .px_5()
                        .py_3()
                        .rounded_md()
                        .bg(rgb(0xd5e3e6))
                        .text_color(rgb(0x182024))
                        .cursor_pointer()
                        .on_click(cx.listener(|this, _, _, cx| this.start_collection(cx)))
                        .child("Connect →"),
                ),
        );
        div()
            .size_full()
            .flex()
            .flex_col()
            .child(self.workspace_header(cx))
            .child(
                div()
                    .id("connection-scroll")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .p_6()
                    .child(div().flex().justify_center().py_6().child(content)),
            )
    }
    fn choose_connection_device(&mut self, id: Option<String>, cx: &mut Context<Self>) {
        if let Some(form) = &mut self.setup {
            form.reset_credentials(cx);
            form.saved_id = id;
            form.profile.clear();
            form.target.update(cx, |input, cx| {
                input.clear();
                cx.notify();
            });
            form.choosing_device = false;
            form.choosing_family = false;
            form.required = self
                .catalog
                .credentials_for(&form.target(cx), &self.saved_devices)
                .unwrap_or(RequiredCredentials::None);
        }
        cx.notify();
    }
    fn choose_connection_family(&mut self, id: &str, cx: &mut Context<Self>) {
        if let Some(form) = &mut self.setup {
            form.reset_credentials(cx);
            form.profile = id.into();
            form.choosing_family = false;
            form.required = self
                .catalog
                .credentials_for(&form.target(cx), &self.saved_devices)
                .unwrap_or(RequiredCredentials::None);
        }
        cx.notify();
    }
    pub(super) fn start_collection(&mut self, cx: &mut Context<Self>) {
        let Some(form) = &self.setup else {
            return;
        };
        let result = form
            .plan(&self.catalog, &self.saved_devices, cx)
            .and_then(collection::Session::start);
        match result {
            Ok(session) => self.attach_session(session, cx),
            Err(error) => {
                if let Some(form) = &mut self.setup {
                    form.error = Some(error);
                }
                cx.notify();
            }
        }
    }
    pub(super) fn start_demo(&mut self, cx: &mut Context<Self>) {
        let result = collection::Session::start(CollectionPlan {
            device: DeviceIdentity {
                id: "synthetic-device".into(),
                name: "Simulated router".into(),
                vendor: "Omnisor lab".into(),
                model: "Synthetic device".into(),
                device_type: "Router".into(),
                os: "Synthetic".into(),
                os_version: String::new(),
            },
            profile_id: "synthetic".into(),
            interval_seconds: 2,
            collector: RuntimeTools::discover().collector,
            source: Source::Synthetic,
        });
        match result {
            Ok(session) => self.attach_session(session, cx),
            Err(error) => {
                self.configure_device(cx);
                if let Some(form) = &mut self.setup {
                    form.error = Some(error);
                }
                cx.notify();
            }
        }
    }
    pub(super) fn focus_field(&self, reverse: bool, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(form) = &self.setup {
            let fields = form.fields();
            if fields.is_empty() {
                return;
            }
            let active = fields
                .iter()
                .position(|input| input.read(cx).focus_handle.is_focused(window));
            let index = match active {
                Some(index) if reverse => (index + fields.len() - 1) % fields.len(),
                Some(index) => (index + 1) % fields.len(),
                None => 0,
            };
            fields[index].read(cx).focus_handle.focus(window);
        }
    }
}
fn input(
    value: &str,
    placeholder: &str,
    secret: bool,
    cx: &mut Context<Workbench>,
) -> Entity<TextInput> {
    cx.new(|cx| TextInput::new(value, placeholder, secret, cx))
}
fn field(label: &str, input: &Entity<TextInput>) -> Div {
    div()
        .flex()
        .flex_col()
        .min_w_0()
        .gap_2()
        .child(
            div()
                .text_xs()
                .text_color(rgb(MUTED))
                .child(label.to_owned()),
        )
        .child(input.clone())
}
fn section(title: &str) -> Div {
    div()
        .flex()
        .flex_col()
        .gap_4()
        .p_5()
        .rounded_lg()
        .border_1()
        .border_color(rgb(BORDER))
        .child(
            div()
                .text_size(px(10.))
                .text_color(rgb(MUTED))
                .child(title.to_owned()),
        )
}
pub(super) fn init(cx: &mut gpui::App) {
    cx.bind_keys([
        KeyBinding::new("tab", super::NextField, Some("TextInput")),
        KeyBinding::new("shift-tab", super::PreviousField, Some("TextInput")),
    ]);
}
