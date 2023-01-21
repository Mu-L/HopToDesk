#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::two_factor_auth;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::two_factor_auth::sockets::{AuthAnswer, TFAChecker};
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::two_factor_auth::ui::Manage2FA;
#[cfg(not(any(target_os = "android", target_os = "ios")))]
use crate::two_factor_auth::{ui, TFAManager};
#[cfg(target_os = "linux")]
use crate::ipc::start_pa;
use crate::ui_cm_interface::{start_ipc, ConnectionManager, InvokeUiCM};

use hbb_common::{allow_err, config::Config, log};
use sciter::{make_args, Element, Value, HELEMENT};
use std::sync::Mutex;
use std::{ops::Deref, sync::Arc};

#[derive(Clone, Default)]
pub struct SciterHandler {
    pub element: Arc<Mutex<Option<Element>>>,
}

impl InvokeUiCM for SciterHandler {
    fn add_connection(&self, client: &crate::ui_cm_interface::Client, security_numbers: String, security_qr_code: String) {
        self.call(
            "addConnection",
            &make_args!(
                client.id,
                client.is_file_transfer,
                client.port_forward.clone(),
                client.peer_id.clone(),
                client.name.clone(),
                client.authorized,
                client.keyboard,
                client.clipboard,
                client.audio,
                client.file,
                client.restart,
                client.recording,
                security_numbers,
                security_qr_code
            ),
        );
    }

    fn remove_connection(&self, id: i32, close: bool) {
        self.call("removeConnection", &make_args!(id, close));
        if crate::ui_cm_interface::get_clients_length().eq(&0) {
            crate::platform::quit_gui();
        }
    }

    fn update_2fa_answer(&self, answer: AuthAnswer) {
        log::info!("update_2fa_answer rs");
        self.call("on_2fa_answer", &make_args!(answer.to_string()))
    }
    fn new_message(&self, id: i32, text: String) {
        self.call("newMessage", &make_args!(id, text));
    }

    fn change_theme(&self, _dark: String) {
        // TODO
    }

    fn change_language(&self) {
        // TODO
    }

    fn show_elevation(&self, show: bool) {
        self.call("showElevation", &make_args!(show));
    }
}

impl SciterHandler {
    #[inline]
    fn call(&self, func: &str, args: &[Value]) {
        if let Some(e) = self.element.lock().unwrap().as_ref() {
            allow_err!(e.call_method(func, &super::value_crash_workaround(args)[..]));
        }
    }
}

pub struct SciterConnectionManager(ConnectionManager<SciterHandler>);

impl Deref for SciterConnectionManager {
    type Target = ConnectionManager<SciterHandler>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl SciterConnectionManager {
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        std::thread::spawn(start_pa);
        let cm = ConnectionManager {
            ui_handler: SciterHandler::default(),
        };
        let cloned = cm.clone();
        std::thread::spawn(move || start_ipc(cloned));
        SciterConnectionManager(cm)
    }

    fn get_icon(&mut self) -> String {
        crate::get_icon()
    }

    fn check_click_time(&mut self, id: i32) {
        crate::ui_cm_interface::check_click_time(id);
    }

    fn get_click_time(&self) -> f64 {
        crate::ui_cm_interface::get_click_time() as _
    }

    fn switch_permission(&self, id: i32, name: String, enabled: bool) {
        crate::ui_cm_interface::switch_permission(id, name, enabled);
    }

    fn close(&self, id: i32) {
        crate::ui_cm_interface::close(id);
    }

    fn remove_disconnected_connection(&self, id: i32) {
        crate::ui_cm_interface::remove(id);
    }

    fn quit(&self) {
        crate::platform::quit_gui();
    }

    fn authorize(&self, id: i32) {
        crate::ui_cm_interface::authorize(id);
    }

    fn send_msg(&self, id: i32, text: String) {
        crate::ui_cm_interface::send_chat(id, text);
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn is_2fa_enabled(&self) -> bool {
        two_factor_auth::utils::is_2fa_enabled()
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn get_2fa_answer(&self, id: Value) -> String {
        let id = id.to_string();
        futures::executor::block_on(async move {
            match TFAManager::get_answer(&id).await {
                None => "".to_string(),
                Some(answer) => answer.to_string(),
            }
        })
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn add_2fa_callback(&self, id: Value, cb: Value) {
        let id = id.to_string();
        futures::executor::block_on(async move {
            TFAManager::add_callback(
                &id,
                Box::new(move |answer| {
                    if let Err(e) = cb.call(None, &[Value::from(answer.to_string())], None) {
                        log::warn!("Error calling callback: {e}");
                    }
                }),
            )
            .await;
        });
    }

    fn get_config_option(&self, key: String) -> String {
        Config::get_option(&key)
    }

    fn set_config_option(&self, key: String, value: String) {
        Config::set_option(key, value);
    }

    fn can_elevate(&self) -> bool {
        crate::ui_cm_interface::can_elevate()
    }
    
    fn elevate_portable(&self, id: i32) {
        crate::ui_cm_interface::elevate_portable(id);
    }

    fn get_option(&self, key: String) -> String {
        crate::ui_interface::get_option(key)
    }    
}

impl sciter::EventHandler for SciterConnectionManager {
    fn attached(&mut self, root: HELEMENT) {
        *self.ui_handler.element.lock().unwrap() = Some(Element::from(root));
    }

    sciter::dispatch_script_call! {
        fn t(String);
        fn check_click_time(i32);
        fn get_click_time();
        fn get_icon();
        fn close(i32);
        fn remove_disconnected_connection(i32);
        fn quit();
        fn authorize(i32);
        fn switch_permission(i32, String, bool);
        fn send_msg(i32, String);
        fn can_elevate();
        fn elevate_portable(i32);
        fn get_option(String);
        fn is_2fa_enabled();
        fn get_2fa_answer(Value);
        fn add_2fa_callback(Value, Value);
        fn get_config_option(String);
        fn set_config_option(String, String);
    }
}
