use wasm_bindgen::__rt::core::borrow::Borrow;
use wasm_bindgen::__rt::std::sync::Arc;

use crate::bindings::accounts_svc_bindings::AccountsPromiseClient;
use crate::bindings::msg_svc_bindings::MessagesPromiseClient;

fn create_service_url() -> String {
    let location = web_sys::window().unwrap().location();

    // TODO error handling
    format!(
        "{}//{}",
        location.protocol().unwrap(),
        location.host().unwrap()
    )
    .to_string()
}

#[derive(Clone)]
pub struct ConnectionManager {
    accounts: Arc<AccountsPromiseClient>,
    messages: Arc<MessagesPromiseClient>,
}

impl ConnectionManager {
    pub fn new() -> ConnectionManager {
        let service_url = create_service_url();

        let accounts = AccountsPromiseClient::new(service_url.clone());
        let messages = MessagesPromiseClient::new(service_url.clone());

        ConnectionManager {
            accounts: Arc::new(accounts),
            messages: Arc::new(messages),
        }
    }

    pub fn accounts(&self) -> &AccountsPromiseClient {
        self.accounts.borrow()
    }

    pub fn messages(&self) -> &MessagesPromiseClient {
        self.messages.borrow()
    }
}
