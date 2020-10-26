use wasm_bindgen::prelude::*;
use js_sys;
use wasm_bindgen_futures::futures_0_3::JsFuture;

use hive_commons::crypto::*;

mod bindings;
use bindings::common_bindings;
use bindings::msg_svc_bindings;
use bindings::accounts_svc_bindings;

// lifted from the `console_log` example
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}

#[wasm_bindgen(start)]
pub fn run() {
    set_panic_hook();
    log(&format!("Hello from {}!", "ItsaMeMario"));

    let key = PrivateKey::generate().unwrap();

    log("Hello from DoingItAgain!");
    let challenge = signing::sign_challenge(&key).unwrap();

    let bound_challenge = common_bindings::SignedChallenge::new();
    bound_challenge.setChallenge(js_sys::Uint8Array::from(&challenge.challenge[..]));
    bound_challenge.setSignature(js_sys::Uint8Array::from(&challenge.signature[..]));

    let client = accounts_svc_bindings::AccountsPromiseClient::new("http://localhost:8080".to_string());
    log("Hello from DoingItAgain!");

    let promise = client.createAccount(bound_challenge);
    JsFuture::from(promise);
}

fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function to get better error messages if we ever panic.
    console_error_panic_hook::set_once();
}
