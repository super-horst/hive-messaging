use wasm_bindgen::prelude::*;
use js_sys;
use wasm_bindgen_futures::futures_0_3::JsFuture;
use wasm_bindgen_futures::futures_0_3::spawn_local;
use wasm_bindgen::JsCast;
use hive_commons::crypto::*;
use hive_commons::model::*;

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

    let client = accounts_svc_bindings::AccountsPromiseClient::new("http://localhost:8080".to_string());

    spawn_local(async move {
        create_account(&client).await;
    });

    log("Hello from DoingItAgain!");
}


async fn create_account(client: &accounts_svc_bindings::AccountsPromiseClient) {

    log("create_account entry");
    let key = PrivateKey::generate().unwrap();

    let challenge = signing::sign_challenge(&key).unwrap();
    let unsig_challenge = common::signed_challenge::Challenge::decode(challenge.challenge.clone()).unwrap();

    log(&format!("Challenge timestamp {}", unsig_challenge.timestamp));

    let bound_challenge = common_bindings::SignedChallenge::new();
    bound_challenge.setChallenge(js_sys::Uint8Array::from(&challenge.challenge[..]));
    bound_challenge.setSignature(js_sys::Uint8Array::from(&challenge.signature[..]));

    let promise = client.createAccount(bound_challenge);
    let value = JsFuture::from(promise).await.unwrap();

    let resp: common_bindings::Certificate = value.dyn_into().expect("response not working...");

    let tbs_cert = common::certificate::TbsCertificate::decode(resp.getCertificate_asU8().to_vec()).unwrap();

    log(&format!("Certificate serial {}", tbs_cert.uuid));
}
