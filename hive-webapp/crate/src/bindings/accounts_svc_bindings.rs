use wasm_bindgen::prelude::*;
use js_sys;

use super::*;

#[wasm_bindgen(module = "/generated/accounts_svc_pb.js")]
extern "C" {
    pub type UpdateKeyResult;
}


#[wasm_bindgen(module = "/generated/accounts_svc_grpc_web_pb.js")]
extern "C" {
    pub type AccountsPromiseClient;

    #[wasm_bindgen(constructor)]
    pub fn new(hostname: String) -> AccountsPromiseClient;

    #[wasm_bindgen(method)]
    pub fn createAccount(this: &AccountsPromiseClient, request: common_bindings::SignedChallenge) -> js_sys::Promise;
}
