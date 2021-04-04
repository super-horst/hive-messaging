use wasm_bindgen::prelude::*;

use serde::{Deserialize, Serialize};

pub mod accounts_svc_bindings;
pub mod common_bindings;
pub mod msg_svc_bindings;

#[derive(Clone, Debug, Hash, Deserialize, Serialize)]
pub struct GrpcStatus {
    pub code: i32,
    pub message: String,
}

#[wasm_bindgen(module = "/js/qr_scanner.js")]
extern "C" {

    #[wasm_bindgen]
    pub fn scan_qr();

}
