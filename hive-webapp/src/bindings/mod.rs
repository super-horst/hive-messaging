pub mod accounts_svc_bindings;
pub mod common_bindings;
pub mod msg_svc_bindings;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/js/qr_scanner.js")]
extern "C" {

    #[wasm_bindgen]
    pub fn scan_qr();

}
