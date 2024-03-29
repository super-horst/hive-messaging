use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    fn prompt(s: &str)-> String;
}

mod identity;
pub use identity::*;

mod error;
pub use error::*;

mod storage;
pub use storage::*;

mod contacts;
pub use contacts::*;

mod messaging;
pub use messaging::*;
