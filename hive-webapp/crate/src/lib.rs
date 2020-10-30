#![recursion_limit = "512"]
use wasm_bindgen::prelude::*;


mod app;
mod contacts;
mod bindings;
mod storage;
mod transport;


#[wasm_bindgen(start)]
pub fn main() {
    wasm_logger::init(wasm_logger::Config::default());
    set_panic_hook();
    yew::start_app::<app::AppContainer>();
}

fn set_panic_hook() {
    // When the `console_error_panic_hook` feature is enabled, we can call the
    // `set_panic_hook` function to get better error messages if we ever panic.
    console_error_panic_hook::set_once();
}