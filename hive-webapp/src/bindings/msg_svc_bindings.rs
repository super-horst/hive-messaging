use js_sys;
use wasm_bindgen::prelude::*;

use super::*;
use hive_commons::model::{common, messages};

#[wasm_bindgen(module = "/js/generated/messages_svc_pb.js")]
extern "C" {
    pub type Envelope;

    #[wasm_bindgen(constructor)]
    pub fn new() -> Envelope;

    #[wasm_bindgen(method)]
    pub fn getEphemeralSessionKey_asU8(this: &Envelope) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setEphemeralSessionKey(this: &Envelope, session_key: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getEncryptedSession_asU8(this: &Envelope) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setEncryptedSession(this: &Envelope, session_key: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getEncryptedPayload_asU8(this: &Envelope) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setEncryptedPayload(this: &Envelope, payload: js_sys::Uint8Array);
}

#[wasm_bindgen(module = "/js/generated/messages_svc_pb.js")]
extern "C" {
    pub type MessageSendResult;
}

#[wasm_bindgen(
    module = "/js/generated/messages_svc_pb.js",
    js_name = "MessageFilter.State"
)]
pub enum MessageFilterState {
    UNKNOWN,
    NEW,
}

#[wasm_bindgen(module = "/js/generated/messages_svc_pb.js")]
extern "C" {
    pub type MessageFilter;

    #[wasm_bindgen(constructor)]
    pub fn new() -> MessageFilter;

    #[wasm_bindgen(method)]
    pub fn getState(this: &MessageFilter) -> MessageFilterState;

    #[wasm_bindgen(method)]
    pub fn setState(this: &MessageFilter, state: MessageFilterState);

    #[wasm_bindgen(method)]
    pub fn getDst(this: &MessageFilter) -> common_bindings::Peer;

    #[wasm_bindgen(method)]
    pub fn setDst(this: &MessageFilter, dst: common_bindings::Peer);
}

#[wasm_bindgen(module = "/js/generated/messages_svc_grpc_web_pb.js")]
extern "C" {
    pub type MessagesPromiseClient;

    #[wasm_bindgen(constructor)]
    pub fn new(hostname: String) -> MessagesPromiseClient;

    #[wasm_bindgen(method)]
    pub fn sendMessage(this: &MessagesPromiseClient, request: Envelope) -> js_sys::Promise;

    #[wasm_bindgen(method)]
    pub fn getMessages(this: &MessagesPromiseClient, filter: MessageFilter) -> js_sys::Promise;
}
