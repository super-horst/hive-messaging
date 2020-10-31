use js_sys;
use wasm_bindgen::prelude::*;

use super::*;

#[wasm_bindgen(module = "/generated/messages_svc_pb.js")]
extern "C" {
    pub type Payload;

    #[wasm_bindgen(constructor)]
    pub fn new() -> Payload;

    #[wasm_bindgen(method)]
    pub fn getEncryptedContent_asU8(this: &Payload) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setEncryptedContent(this: &Payload, content: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getKeyEx(this: &Payload) -> common_bindings::KeyExchange;

    #[wasm_bindgen(method)]
    pub fn setKeyEx(this: &Payload, exchange: common_bindings::KeyExchange);
}

#[wasm_bindgen(module = "/generated/messages_svc_pb.js")]
extern "C" {
    pub type MessageEnvelope;

    #[wasm_bindgen(constructor)]
    pub fn new() -> MessageEnvelope;

    #[wasm_bindgen(method)]
    pub fn getPayload(this: &MessageEnvelope) -> Payload;

    #[wasm_bindgen(method)]
    pub fn setPayload(this: &MessageEnvelope, payload: Payload);

    #[wasm_bindgen(method)]
    pub fn getParams(this: &MessageEnvelope) -> common_bindings::EncryptionParameters;

    #[wasm_bindgen(method)]
    pub fn setParams(this: &MessageEnvelope, params: common_bindings::EncryptionParameters);

    #[wasm_bindgen(method)]
    pub fn getDst(this: &MessageEnvelope) -> common_bindings::Peer;

    #[wasm_bindgen(method)]
    pub fn setDst(this: &MessageEnvelope, dst: common_bindings::Peer);
}

#[wasm_bindgen(module = "/generated/messages_svc_pb.js")]
extern "C" {
    pub type MessageSendResult;
}

#[wasm_bindgen(module = "/generated/messages_svc_grpc_web_pb.js")]
extern "C" {
    pub type MessagesPromiseClient;

    #[wasm_bindgen(constructor)]
    pub fn new(hostname: String) -> MessagesPromiseClient;

    #[wasm_bindgen(method)]
    pub fn sendMessage(this: &MessagesPromiseClient, request: MessageEnvelope) -> js_sys::Promise;

}
