use js_sys;
use wasm_bindgen::prelude::*;

use super::*;
use hive_commons::model::{messages, common};


#[wasm_bindgen(module = "/js/generated/messages_svc_pb.js")]
extern "C" {
    pub type EncryptionParameters;

    #[wasm_bindgen(constructor)]
    pub fn new() -> EncryptionParameters;

    #[wasm_bindgen(method)]
    pub fn getRatchetKey_asU8(this: &EncryptionParameters) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setRatchetKey(this: &EncryptionParameters, key: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getChainIdx(this: &EncryptionParameters) -> u64;

    #[wasm_bindgen(method)]
    pub fn setChainIdx(this: &EncryptionParameters, idx: u64);

    #[wasm_bindgen(method)]
    pub fn getPrevChainCount(this: &EncryptionParameters) -> u64;

    #[wasm_bindgen(method)]
    pub fn setPrevChainCount(this: &EncryptionParameters, idx: u64);
}

#[wasm_bindgen(module = "/js/generated/messages_svc_pb.js")]
extern "C" {
    pub type KeyExchange;

    #[wasm_bindgen(constructor)]
    pub fn new() -> KeyExchange;

    #[wasm_bindgen(method)]
    pub fn getOrigin(this: &KeyExchange) -> common_bindings::Peer;

    #[wasm_bindgen(method)]
    pub fn setOrigin(this: &KeyExchange, origin: common_bindings::Peer);

    #[wasm_bindgen(method)]
    pub fn getEphemeralKey_asU8(this: &KeyExchange) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setEphemeralKey(this: &KeyExchange, ephemeral_key: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getOneTimeKey_asU8(this: &KeyExchange) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setOneTimeKey(this: &KeyExchange, one_time_key: js_sys::Uint8Array);
}

impl From<messages::KeyExchange> for KeyExchange {
    fn from(exchange: messages::KeyExchange) -> Self {
        // TODO error handling
        let peer: common::Peer = exchange.origin.unwrap().into();
        let ephemeral_key = js_sys::Uint8Array::from(&exchange.ephemeral_key[..]);
        let one_time_key = js_sys::Uint8Array::from(&exchange.one_time_key[..]);

        let binding = Self::new();
        binding.setOrigin(peer.into());
        binding.setEphemeralKey(ephemeral_key);
        binding.setOneTimeKey(one_time_key);

        return binding;
    }
}

impl Into<messages::KeyExchange> for KeyExchange {
    fn into(self) -> messages::KeyExchange {
        let peer: Option<common::Peer> = Some(self.getOrigin().into());

        return messages::KeyExchange {
            origin: peer.into(),
            ephemeral_key: self.getEphemeralKey_asU8().to_vec(),
            one_time_key: self.getOneTimeKey_asU8().to_vec(),
        };
    }
}

#[wasm_bindgen(module = "/js/generated/messages_svc_pb.js")]
extern "C" {
    pub type PayloadHeader;

    #[wasm_bindgen(constructor)]
    pub fn new() -> PayloadHeader;

    #[wasm_bindgen(method)]
    pub fn getIdentifier(this: &PayloadHeader) -> String;

    #[wasm_bindgen(method)]
    pub fn setIdentifier(this: &PayloadHeader, identifier: String);
}

#[wasm_bindgen(module = "/js/generated/messages_svc_pb.js")]
extern "C" {
    pub type Payload;

    #[wasm_bindgen(constructor)]
    pub fn new() -> Payload;

    #[wasm_bindgen(method)]
    pub fn getPayload(this: &Payload) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setPayload(this: &Payload, content: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getPayloadHeader(this: &Payload) -> PayloadHeader;

    #[wasm_bindgen(method)]
    pub fn setPayloadHeader(this: &Payload, content: PayloadHeader);
}

#[wasm_bindgen(module = "/js/generated/messages_svc_pb.js")]
extern "C" {
    pub type MessageEnvelope;

    #[wasm_bindgen(constructor)]
    pub fn new() -> MessageEnvelope;

    #[wasm_bindgen(method)]
    pub fn getDst(this: &MessageEnvelope) -> common_bindings::Peer;

    #[wasm_bindgen(method)]
    pub fn setDst(this: &MessageEnvelope, dst: common_bindings::Peer);

    #[wasm_bindgen(method)]
    pub fn getParams(this: &MessageEnvelope) -> EncryptionParameters;

    #[wasm_bindgen(method)]
    pub fn setParams(this: &MessageEnvelope, params: EncryptionParameters);

    #[wasm_bindgen(method)]
    pub fn getKeyExchange(this: &MessageEnvelope) -> KeyExchange;

    #[wasm_bindgen(method)]
    pub fn setKeyExchange(this: &MessageEnvelope, params: KeyExchange);

    #[wasm_bindgen(method)]
    pub fn getPayload(this: &MessageEnvelope) -> Payload;

    #[wasm_bindgen(method)]
    pub fn setPayload(this: &MessageEnvelope, payload: Payload);
}

#[wasm_bindgen(module = "/js/generated/messages_svc_pb.js")]
extern "C" {
    pub type MessageSendResult;
}

#[wasm_bindgen(module = "/js/generated/messages_svc_grpc_web_pb.js")]
extern "C" {
    pub type MessagesPromiseClient;

    #[wasm_bindgen(constructor)]
    pub fn new(hostname: String) -> MessagesPromiseClient;

    #[wasm_bindgen(method)]
    pub fn sendMessage(this: &MessagesPromiseClient, request: MessageEnvelope) -> js_sys::Promise;
}
