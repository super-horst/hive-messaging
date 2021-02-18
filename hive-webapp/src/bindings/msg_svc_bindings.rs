use js_sys;
use wasm_bindgen::prelude::*;

use super::*;
use hive_commons::model::{common, messages};

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

impl From<messages::EncryptionParameters> for EncryptionParameters {
    fn from(parameters: messages::EncryptionParameters) -> Self {
        let ratchet_key = js_sys::Uint8Array::from(&parameters.ratchet_key[..]);

        let binding = Self::new();
        binding.setRatchetKey(ratchet_key);
        binding.setChainIdx(parameters.chain_idx);
        binding.setPrevChainCount(parameters.prev_chain_count);

        return binding;
    }
}

impl Into<messages::EncryptionParameters> for EncryptionParameters {
    fn into(self) -> messages::EncryptionParameters {
        return messages::EncryptionParameters {
            ratchet_key: self.getRatchetKey_asU8().to_vec(),
            chain_idx: self.getChainIdx(),
            prev_chain_count: self.getPrevChainCount(),
        };
    }
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
    pub type Envelope;

    #[wasm_bindgen(constructor)]
    pub fn new() -> Envelope;

    #[wasm_bindgen(method)]
    pub fn getDst(this: &Envelope) -> common_bindings::Peer;

    #[wasm_bindgen(method)]
    pub fn setDst(this: &Envelope, dst: common_bindings::Peer);

    #[wasm_bindgen(method)]
    pub fn getParams(this: &Envelope) -> EncryptionParameters;

    #[wasm_bindgen(method)]
    pub fn setParams(this: &Envelope, params: EncryptionParameters);

    #[wasm_bindgen(method)]
    pub fn getKeyExchange(this: &Envelope) -> KeyExchange;

    #[wasm_bindgen(method)]
    pub fn setKeyExchange(this: &Envelope, params: KeyExchange);

    #[wasm_bindgen(method)]
    pub fn getEncryptedPayload_asU8(this: &Envelope) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setEncryptedPayload(this: &Envelope, payload: js_sys::Uint8Array);
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
    pub fn sendMessage(this: &MessagesPromiseClient, request: Envelope) -> js_sys::Promise;
}
