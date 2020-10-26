use wasm_bindgen::prelude::*;
use js_sys;

#[wasm_bindgen(module = "/generated/common_pb.js")]
extern "C" {
    pub type Peer;

    #[wasm_bindgen(constructor)]
    pub fn new() -> Peer;

    #[wasm_bindgen(method)]
    pub fn getIdentity_asU8(this: &Peer) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setIdentity(this: &Peer, id: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getNamespace(this: &Peer) -> String;

    #[wasm_bindgen(method)]
    pub fn setNamespace(this: &Peer, namespace: String);
}

#[wasm_bindgen(module = "/generated/common_pb.js")]
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

#[wasm_bindgen(module = "/generated/common_pb.js")]
extern "C" {
    pub type KeyExchange;

    #[wasm_bindgen(constructor)]
    pub fn new() -> KeyExchange;

    #[wasm_bindgen(method)]
    pub fn getOrigin(this: &KeyExchange) -> Peer;

    #[wasm_bindgen(method)]
    pub fn setOrigin(this: &KeyExchange, origin: Peer);

    #[wasm_bindgen(method)]
    pub fn getEphemeralKey_asU8(this: &KeyExchange) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setEphemeralKey(this: &KeyExchange, ephemeral_key: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getOneTimeKey_asU8(this: &KeyExchange) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setOneTimeKey(this: &KeyExchange, one_time_key: js_sys::Uint8Array);
}

#[wasm_bindgen(module = "/generated/common_pb.js")]
extern "C" {
    pub type SignedChallenge;

    #[wasm_bindgen(constructor)]
    pub fn new() -> SignedChallenge;

    #[wasm_bindgen(method)]
    pub fn getChallenge_asU8(this: &SignedChallenge) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setChallenge(this: &SignedChallenge, challenge: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getSignature_asU8(this: &SignedChallenge) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setSignature(this: &SignedChallenge, signature: js_sys::Uint8Array);
}

#[wasm_bindgen(module = "/generated/common_pb.js")]
extern "C" {
    pub type Certificate;

    #[wasm_bindgen(constructor)]
    pub fn new() -> Certificate;

    #[wasm_bindgen(method)]
    pub fn getCertificate_asU8(this: &Certificate) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setCertificate(this: &Certificate, certificate: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getSignature_asU8(this: &Certificate) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setSignature(this: &Certificate, signature: js_sys::Uint8Array);
}
