use wasm_bindgen::prelude::*;
use js_sys;

use hive_commons::model::common;

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

impl From<common::Peer> for Peer {
    fn from(peer: common::Peer) -> Self {
        let identity = js_sys::Uint8Array::from(&peer.identity[..]);

        let binding = Self::new();
        binding.setIdentity(identity);
        binding.setNamespace(peer.namespace);

        return binding;
    }
}

impl Into<common::Peer> for Peer {
    fn into(self) -> common::Peer {
        return common::Peer {
            identity: self.getIdentity_asU8().to_vec(),
            namespace: self.getNamespace(),
        };
    }
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

impl From<common::KeyExchange> for KeyExchange {
    fn from(exchange: common::KeyExchange) -> Self {

        // TODO error handling
        let peer: Peer =exchange.origin.unwrap().into();
        let ephemeral_key = js_sys::Uint8Array::from(&exchange.ephemeral_key[..]);
        let one_time_key = js_sys::Uint8Array::from(&exchange.one_time_key[..]);

        let binding = Self::new();
        binding.setOrigin(peer);
        binding.setEphemeralKey(ephemeral_key);
        binding.setOneTimeKey(one_time_key);

        return binding;
    }
}

impl Into<common::KeyExchange> for KeyExchange {
    fn into(self) -> common::KeyExchange {
        let peer: Option<common::Peer> = Some(self.getOrigin().into());

        return common::KeyExchange {
            origin: peer,
            ephemeral_key: self.getEphemeralKey_asU8().to_vec(),
            one_time_key: self.getOneTimeKey_asU8().to_vec(),
        };
    }
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

impl From<common::SignedChallenge> for SignedChallenge {
    fn from(sig_challenge: common::SignedChallenge) -> Self {
        let challenge = js_sys::Uint8Array::from(&sig_challenge.challenge[..]);
        let signature = js_sys::Uint8Array::from(&sig_challenge.signature[..]);

        let binding = Self::new();
        binding.setChallenge(challenge);
        binding.setSignature(signature);

        return binding;
    }
}

impl Into<common::SignedChallenge> for SignedChallenge {
    fn into(self) -> common::SignedChallenge {
        return common::SignedChallenge {
            challenge: self.getChallenge_asU8().to_vec(),
            signature: self.getSignature_asU8().to_vec(),
        };
    }
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

impl From<common::Certificate> for Certificate {
    fn from(sig_certificate: common::Certificate) -> Self {
        let certificate = js_sys::Uint8Array::from(&sig_certificate.certificate[..]);
        let signature = js_sys::Uint8Array::from(&sig_certificate.signature[..]);

        let binding = Self::new();
        binding.setCertificate(certificate);
        binding.setSignature(signature);

        return binding;
    }
}

impl Into<common::Certificate> for Certificate {
    fn into(self) -> common::Certificate {
        return common::Certificate {
            certificate: self.getCertificate_asU8().to_vec(),
            signature: self.getSignature_asU8().to_vec(),
        };
    }
}
