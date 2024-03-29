use js_sys;
use wasm_bindgen::prelude::*;

use hive_commons::model::common;

#[wasm_bindgen(module = "/js/generated/common_pb.js")]
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

#[wasm_bindgen(module = "/js/generated/common_pb.js")]
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

#[wasm_bindgen(module = "/js/generated/common_pb.js")]
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

#[wasm_bindgen(module = "/js/generated/common_pb.js")]
extern "C" {
    pub type PreKeyBundle;

    #[wasm_bindgen(constructor)]
    pub fn new() -> PreKeyBundle;

    #[wasm_bindgen(method)]
    pub fn getIdentity(this: &PreKeyBundle) -> Peer;

    #[wasm_bindgen(method)]
    pub fn setIdentity(this: &PreKeyBundle, identity: Peer);

    #[wasm_bindgen(method)]
    pub fn getPreKey_asU8(this: &PreKeyBundle) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setPreKey(this: &PreKeyBundle, pre_key: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getPreKeySignature_asU8(this: &PreKeyBundle) -> js_sys::Uint8Array;

    #[wasm_bindgen(method)]
    pub fn setPreKeySignature(this: &PreKeyBundle, signature: js_sys::Uint8Array);

    #[wasm_bindgen(method)]
    pub fn getOneTimePreKeysList_asU8(this: &PreKeyBundle) -> js_sys::Array;

    #[wasm_bindgen(method)]
    pub fn setOneTimePreKeysList(this: &PreKeyBundle, key_list: js_sys::Array);
}

impl From<common::PreKeyBundle> for PreKeyBundle {
    fn from(key_bundle: common::PreKeyBundle) -> Self {
        let mut key_bundle = key_bundle;

        // TODO error handling
        let peer = key_bundle.identity.unwrap();

        let pre_key = js_sys::Uint8Array::from(&key_bundle.pre_key[..]);
        let pre_key_signature = js_sys::Uint8Array::from(&key_bundle.pre_key_signature[..]);

        let one_time_pre_keys = key_bundle
            .one_time_pre_keys
            .drain(..)
            .map(|v| js_sys::Uint8Array::from(&v[..]))
            .collect();

        let binding = Self::new();
        binding.setIdentity(peer.into());
        binding.setPreKey(pre_key);
        binding.setPreKeySignature(pre_key_signature);
        binding.setOneTimePreKeysList(one_time_pre_keys);

        return binding;
    }
}

impl Into<common::PreKeyBundle> for PreKeyBundle {
    fn into(self) -> common::PreKeyBundle {
        // TODO error handling
        let keys: Vec<js_sys::Uint8Array> = self
            .getOneTimePreKeysList_asU8()
            .to_vec()
            .drain(..)
            .map(wasm_bindgen::JsCast::dyn_into::<js_sys::Uint8Array>)
            .map(Result::unwrap)
            .collect();

        return common::PreKeyBundle {
            identity: Some(self.getIdentity().into()),
            pre_key: self.getPreKey_asU8().to_vec(),
            pre_key_signature: self.getPreKeySignature_asU8().to_vec(),
            one_time_pre_keys: keys.iter().map(js_sys::Uint8Array::to_vec).collect(),
        };
    }
}
