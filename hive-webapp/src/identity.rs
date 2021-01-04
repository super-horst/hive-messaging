use log::*;

use wasm_bindgen::JsCast;
use wasm_bindgen::__rt::std::sync::{Arc, RwLock};
use wasm_bindgen_futures::futures_0_3::spawn_local;
use wasm_bindgen_futures::futures_0_3::JsFuture;

use hive_commons::crypto;
use hive_commons::crypto::{ManagedRatchet, PublicKey};
use hive_commons::model::*;

use crate::bindings::*;
use crate::storage::*;
use crate::transport::ConnectionManager;

#[derive(Clone)]
pub struct LocalIdentity {
    model: Arc<RwLock<IdentityModel>>,
    storage: StorageController,
    connections: ConnectionManager,
}

impl LocalIdentity {
    /// initialise local identity by loading from storage, or create identity and try to publish account
    pub fn initialise(storage: StorageController, connections: ConnectionManager) -> LocalIdentity {
        let mut new_account = false;

        let id = match storage.get_identity() {
            Some(model) => LocalIdentity {
                model: Arc::new(RwLock::new(model)),
                storage,
                connections,
            },
            None => {
                info!("No model identity found ... creating new");
                let key = crypto::PrivateKey::generate().unwrap();

                let created = IdentityModel::new(key);
                storage.set_identity(&created);

                new_account = true;

                let id = LocalIdentity {
                    model: Arc::new(RwLock::new(created)),
                    storage,
                    connections,
                };

                let cloned = id.clone();
                spawn_local(async move {
                    cloned.create_account().await;
                    cloned.publish_pre_key_bundle().await;
                });

                id
            }
        };

        {
            let model = id.model.read().unwrap();

            if model.certificate.is_none() && !new_account {
                let cloned = id.clone();
                spawn_local(async move {
                    cloned.create_account().await;
                    cloned.publish_pre_key_bundle().await;
                });
            } else if model.pre_keys.is_none() && !new_account {
                let cloned = id.clone();
                spawn_local(async move {
                    cloned.publish_pre_key_bundle().await;
                });
            }
        }

        return id;
    }

    /// provide my public key
    pub fn public_key(&self) -> PublicKey {
        let read_model = self.model.read().unwrap();
        read_model.key.public_key().clone()
    }

    /// prepare a ratchet with this identity and another party's pre keys
    pub fn prepare_ratchet(&self, pre_key: common::PreKeyBundle) -> ManagedRatchet {
        let model = self.model.read().unwrap();

        let ratchet = crypto::utils::initialise_ratchet_to_send(&model.key, pre_key).unwrap();
        return ratchet;
    }

    async fn create_account(&self) {
        // TODO error handling
        let mut model = self.model.write().unwrap();
        debug!("Creating new account");

        let challenge = crypto::utils::sign_challenge(&model.key).unwrap();
        let unsig_challenge =
            common::signed_challenge::Challenge::decode(challenge.challenge.clone()).unwrap();

        debug!("Challenge timestamp {}", unsig_challenge.timestamp);

        let bound_challenge = common_bindings::SignedChallenge::new();
        bound_challenge.setChallenge(js_sys::Uint8Array::from(&challenge.challenge[..]));
        bound_challenge.setSignature(js_sys::Uint8Array::from(&challenge.signature[..]));

        let promise = self.connections.accounts().createAccount(bound_challenge);
        let value = JsFuture::from(promise).await.unwrap();

        let certificate_binding: common_bindings::Certificate =
            value.dyn_into().expect("response not working...");

        // TODO how to handle signer cert
        let (certificate, ignore_for_now) =
            crypto::CertificateFactory::decode(certificate_binding.into()).unwrap();

        debug!("Certificate serial {}", certificate.infos().serial());

        model.certificate = Some(certificate);
        self.storage.set_identity(&model);
    }

    async fn publish_pre_key_bundle(&self) {
        // TODO error handling
        let mut model = self.model.write().unwrap();
        debug!("Publishing new pre key bundle");

        let (pre_keys, privates) = crypto::utils::create_pre_key_bundle(&model.key).unwrap();

        let bound_pre_keys: common_bindings::PreKeyBundle = pre_keys.into();
        let promise = self.connections.accounts().updatePreKeys(bound_pre_keys);
        let value = JsFuture::from(promise).await.unwrap();

        let _: accounts_svc_bindings::UpdateKeyResult =
            value.dyn_into().expect("response not working...");

        model.pre_keys = Some(privates);
        self.storage.set_identity(&model);
    }
}
