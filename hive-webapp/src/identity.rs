use log::*;

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::futures_0_3::spawn_local;
use wasm_bindgen_futures::futures_0_3::JsFuture;

use hive_commons::crypto;
use hive_commons::crypto::ManagedRatchet;
use hive_commons::model::*;

use crate::bindings::accounts_svc_bindings;
use crate::bindings::common_bindings;
use crate::storage::*;
use crate::transport;
use wasm_bindgen::__rt::std::sync::{RwLock, Arc};

#[derive(Clone)]
pub struct LocalIdentity {
    stored: Arc<RwLock<IdentityModel>>,
}

impl LocalIdentity {
    /// initialise local identity by loading from storage, or create identity and try to publish account
    pub fn initialise() -> LocalIdentity {
        let mut storage = StorageController::new();
        let mut new_account = false;

        let id = match storage.get_identity() {
            Some(id) => LocalIdentity {
                stored: Arc::new(RwLock::new(id)),
            },
            None => {
                info!("No stored identity found ... creating new");
                let key = crypto::PrivateKey::generate().unwrap();

                let created = IdentityModel::new(key);
                storage.set_identity(&created);

                new_account = true;

                let id = LocalIdentity {
                    stored: Arc::new(RwLock::new(created)),
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
            let model = id.stored.read().unwrap();

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

    /// prepare a ratchet with this identity and another party's pre keys
    pub fn prepare_ratchet(&self, pre_key: common::PreKeyBundle) -> ManagedRatchet {
        let model = self.stored.read().unwrap();

        let ratchet =
            crypto::utils::initialise_ratchet_to_send(&model.key, pre_key).unwrap();
        return ratchet;
    }

    async fn create_account(&self) {
        // TODO error handling
        let mut model = self.stored.write().unwrap();
        debug!("Creating new account");

        let challenge = crypto::utils::sign_challenge(&model.key).unwrap();
        let unsig_challenge =
            common::signed_challenge::Challenge::decode(challenge.challenge.clone()).unwrap();

        debug!("Challenge timestamp {}", unsig_challenge.timestamp);

        let bound_challenge = common_bindings::SignedChallenge::new();
        bound_challenge.setChallenge(js_sys::Uint8Array::from(&challenge.challenge[..]));
        bound_challenge.setSignature(js_sys::Uint8Array::from(&challenge.signature[..]));

        let client = accounts_svc_bindings::AccountsPromiseClient::new(transport::create_service_url());
        let promise = client.createAccount(bound_challenge);
        let value = JsFuture::from(promise).await.unwrap();

        let certificate_binding: common_bindings::Certificate =
            value.dyn_into().expect("response not working...");

        // TODO how to handle signer cert
        let (certificate, ignore_for_now) =
            crypto::CertificateFactory::decode(certificate_binding.into()).unwrap();

        debug!("Certificate serial {}", certificate.infos().serial());

        model.certificate = Some(certificate);
        let mut storage = StorageController::new();
        storage.set_identity(&model);
    }

    async fn publish_pre_key_bundle(&self)  {
        // TODO error handling
        let mut model = self.stored.write().unwrap();
        debug!("Publishing new pre key bundle");

        let (pre_keys, privates) = crypto::utils::create_pre_key_bundle(&model.key).unwrap();

        let client = accounts_svc_bindings::AccountsPromiseClient::new(transport::create_service_url());

        let bound_pre_keys: common_bindings::PreKeyBundle = pre_keys.into();
        let promise = client.updatePreKeys(bound_pre_keys);
        let value = JsFuture::from(promise).await.unwrap();

        let _: accounts_svc_bindings::UpdateKeyResult =
            value.dyn_into().expect("response not working...");

        model.pre_keys = Some(privates);
        let mut storage = StorageController::new();
        storage.set_identity(&model);
    }
}
