use std::borrow::Borrow;
use std::cell::RefCell;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::futures_0_3::{spawn_local, JsFuture};

use yew::Callback;

use log::*;
use serde::{Deserialize, Serialize};

use hive_commons::crypto::{
    Certificate, CertificateFactory, CryptoError, KeyAgreement, PrivateKey, PublicKey, Signer,
};
use hive_commons::protocol;

use hive_commons::model::{common, Decodable};

use crate::bindings::{accounts_svc_bindings, common_bindings};
use crate::ctrl::{ControllerError, StorageController};
use crate::transport::ConnectionManager;

const IDENTITY_KEY: &'static str = "hive.core.identity";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IdentityModel {
    key: PrivateKey,
    state: IdentityState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IdentityState {
    New,
    Acknowledged { certificate: Certificate },
    Initialised { certificate: Certificate, pre_keys: protocol::PrivatePreKeys },
}

#[derive(Clone)]
pub struct IdentityController {
    storage: StorageController,
    transport: ConnectionManager,
    key: PrivateKey,
    state: Arc<RwLock<RefCell<IdentityState>>>,
}

impl IdentityController {
    pub fn new(
        on_error: Callback<String>,
        storage: StorageController,
        transport: ConnectionManager,
    ) -> Result<IdentityController, ControllerError> {
        match storage.load::<IdentityModel>(IDENTITY_KEY) {
            Ok(model) => Ok(IdentityController {
                storage,
                transport,
                key: model.key,
                state: Arc::new(RwLock::new(RefCell::new(model.state))),
            }),
            Err(cause) => {
                match cause {
                    ControllerError::NoDataFound { .. } => Ok(()),
                    _ => Err(cause),
                }?;

                info!("No identity found ... creating new");
                let key = PrivateKey::generate().map_err(|cause| {
                    ControllerError::CryptographicError {
                        message: "Private key generation failed".to_string(),
                        cause,
                    }
                })?;

                let model = IdentityModel { key, state: IdentityState::New };

                storage.store(IDENTITY_KEY, &model)?;
                let ctrl = IdentityController {
                    storage,
                    transport,
                    key: model.key,
                    state: Arc::new(RwLock::new(RefCell::new(model.state))),
                };

                ctrl.identity_maintenance(on_error);

                Ok(ctrl)
            }
        }
    }

    fn identity_maintenance(&self, on_error: Callback<String>) {
        match self.state.read() {
            Ok(guard) => {
                match guard.deref().borrow().deref() {
                    IdentityState::New => {
                        let cloned = self.clone();
                        spawn_local(async move {
                            if let Err(error) = cloned.create_account().await {
                                on_error.emit(format!("Failed to create account {:?}", error));
                                panic!(error)
                            }
                            if let Err(error) = cloned.publish_pre_key_bundle().await {
                                on_error.emit(format!("Failed to publish pre keys {:?}", error));
                                panic!(error)
                            }
                        });
                    }
                    IdentityState::Acknowledged { .. } => {
                        let cloned = self.clone();
                        spawn_local(async move {
                            if let Err(error) = cloned.publish_pre_key_bundle().await {
                                on_error.emit(format!("Failed to publish pre keys {:?}", error));
                                panic!(error)
                            }
                        });
                    }
                    IdentityState::Initialised { .. } => {}
                }
            }
            Err(error) => {
                on_error.emit(format!("Failed to lock identity state {:?}", error));
                error!("Failed to lock identity state {:?}", error);
            }
        }
    }

    async fn create_account(&self) -> Result<(), ControllerError> {
        debug!("Creating new account");
        let challenge = protocol::sign_challenge(&self)
            .map_err(|cause| ControllerError::ProtocolExecution { message: "Failed to sign challenge".to_string(), cause })?;

        let unsig_challenge =
            common::signed_challenge::Challenge::decode(challenge.challenge.clone())
                .map_err(|cause| ControllerError::FailedSerialisation { cause })?;

        debug!("Challenge timestamp {}", unsig_challenge.timestamp);

        let bound_challenge = common_bindings::SignedChallenge::new();
        bound_challenge.setChallenge(js_sys::Uint8Array::from(&challenge.challenge[..]));
        bound_challenge.setSignature(js_sys::Uint8Array::from(&challenge.signature[..]));

        let promise = self.transport.accounts().createAccount(bound_challenge);
        let value = JsFuture::from(promise).await.map_err(|e| {
            ControllerError::Message {
                message: e.as_string().unwrap_or("Unknown error creating account".to_string())
            }
        })?;

        let certificate_binding: common_bindings::Certificate =
            value.dyn_into().map_err(|e| {
                ControllerError::Message {
                    message: e.as_string().unwrap_or("Unknown error during certificate conversion".to_string())
                }
            })?;

        // TODO how to handle signer cert
        let (certificate, _ignore_for_now) =
            CertificateFactory::decode(&certificate_binding.into())
                .map_err(|cause| ControllerError::CryptographicError { message: "Failed to decode incoming certificate".to_string(), cause })?;

        debug!("Certificate serial {}", certificate.infos().serial());

        self.incoming_certificate(certificate).await
    }

    async fn incoming_certificate(&self, certificate: Certificate) -> Result<(), ControllerError> {
        {
            let write_state = self.state.write().map_err(|cause| ControllerError::Message {
                message: "Locking failed".to_string(),
            })?;

            write_state.replace_with(|state| match state {
                IdentityState::New | IdentityState::Acknowledged { .. } => {
                    IdentityState::Acknowledged { certificate }
                }
                IdentityState::Initialised { certificate: _, pre_keys } => {
                    IdentityState::Initialised { certificate, pre_keys: pre_keys.clone() }
                }
            });
        };

        // TODO blocking in async
        self.store()?;

        Ok(())
    }

    async fn publish_pre_key_bundle(&self) -> Result<(), ControllerError> {
        debug!("Publishing new pre key bundle");

        let (pre_keys, privates) = protocol::create_pre_key_bundle(&self).map_err(|cause| {
            ControllerError::CryptographicError {
                message: "Failed to create pre key bundle".to_string(),
                cause,
            }
        })?;

        let bound_pre_keys: common_bindings::PreKeyBundle = pre_keys.into();

        let promise = self.transport.accounts().updatePreKeys(bound_pre_keys);
        let value = JsFuture::from(promise).await.map_err(|e| {
            ControllerError::Message {
                message: e.as_string().unwrap_or("Unknown error publishing pre keys".to_string())
            }
        })?;

        let _: accounts_svc_bindings::UpdateKeyResult =
            value.dyn_into().map_err(|e| {
                ControllerError::Message {
                    message: e.as_string().unwrap_or("Unknown error during update result conversion".to_string())
                }
            })?;

        self.pre_keys_accepted(privates).await
    }

    async fn pre_keys_accepted(
        &self,
        private_pre_keys: protocol::PrivatePreKeys,
    ) -> Result<(), ControllerError> {
        {
            let write_state = self.state.write().map_err(|cause| ControllerError::Message {
                message: "Locking failed".to_string(),
            })?;

            let update = match write_state.deref().borrow().deref() {
                IdentityState::New => Err(ControllerError::InvalidState {
                    message: "Did not receive a certificate before pre keys".to_string(),
                }),
                IdentityState::Acknowledged { certificate }
                | IdentityState::Initialised { certificate, pre_keys: _ } => {
                    Ok(IdentityState::Initialised {
                        certificate: certificate.clone(),
                        pre_keys: private_pre_keys,
                    })
                }
            }?;

            write_state.replace(update);
        }

        // TODO blocking in async
        self.store()?;

        Ok(())
    }

    pub fn certificate(&self) -> Option<Certificate> {
        return match self.state.read() {
            Ok(guard) => match guard.deref().borrow().deref() {
                IdentityState::New { .. } => None,
                IdentityState::Acknowledged { certificate, .. }
                | IdentityState::Initialised { certificate, .. } => Some(certificate.clone()),
            },
            Err(cause) => {
                error!("Failed to lock: {}", cause);
                None
            }
        };
    }

    fn retrieve_pre_keys(&self) -> Result<protocol::PrivatePreKeys, ControllerError> {
        unimplemented!()
    }

    fn store(&self) -> Result<(), ControllerError> {
        let read_state = self
            .state
            .read()
            .map_err(|cause| ControllerError::Message { message: "Locking failed".to_string() })?;

        let model = IdentityModel {
            key: self.key.clone(),
            state: read_state.deref().borrow().deref().clone(),
        };

        let store_result = self.storage.store(IDENTITY_KEY, &model);
        store_result
    }
}

impl protocol::KeyAccess for IdentityController {
    fn pre_key_access(&self) -> &PrivateKey {
        unimplemented!()
    }

    fn one_time_key_access(&self, public: &PublicKey) -> Option<PrivateKey> {
        unimplemented!()
    }
}

impl Signer for &IdentityController {
    fn public_key(&self) -> &PublicKey {
        &self.key.public_key()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.key.sign(data)
    }
}

impl Signer for IdentityController {
    fn public_key(&self) -> &PublicKey {
        &self.key.public_key()
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.key.sign(data)
    }
}

impl KeyAgreement for IdentityController {
    fn agree(&self, public: &PublicKey) -> [u8; 32] {
        self.key.agree(public)
    }
}

#[cfg(test)]
mod identity_ctrl_tests {
    #[test]
    fn test_ing() {}
}
