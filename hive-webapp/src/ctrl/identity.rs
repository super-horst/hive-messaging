use std::borrow::Borrow;
use std::cell::RefCell;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::futures_0_3::{spawn_local, JsFuture};

use yew::Callback;

use log::*;
use serde::{Deserialize, Serialize};

use hive_commons::crypto::{Certificate, CryptoError, KeyAgreement, PrivateKey, PublicKey, Signer, CertificateFactory};
use hive_commons::protocol;

use hive_commons::model::{common, Decodable};

use crate::bindings::{common_bindings, accounts_svc_bindings};
use crate::transport::ConnectionManager;
use crate::ctrl::{ControllerError, StorageController};

const IDENTITY_KEY: &'static str = "hive.core.identity";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum IdentityState {
    New {
        key: PrivateKey,
    },
    Acknowledged {
        key: PrivateKey,
        certificate: Certificate,
    },
    Initialised {
        key: PrivateKey,
        certificate: Certificate,
        pre_keys: protocol::PrivatePreKeys,
    },
}

#[derive(Clone)]
pub struct IdentityController {
    storage: StorageController,
    transport: ConnectionManager,
    state: Arc<RwLock<RefCell<IdentityState>>>,
}

impl IdentityController {
    pub fn new(on_error: Callback<String>, storage: StorageController,
               transport: ConnectionManager, ) -> Result<IdentityController, ControllerError> {
        match storage.load::<IdentityState>(IDENTITY_KEY) {
            Ok(state) => Ok(IdentityController {
                storage,
                transport,
                state: Arc::new(RwLock::new(RefCell::new(state))),
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

                let state = IdentityState::New { key };

                storage.store(IDENTITY_KEY, &state)?;
                let ctrl = IdentityController {
                    storage,
                    transport,
                    state: Arc::new(RwLock::new(RefCell::new(state))),
                };

                ctrl.identity_maintenance(on_error);

                Ok(ctrl)
            }
        }
    }

    fn identity_maintenance(&self, on_error: Callback<String>) {
        let cloned = self.clone();

        spawn_local(async move {
            match cloned.state.read() {
                Ok(guard) => {
                    match guard.deref().borrow().deref() {
                        IdentityState::New { .. } => {
                            // TODO error handling
                            cloned.create_account().await.unwrap();
                            cloned.publish_pre_key_bundle().await.unwrap();
                        }
                        IdentityState::Acknowledged { .. } => {
                            // TODO error handling
                            cloned.publish_pre_key_bundle().await.unwrap();
                        }
                        IdentityState::Initialised { .. } => {}
                    }
                }
                Err(error) => {
                    on_error.emit(format!("Failed to identity state {:?}", error));
                    error!("Failed to identity state {:?}", error);
                }
            }
        });
    }

    async fn create_account(&self) -> Result<(), ControllerError> {
        // TODO error handling
        debug!("Creating new account");
        let challenge = protocol::sign_challenge(&self).unwrap();

        let unsig_challenge = common::signed_challenge::Challenge::decode(challenge.challenge.clone()).unwrap();
        debug!("Challenge timestamp {}", unsig_challenge.timestamp);

        let bound_challenge = common_bindings::SignedChallenge::new();
        bound_challenge.setChallenge(js_sys::Uint8Array::from(&challenge.challenge[..]));
        bound_challenge.setSignature(js_sys::Uint8Array::from(&challenge.signature[..]));

        let promise = self.transport.accounts().createAccount(bound_challenge);
        let value = JsFuture::from(promise).await.unwrap();

        let certificate_binding: common_bindings::Certificate =
            value.dyn_into().expect("response not working...");

        // TODO how to handle signer cert
        let (certificate, _ignore_for_now) =
            CertificateFactory::decode(&certificate_binding.into()).unwrap();

        debug!("Certificate serial {}", certificate.infos().serial());

        self.incoming_certificate(certificate).await
    }

    async fn publish_pre_key_bundle(&self) -> Result<(), ControllerError> {
        // TODO error handling
        debug!("Publishing new pre key bundle");

        let (pre_keys, privates) = protocol::create_pre_key_bundle(&self)
            .map_err(|cause| ControllerError::CryptographicError { message: "Failed to create pre key bundle".to_string(), cause })?;

        let bound_pre_keys: common_bindings::PreKeyBundle = pre_keys.into();

        let promise = self.transport.accounts().updatePreKeys(bound_pre_keys);
        let value = JsFuture::from(promise).await.unwrap();

        let _: accounts_svc_bindings::UpdateKeyResult =
            value.dyn_into().expect("response not working...");

        self.pre_keys_accepted(privates).await
    }

    async fn incoming_certificate(&self, certificate: Certificate) -> Result<(), ControllerError> {
        {
            let write_state = self.state.write().map_err(|cause| ControllerError::Message {
                message: "Locking failed".to_string(),
            })?;

            write_state.replace_with(|state| match state {
                IdentityState::New { key } | IdentityState::Acknowledged { key, .. } => {
                    IdentityState::Acknowledged {
                        key: key.clone(),
                        certificate,
                    }
                }
                IdentityState::Initialised {
                    key,
                    certificate: _,
                    pre_keys,
                } => IdentityState::Initialised {
                    key: key.clone(),
                    certificate,
                    pre_keys: pre_keys.clone(),
                },
            });
        };

        // TODO blocking in async
        self.store()?;

        Ok(())
    }

    async fn pre_keys_accepted(&self, private_pre_keys: protocol::PrivatePreKeys) -> Result<(), ControllerError> {
        {
            let write_state = self.state.write().map_err(|cause| ControllerError::Message {
                message: "Locking failed".to_string(),
            })?;

            let update = match write_state.deref().borrow().deref() {
                IdentityState::New { .. } => Err(ControllerError::InvalidState {
                    message: "Did not receive a certificate before pre keys".to_string(),
                }),
                IdentityState::Acknowledged { key, certificate }
                | IdentityState::Initialised {
                    key,
                    certificate,
                    pre_keys: _,
                } => Ok(IdentityState::Initialised {
                    key: *key,
                    certificate: certificate.clone(),
                    pre_keys: private_pre_keys,
                }),
            }?;

            write_state.replace(update);
        }

        // TODO blocking in async
        self.store()?;

        Ok(())
    }

    pub fn certificate(&self) -> Option<Certificate> {
        return match self.state.read() {
            Ok(guard) => {
                match guard.deref().borrow().deref() {
                    IdentityState::New { .. } => None,
                    IdentityState::Acknowledged { certificate, .. }
                    | IdentityState::Initialised { certificate, .. } => Some(certificate.clone()),
                }
            }
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
            .read().map_err(|cause| ControllerError::Message {
            message: "Locking failed".to_string(),
        })?;

        let store_result = self
            .storage
            .store(IDENTITY_KEY, read_state.borrow().deref());
        store_result
    }
}

impl protocol::KeyAccess for IdentityController {
    fn identity_access(&self) -> &PrivateKey {
        // TODO error handling
        let read_state = self.state.read().unwrap();

        return match read_state.deref().borrow().deref() {
            IdentityState::New { key }
            | IdentityState::Acknowledged { key, .. }
            | IdentityState::Initialised { key, .. } => &key,
        };
    }

    fn pre_key_access(&self) -> &PrivateKey {
        unimplemented!()
    }

    fn one_time_key_access(&self, public: &PublicKey) -> Option<PrivateKey> {
        unimplemented!()
    }
}

impl Signer for &IdentityController {
    fn public_key(&self) -> &PublicKey {
        // TODO error handling
        let read_state = self.state.read().unwrap();

        return match read_state.deref().borrow().deref() {
            IdentityState::New { key }
            | IdentityState::Acknowledged { key, .. }
            | IdentityState::Initialised { key, .. } => &key.public_key(),
        };
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let read_state = self.state.read().map_err(|cause| CryptoError::Message {
            message: "Locking failed".to_string(),
        })?;

        return match read_state.deref().borrow().deref() {
            IdentityState::New { key }
            | IdentityState::Acknowledged { key, .. }
            | IdentityState::Initialised { key, .. } => key.sign(data),
        };
    }
}

impl Signer for IdentityController {
    fn public_key(&self) -> &PublicKey {
        // TODO error handling
        let read_state = self.state.read().unwrap();

        return match read_state.deref().borrow().deref() {
            IdentityState::New { key }
            | IdentityState::Acknowledged { key, .. }
            | IdentityState::Initialised { key, .. } => key.public_key(),
        };
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let read_state = self.state.read().map_err(|cause| CryptoError::Message {
            message: "Locking failed".to_string(),
        })?;

        return match read_state.deref().borrow().deref() {
            IdentityState::New { key }
            | IdentityState::Acknowledged { key, .. }
            | IdentityState::Initialised { key, .. } => key.sign(data),
        };
    }
}

impl KeyAgreement for IdentityController {
    fn agree(&self, public: &PublicKey) -> [u8; 32] {
        let read_state = self
            .state
            .read()
            .map_err(|cause| CryptoError::Message {
                message: "Locking failed".to_string(),
            })
            .unwrap();

        return match read_state.deref().borrow().deref() {
            IdentityState::New { key }
            | IdentityState::Acknowledged { key, .. }
            | IdentityState::Initialised { key, .. } => key.agree(public),
        };
    }
}

#[cfg(test)]
mod identity_ctrl_tests {

    #[test]
    fn test_ing() {}
}
