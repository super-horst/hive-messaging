use crate::model::common::PreKeyBundle;
use crate::model::messages::{EncryptionParameters, KeyExchange};

use crate::crypto::{
    x3dh_agree_initial, x3dh_agree_respond, CryptoError, FromBytes, ManagedRatchet, PrivateKey,
    PublicKey, RecvStep, SendStep,
};
use std::sync::Arc;

use failure::Fail;

#[cfg(test)]
use mockall::automock;

#[derive(Debug, Fail)]
pub enum SessionError {
    #[fail(display = "Error message: {}", message)]
    Message { message: String },
    #[fail(display = "Invalid session state: {}", message)]
    InvalidSessionState { message: String },
    #[fail(display = "Error during session cryptography: {}", message)]
    FailedCryptography {
        message: String,
        #[fail(cause)]
        cause: CryptoError,
    },
    #[fail(display = "Input is invalid: {}", message)]
    InvalidInput { message: String },
}

#[cfg_attr(test, automock)]
#[async_trait::async_trait]
pub trait PreKeyProvider {
    async fn retrieve_pre_keys(&self) -> Result<PreKeyBundle, ()>;
}

pub trait KeyAccess {
    fn identity_access(&self) -> &PrivateKey;

    fn pre_key_access(&self) -> &PrivateKey;

    fn one_time_key_access(&self, public: &PublicKey) -> Option<PrivateKey>;
}

enum SessionState {
    Initialised { ratchet: ManagedRatchet },
    New {},
}

pub struct SessionManager {
    state: SessionState,
    peer_identity: PublicKey,
    pre_keys: Arc<dyn PreKeyProvider>,
    keys: Arc<dyn KeyAccess>,
}

impl SessionManager {
    pub fn new(peer_identity: PublicKey, pre_keys: Arc<dyn PreKeyProvider>, keys: Arc<dyn KeyAccess>) -> SessionManager {
        SessionManager {
            state: SessionState::New {},
            peer_identity,
            pre_keys,
            keys,
        }
    }

    pub fn refresh(&mut self, exchange: KeyExchange) -> Result<(), SessionError> {
        let peer = exchange.origin.ok_or_else(|| SessionError::InvalidInput {
            message: "Origin missing in exchange".to_string(),
        })?;

        let other_identity = PublicKey::from_bytes(&peer.identity[..]).map_err(|e| {
            SessionError::FailedCryptography {
                message: "Decode of peer identity".to_string(),
                cause: e,
            }
        })?;

        if other_identity != self.peer_identity {
            return Err(SessionError::InvalidSessionState {
                message: "Peer identity in key exchange does not match session".to_string(),
            });
        }

        let ephemeral = PublicKey::from_bytes(&exchange.ephemeral_key[..]).map_err(|e| {
            SessionError::FailedCryptography {
                message: "Decode of ephemeral key".to_string(),
                cause: e,
            }
        })?;

        let otk = if exchange.one_time_key.is_empty() {
            None
        } else {
            let key = PublicKey::from_bytes(&exchange.one_time_key[..]).map_err(|e| {
                SessionError::FailedCryptography {
                    message: "Decode of one time key".to_string(),
                    cause: e,
                }
            })?;
            Some(key)
        }
            .map(|otk_pub| self.keys.one_time_key_access(&otk_pub))
            .flatten();

        let identity = self.keys.identity_access();
        let pre_key = self.keys.pre_key_access();

        let secret =
            x3dh_agree_respond(&other_identity, identity, &ephemeral, pre_key, otk.as_ref());

        let ratchet = ManagedRatchet::initialise_received(&secret, pre_key).map_err(|e| {
            SessionError::FailedCryptography {
                message: "Initialisation of ratchet".to_string(),
                cause: e,
            }
        })?;

        // TODO history
        self.state = SessionState::Initialised { ratchet };

        Ok(())
    }

    pub async fn receive(
        &mut self,
        params: EncryptionParameters,
    ) -> Result<RecvStep, SessionError> {
        match &mut self.state {
            SessionState::Initialised { ratchet } => {
                let ratchet_key = PublicKey::from_bytes(&params.ratchet_key[..]).map_err(|e| {
                    SessionError::FailedCryptography {
                        message: "Decode of ratchet key".to_string(),
                        cause: e,
                    }
                })?;

                let step = ratchet
                    .recv_step_for(ratchet_key, params.chain_idx, params.prev_chain_count)
                    .map_err(|e| SessionError::FailedCryptography {
                        message: "Decode of ratchet key".to_string(),
                        cause: e,
                    })?;
                Ok(step)
            }
            SessionState::New {} => Err(SessionError::InvalidSessionState {
                message: "'New' can't handle params ... ".to_string(),
            }),
        }
    }

    pub async fn send(&mut self) -> Result<(Option<KeyExchange>, SendStep), SessionError> {
        match &mut self.state {
            SessionState::Initialised { ratchet } => Ok((None, ratchet.send_step())),
            SessionState::New {} => {
                let bundle: PreKeyBundle =
                    self.pre_keys
                        .retrieve_pre_keys()
                        .await
                        .map_err(|()| SessionError::Message {
                            message: "Failed to get pre keys".to_string(),
                        })?;

                let peer = bundle
                    .identity
                    .clone()
                    .ok_or_else(|| SessionError::InvalidInput {
                        message: "Identity missing in pre key bundle".to_string(),
                    })?;
                let other_identity = PublicKey::from_bytes(&peer.identity[..]).map_err(|e| {
                    SessionError::FailedCryptography {
                        message: "Decode of peer identity".to_string(),
                        cause: e,
                    }
                })?;

                if other_identity != self.peer_identity {
                    return Err(SessionError::InvalidSessionState {
                        message: "Peer identity in pre key bundle does not match session".to_string(),
                    });
                }

                other_identity
                    .verify(&bundle.pre_key[..], &bundle.pre_key_signature[..])
                    .map_err(|e| SessionError::FailedCryptography {
                        message: "Verification of pre key signature".to_string(),
                        cause: e,
                    })?;

                let pre_key = PublicKey::from_bytes(&bundle.pre_key[..]).map_err(|e| {
                    SessionError::FailedCryptography {
                        message: "Decode of pre key".to_string(),
                        cause: e,
                    }
                })?;

                let otk = if let Some(bytes) = bundle.one_time_pre_keys.first() {
                    let one_time_key = PublicKey::from_bytes(&bytes[..]).map_err(|e| {
                        SessionError::FailedCryptography {
                            message: "Decode of one time key".to_string(),
                            cause: e,
                        }
                    })?;
                    Ok(Some(one_time_key))
                } else {
                    Ok(None)
                }?;

                let identity = self.keys.identity_access();
                let (eph_key, secret) =
                    x3dh_agree_initial(identity, &other_identity, &pre_key, otk.as_ref());

                let mut ratchet =
                    ManagedRatchet::initialise_to_send(&secret, &pre_key).map_err(|e| {
                        SessionError::FailedCryptography {
                            message: "Initialisation of ratchet".to_string(),
                            cause: e,
                        }
                    })?;

                let step = ratchet.send_step();

                self.state = SessionState::Initialised { ratchet };

                // TODO sign key exchange?
                let exchange = KeyExchange {
                    origin: Some(identity.public_key().into_peer()),
                    ephemeral_key: eph_key.id_bytes(),
                    one_time_key: otk.map(|otk_pub| otk_pub.id_bytes()).unwrap_or(vec![]),
                };

                Ok((Some(exchange), step))
            }
        }
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use crate::crypto::utils::{create_pre_key_bundle, PrivatePreKeys};

    #[tokio::test]
    async fn test_new_state_receives() {
        let mock_keys = Arc::new(MockCryptoProvider::any());
        let mock_pre_keys = Arc::new(MockPreKeyProvider::new());

        let mut sess_mgr = SessionManager::new(PrivateKey::generate().unwrap().public_key().clone(), mock_pre_keys, mock_keys);

        let params = EncryptionParameters {
            ratchet_key: vec![],
            chain_idx: 0,
            prev_chain_count: 0,
        };

        let result = sess_mgr.receive(params).await;
        assert!(result.is_err());
        assert!(match result.unwrap_err() {
            SessionError::InvalidSessionState { .. } => true,
            _ => false,
        });
    }

    #[tokio::test]
    async fn test_new_state_sends() {
        let alice_key = PrivateKey::generate().unwrap();
        let (alice_bundle, alice_bundle_privates) = prepare_pre_keys(&alice_key);

        let bob_key = PrivateKey::generate().unwrap();

        let mock_keys = Arc::new(MockCryptoProvider::new(bob_key.clone()));
        let mut mock_pre_keys = MockPreKeyProvider::new();
        mock_pre_keys
            .expect_retrieve_pre_keys()
            .times(1)
            .return_const(Ok(alice_bundle));

        let mut sess_mgr = SessionManager::new(alice_key.public_key().clone(), Arc::new(mock_pre_keys), mock_keys);

        let result = sess_mgr.send().await;
        assert!(result.is_ok());

        let (key_exchange, send_step) = result.unwrap();
        assert!(key_exchange.is_some());
        let key_exchange = key_exchange.unwrap();

        let eph_key = PublicKey::from_bytes(&key_exchange.ephemeral_key[..]).unwrap();

        let secret = x3dh_agree_respond(
            &bob_key.public_key(),
            &alice_key,
            &eph_key,
            &alice_bundle_privates.pre_key,
            alice_bundle_privates.one_time_keys.first(),
        );

        let mut ratchet =
            ManagedRatchet::initialise_received(&secret, &alice_bundle_privates.pre_key).unwrap();
        let recv_step = ratchet
            .recv_step_for(
                send_step.ratchet_key,
                send_step.counter,
                send_step.prev_ratchet_counter,
            )
            .unwrap();

        assert_eq!(send_step.secret, recv_step.secret)
    }

    #[tokio::test]
    async fn test_intialised_state_send() {
        let alice_key = PrivateKey::generate().unwrap();
        let (_alice_bundle, alice_bundle_privates) = prepare_pre_keys(&alice_key);
        let mock_keys = Arc::new(MockCryptoProvider::with_pre_key(
            alice_key.clone(),
            alice_bundle_privates.pre_key,
        ));

        let bob_key = PrivateKey::generate().unwrap();
        let eph_key = PrivateKey::generate().unwrap();

        let exchange = KeyExchange {
            origin: Some(bob_key.public_key().into_peer()),
            ephemeral_key: eph_key.public_key().id_bytes(),
            one_time_key: vec![],
        };

        let mut mock_pre_keys = MockPreKeyProvider::new();
        mock_pre_keys.expect_retrieve_pre_keys().times(0);

        let mut sess_mgr = SessionManager::new(bob_key.public_key().clone(), Arc::new(mock_pre_keys), mock_keys);

        let result = sess_mgr.refresh(exchange);
        assert!(result.is_ok());

        let result = sess_mgr.send().await;
        assert!(result.is_ok());

        let (key_exchange, _) = result.unwrap();
        assert!(key_exchange.is_none());
    }

    #[tokio::test]
    async fn test_new_state_sends_with_wrong_identity() {
        let alice_key = PrivateKey::generate().unwrap();
        let (alice_bundle, _) = prepare_pre_keys(&alice_key);

        let bob_key = PrivateKey::generate().unwrap();

        let mut mock_pre_keys = MockPreKeyProvider::new();
        mock_pre_keys
            .expect_retrieve_pre_keys()
            .times(1)
            .return_const(Ok(alice_bundle));

        let any_unrelated_key = PrivateKey::generate().unwrap().public_key().clone();
        let mut sess_mgr = SessionManager::new(any_unrelated_key, Arc::new(mock_pre_keys), Arc::new(MockCryptoProvider::any()));

        let result = sess_mgr.send().await;
        assert!(result.is_err());
        assert!(match result.unwrap_err() {
            SessionError::InvalidSessionState { .. } => true,
            _ => false,
        });
    }

    #[tokio::test]
    async fn test_refresh_with_wrong_identity() {
        let bob_key = PrivateKey::generate().unwrap();

        let exchange = KeyExchange {
            origin: Some(bob_key.public_key().into_peer()),
            ephemeral_key: vec![],
            one_time_key: vec![],
        };

        let mut mock_pre_keys = MockPreKeyProvider::new();
        mock_pre_keys.expect_retrieve_pre_keys().times(0);

        let any_unrelated_key = PrivateKey::generate().unwrap().public_key().clone();
        let mut sess_mgr = SessionManager::new(any_unrelated_key, Arc::new(mock_pre_keys), Arc::new(MockCryptoProvider::any()));

        let result = sess_mgr.refresh(exchange);
        assert!(result.is_err());
        assert!(match result.unwrap_err() {
            SessionError::InvalidSessionState { .. } => true,
            _ => false,
        });
    }

    fn prepare_pre_keys(alice_key: &PrivateKey) -> (PreKeyBundle, PrivatePreKeys) {
        let (mut alice_bundle, mut alice_bundle_privates) =
            create_pre_key_bundle(alice_key).unwrap();

        let _ignore = alice_bundle.one_time_pre_keys.split_off(1);
        alice_bundle.one_time_pre_keys.shrink_to_fit();

        let _ignore = alice_bundle_privates.one_time_keys.split_off(1);
        alice_bundle_privates.one_time_keys.shrink_to_fit();

        (alice_bundle, alice_bundle_privates)
    }

    pub struct MockCryptoProvider {
        pub key: PrivateKey,
        pub pre_key: PrivateKey,
    }

    impl MockCryptoProvider {
        pub fn any() -> MockCryptoProvider {
            MockCryptoProvider {
                key: PrivateKey::generate().unwrap(),
                pre_key: PrivateKey::generate().unwrap(),
            }
        }
        pub fn new(key: PrivateKey) -> MockCryptoProvider {
            MockCryptoProvider {
                key,
                pre_key: PrivateKey::generate().unwrap(),
            }
        }
        pub fn with_pre_key(key: PrivateKey, pre_key: PrivateKey) -> MockCryptoProvider {
            MockCryptoProvider { key, pre_key }
        }
    }

    impl KeyAccess for MockCryptoProvider {
        fn identity_access(&self) -> &PrivateKey {
            &self.key
        }

        fn pre_key_access(&self) -> &PrivateKey {
            &self.pre_key
        }

        fn one_time_key_access(&self, _: &PublicKey) -> Option<PrivateKey> {
            return None;
        }
    }
}
