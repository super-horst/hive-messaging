use std::hash::{Hash, Hasher};
use std::ops::Deref;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::crypto::{
    x3dh_agree_initial, x3dh_agree_respond, CertificateFactory, FromBytes, ManagedRatchet,
    PublicKey, RecvStep, SendStep, Verifier,
};
use crate::model::common::PreKeyBundle;
use crate::model::messages::{KeyExchange, SessionParameters};

use crate::protocol::*;

#[derive(Debug)]
pub enum SendingStatus {
    RequirePreKeys,
    Ok {
        key_exchange: Option<KeyExchange>,
        step: SendStep,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
enum SessionState {
    Initialised {
        ratchet: ManagedRatchet,
    },
    ReceivedPreKeyBundle {
        identity: PublicKey,
        pre_key: PublicKey,
        one_time_key: Option<PublicKey>,
    },
    New,
}

impl Hash for SessionState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_i8(match *self {
            SessionState::New {} => 1,
            SessionState::ReceivedPreKeyBundle { .. } => 2,
            SessionState::Initialised { .. } => 3,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Session {
    pub peer_identity: PublicKey,
    state: SessionState,
}

impl Hash for Session {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.peer_identity.hash(state);
        self.state.hash(state);
    }
}

impl std::cmp::PartialEq<Session> for Session {
    fn eq(&self, other: &Session) -> bool {
        if self.peer_identity == other.peer_identity {
            return match (&self.state, &other.state) {
                (SessionState::New {}, SessionState::New {}) => true,
                (SessionState::Initialised { .. }, SessionState::Initialised { .. }) => true,
                _ => false,
            };
        }
        return false;
    }
}

impl<'a> std::cmp::PartialEq<Session> for &'a Session {
    fn eq(&self, other: &Session) -> bool {
        if self.peer_identity == other.peer_identity {
            return match (&self.state, &other.state) {
                (SessionState::New {}, SessionState::New {}) => true,
                (SessionState::Initialised { .. }, SessionState::Initialised { .. }) => true,
                _ => false,
            };
        }
        return false;
    }
}

impl Eq for Session {}

#[derive(Clone)]
pub struct SessionManager {
    session: Session,
    keys: Arc<dyn KeyAccess>,
}

impl SessionManager {
    pub fn new(peer_identity: PublicKey, keys: Arc<dyn KeyAccess>) -> SessionManager {
        SessionManager {
            session: Session {
                peer_identity,
                state: SessionState::New {},
            },
            keys,
        }
    }

    pub fn manage_session(session: Session, keys: Arc<dyn KeyAccess>) -> SessionManager {
        SessionManager { session, keys }
    }

    pub fn session(&self) -> &Session {
        &self.session
    }

    pub fn received_pre_keys(&mut self, bundle: PreKeyBundle) -> Result<(), ProtocolError> {
        match &mut self.session.state {
            SessionState::Initialised { .. } => Err(ProtocolError::InvalidSessionState {
                message: "Received pre keys, but session is already initialised".to_string(),
            }),
            SessionState::New {} | SessionState::ReceivedPreKeyBundle { .. } => {
                let peer = bundle
                    .identity
                    .clone()
                    .ok_or_else(|| ProtocolError::InvalidInput {
                        message: "Identity missing in pre key bundle".to_string(),
                    })?;
                let identity = PublicKey::from_bytes(&peer.identity[..]).map_err(|cause| {
                    ProtocolError::FailedCryptography {
                        message: "Decode of peer identity".to_string(),
                        cause,
                    }
                })?;

                if identity != self.session.peer_identity {
                    return Err(ProtocolError::InvalidSessionState {
                        message: "Peer identity in pre key bundle does not match session"
                            .to_string(),
                    });
                }

                identity
                    .verify(&bundle.pre_key[..], &bundle.pre_key_signature[..])
                    .map_err(|cause| ProtocolError::FailedCryptography {
                        message: "Verification of pre key signature".to_string(),
                        cause,
                    })?;

                let pre_key = PublicKey::from_bytes(&bundle.pre_key[..]).map_err(|cause| {
                    ProtocolError::FailedCryptography {
                        message: "Decode of pre key".to_string(),
                        cause,
                    }
                })?;

                let one_time_key = if let Some(bytes) = bundle.one_time_pre_keys.first() {
                    let one_time_key = PublicKey::from_bytes(&bytes[..]).map_err(|cause| {
                        ProtocolError::FailedCryptography {
                            message: "Decode of one time key".to_string(),
                            cause,
                        }
                    })?;
                    Ok(Some(one_time_key))
                } else {
                    Ok(None)
                }?;

                self.session.state = SessionState::ReceivedPreKeyBundle {
                    identity,
                    pre_key,
                    one_time_key,
                };
                Ok(())
            }
        }
    }

    fn received_key_exchange(&mut self, exchange: &KeyExchange) -> Result<(), ProtocolError> {
        let ephemeral = PublicKey::from_bytes(&exchange.ephemeral_key[..]).map_err(|cause| {
            ProtocolError::FailedCryptography {
                message: "Decode of ephemeral key".to_string(),
                cause,
            }
        })?;

        let otk = if exchange.one_time_key.is_empty() {
            None
        } else {
            let key = PublicKey::from_bytes(&exchange.one_time_key[..]).map_err(|cause| {
                ProtocolError::FailedCryptography {
                    message: "Decode of one time key".to_string(),
                    cause,
                }
            })?;
            Some(key)
        }
        .map(|otk_pub| self.keys.one_time_key_access(&otk_pub))
        .flatten();

        let pre_key = self.keys.pre_key_access();

        let secret = x3dh_agree_respond(
            &self.session.peer_identity,
            self.keys.deref(),
            &ephemeral,
            &pre_key,
            otk.as_ref(),
        );

        let ratchet = ManagedRatchet::initialise_received(&secret, &pre_key).map_err(|cause| {
            ProtocolError::FailedCryptography {
                message: "Initialisation of ratchet".to_string(),
                cause,
            }
        })?;

        // TODO history
        self.session.state = SessionState::Initialised { ratchet };

        Ok(())
    }

    pub fn receive(
        &mut self,
        session_params: &SessionParameters,
    ) -> Result<RecvStep, ProtocolError> {
        let peer_certificate =
            session_params
                .origin
                .as_ref()
                .ok_or_else(|| ProtocolError::InvalidInput {
                    message: "Origin missing in exchange".to_string(),
                })?;

        // TODO validate signer
        let (peer_certificate, _) =
            CertificateFactory::decode(peer_certificate).map_err(|cause| {
                ProtocolError::FailedCryptography {
                    message: "Decode of peer identity".to_string(),
                    cause,
                }
            })?;

        if peer_certificate.public_key() != self.session.peer_identity {
            return Err(ProtocolError::InvalidSessionState {
                message: "Peer identity in session message does not match session".to_string(),
                // TODO advice?
            });
        }

        if let Some(ref key_exchange) = session_params.key_exchange {
            self.received_key_exchange(key_exchange)?;
        }

        let params = session_params
            .params
            .as_ref()
            .ok_or_else(|| ProtocolError::InvalidInput {
                message: "Encryption parameters missing in exchange".to_string(),
            })?;

        match &mut self.session.state {
            SessionState::Initialised { ratchet } => {
                let ratchet_key =
                    PublicKey::from_bytes(&params.ratchet_key[..]).map_err(|cause| {
                        ProtocolError::FailedCryptography {
                            message: "Decode of ratchet key".to_string(),
                            cause,
                        }
                    })?;

                let step = ratchet
                    .recv_step_for(ratchet_key, params.chain_idx, params.prev_chain_count)
                    .map_err(|cause| ProtocolError::FailedCryptography {
                        message: "Decode of ratchet key".to_string(),
                        cause,
                    })?;
                Ok(step)
            }
            // for now ignore the existing pre keys, being able to decrypt an incoming message is priority
            SessionState::New {} | SessionState::ReceivedPreKeyBundle { .. } => {
                Err(ProtocolError::InvalidSessionState {
                    message: "Uninitialised session cannot process received message".to_string(),
                    // TODO advice, refresh session
                })
            }
        }
    }

    pub fn send(&mut self) -> Result<SendingStatus, ProtocolError> {
        match &mut self.session.state {
            SessionState::New {} => Ok(SendingStatus::RequirePreKeys {}),
            SessionState::Initialised { ratchet } => Ok(SendingStatus::Ok {
                key_exchange: None,
                step: ratchet.send_step(),
            }),
            SessionState::ReceivedPreKeyBundle {
                identity: other_identity,
                pre_key,
                one_time_key,
            } => {
                let (eph_key, secret) = x3dh_agree_initial(
                    self.keys.deref(),
                    &other_identity,
                    &pre_key,
                    one_time_key.as_ref(),
                );

                let mut ratchet =
                    ManagedRatchet::initialise_to_send(&secret, &pre_key).map_err(|cause| {
                        ProtocolError::FailedCryptography {
                            message: "Initialisation of ratchet".to_string(),
                            cause,
                        }
                    })?;

                let step = ratchet.send_step();

                let exchange = KeyExchange {
                    ephemeral_key: eph_key.id_bytes(),
                    one_time_key: one_time_key
                        .map(|otk_pub| otk_pub.id_bytes())
                        .unwrap_or(vec![]),
                };

                self.session.state = SessionState::Initialised { ratchet };

                Ok(SendingStatus::Ok {
                    key_exchange: Some(exchange),
                    step,
                })
            }
        }
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    use crate::crypto::certificates::certificate_tests::create_self_signed_cert;
    use crate::crypto::{PrivateKey, Signer};

    use crate::model::common;
    use crate::model::messages::EncryptionParameters;

    #[test]
    fn new_state_requires_key_exchange_to_receive() {
        let (my_key, my_cert) = create_self_signed_cert();

        let my_cert = common::Certificate {
            certificate: my_cert.encoded_certificate().to_vec(),
            signature: my_cert.signature().to_vec(),
        };

        let mut sess_mgr = SessionManager::new(
            my_key.public_key().clone(),
            Arc::new(MockCryptoProvider::any()),
        );

        let params = EncryptionParameters {
            ratchet_key: vec![],
            chain_idx: 0,
            prev_chain_count: 0,
        };

        let session_msg = SessionParameters {
            origin: Some(my_cert),
            params: Some(params),
            key_exchange: None,
        };

        let result = sess_mgr.receive(&session_msg);
        assert!(result.is_err());
        assert!(match result.unwrap_err() {
            ProtocolError::InvalidSessionState { .. } => true,
            _ => false,
        });
    }

    #[test]
    fn new_state_requires_pre_keys_to_send() {
        let bob_key = PrivateKey::generate().unwrap();

        let mut sess_mgr = SessionManager::new(
            PrivateKey::generate().unwrap().public_key().clone(),
            Arc::new(MockCryptoProvider::new(bob_key)),
        );

        let result = sess_mgr.send();
        assert!(result.is_ok());
        assert!(match result.unwrap() {
            SendingStatus::RequirePreKeys {} => true,
            _ => false,
        });
    }

    #[test]
    fn pre_key_state_sends() {
        let alice_key = PrivateKey::generate().unwrap();
        let (alice_bundle, alice_bundle_privates) = prepare_pre_keys(&alice_key);

        let bob_key = PrivateKey::generate().unwrap();

        let mock_keys = Arc::new(MockCryptoProvider::new(bob_key.clone()));

        let mut sess_mgr = SessionManager::new(alice_key.public_key().clone(), mock_keys);

        sess_mgr.received_pre_keys(alice_bundle).unwrap();

        let result = sess_mgr.send();
        assert!(result.is_ok());

        let key_exchange;
        let send_step;
        if let SendingStatus::Ok {
            key_exchange: inner_exchange,
            step,
        } = result.unwrap()
        {
            send_step = step;
            assert!(inner_exchange.is_some());
            key_exchange = inner_exchange.unwrap();
        } else {
            panic!("Invalid state")
        }

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

    #[test]
    fn intialised_state_send() {
        let alice_key = PrivateKey::generate().unwrap();
        let (_, alice_bundle_privates) = prepare_pre_keys(&alice_key);
        let mock_keys = Arc::new(MockCryptoProvider::with_pre_key(
            alice_key.clone(),
            alice_bundle_privates.pre_key,
        ));

        let bob_key = PrivateKey::generate().unwrap();
        let eph_key = PrivateKey::generate().unwrap();

        let exchange = KeyExchange {
            ephemeral_key: eph_key.public_key().id_bytes(),
            one_time_key: vec![],
        };

        let mut sess_mgr = SessionManager::new(bob_key.public_key().clone(), mock_keys);

        let result = sess_mgr.received_key_exchange(&exchange);
        assert!(result.is_ok());

        let result = sess_mgr.send();
        assert!(result.is_ok());
        assert!(match result.unwrap() {
            SendingStatus::Ok { key_exchange, .. } => key_exchange.is_none(),
            _ => false,
        });
    }

    #[test]
    fn new_state_receives_pre_keys_with_wrong_identity() {
        let any_unrelated_key = PrivateKey::generate().unwrap().public_key().clone();
        let mut sess_mgr =
            SessionManager::new(any_unrelated_key, Arc::new(MockCryptoProvider::any()));

        let (alice_bundle, _) = prepare_pre_keys(&PrivateKey::generate().unwrap());
        let result = sess_mgr.received_pre_keys(alice_bundle);
        assert!(result.is_err());
        assert!(match result.unwrap_err() {
            ProtocolError::InvalidSessionState { .. } => true,
            _ => false,
        });
    }

    #[test]
    fn receives_key_exchange_with_wrong_identity() {
        let (_, my_cert) = create_self_signed_cert();

        let my_cert = common::Certificate {
            certificate: my_cert.encoded_certificate().to_vec(),
            signature: my_cert.signature().to_vec(),
        };

        let exchange = KeyExchange {
            ephemeral_key: vec![],
            one_time_key: vec![],
        };

        let session_msg = SessionParameters {
            origin: Some(my_cert),
            params: None,
            key_exchange: Some(exchange),
        };

        let any_unrelated_key = PrivateKey::generate().unwrap().public_key().clone();
        let mut sess_mgr =
            SessionManager::new(any_unrelated_key, Arc::new(MockCryptoProvider::any()));

        let result = sess_mgr.receive(&session_msg);
        assert!(result.is_err());
        assert!(match result.unwrap_err() {
            ProtocolError::InvalidSessionState { .. } => true,
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

    impl KeyAgreement for MockCryptoProvider {
        fn agree(&self, public: &PublicKey) -> [u8; 32] {
            self.key.agree(public)
        }
    }

    impl Signer for MockCryptoProvider {
        fn public_key(&self) -> &PublicKey {
            self.key.public_key()
        }

        fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
            self.key.sign(data)
        }
    }

    impl KeyAccess for MockCryptoProvider {
        fn pre_key_access(&self) -> PrivateKey {
            self.pre_key.clone()
        }

        fn one_time_key_access(&self, _: &PublicKey) -> Option<PrivateKey> {
            return None;
        }
    }
}
