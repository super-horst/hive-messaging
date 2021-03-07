use std::time::UNIX_EPOCH;

use crate::model::*;

mod error;
pub use error::*;

mod keys;
pub use keys::{PrivateKey, PublicKey};

pub(crate) mod certificates;
pub use certificates::{Certificate, CertificateFactory, CertificateInfoBundle};

mod x3dh;
pub use x3dh::*;

mod ratchet;
pub use ratchet::{ManagedRatchet, RecvStep, SendStep};

pub mod encryption;

pub mod utils;

pub trait Verifier {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;
}

pub trait Signer {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

pub trait KeyAgreement {
    fn agree(&self, public: &PublicKey) -> [u8; 32];
}

pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
}

impl Encodable for Certificate {
    fn encode(&self) -> Result<Vec<u8>, SerialisationError> {
        common::Certificate {
            certificate: self.encoded_certificate().to_vec(),
            signature: self.signature().to_vec(),
        }
            .encode()
    }
}

impl Encodable for CertificateInfoBundle {
    fn encode(&self) -> Result<Vec<u8>, SerialisationError> {
        let expires = self
            .expiration
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| SerialisationError::Message {
                message: e.to_string(),
            })?;

        let mut tbs_cert = common::certificate::TbsCertificate {
            identity: self.identity.id_bytes(),
            namespace: self.identity.namespace(),
            expires,
            uuid: self.serial.clone(),
            signer: None,
        };

        match &self.signer_certificate {
            Some(c) => {
                let gc = common::Certificate {
                    certificate: c.encoded_certificate().to_vec(),
                    signature: c.signature().to_vec(),
                };
                tbs_cert.signer = Some(gc);
            }
            None => (),
        }

        tbs_cert.encode()
    }
}

impl Into<messages::EncryptionParameters> for SendStep {
    fn into(self) -> messages::EncryptionParameters {
        return messages::EncryptionParameters {
            ratchet_key: self.ratchet_key.id_bytes(),
            chain_idx: self.counter,
            prev_chain_count: self.prev_ratchet_counter,
        };
    }
}

impl PublicKey {
    pub fn into_peer(&self) -> common::Peer {
        common::Peer {
            identity: self.id_bytes(),
            namespace: self.namespace(),
        }
    }
}
