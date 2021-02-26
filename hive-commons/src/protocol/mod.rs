use crate::crypto::*;
use crate::model::*;

mod error;

pub use error::*;

mod session;

pub use session::*;

// TODO add error::advice field to maybe mitigate error

pub trait KeyAccess {
    fn identity_access(&self) -> &PrivateKey;

    fn pre_key_access(&self) -> &PrivateKey;

    fn one_time_key_access(&self, public: &PublicKey) -> Option<PrivateKey>;
}

pub struct MyIdentity {
    my_key: PrivateKey,
    my_certificate: Certificate,
}

impl MyIdentity {
    pub fn new(my_key: PrivateKey, my_certificate: Certificate) -> MyIdentity {
        MyIdentity {
            my_key,
            my_certificate,
        }
    }

    pub fn encrypt_session(
        &self,
        destination: &PublicKey,
        enc_params: messages::EncryptionParameters,
        key_exchange: Option<messages::KeyExchange>,
    ) -> Result<(PublicKey, Vec<u8>), ProtocolError> {
        let eph_key =
            PrivateKey::generate().map_err(|cause| ProtocolError::FailedCryptography {
                message: "Generate ephemeral key".to_string(),
                cause,
            })?;

        let shared_secret = eph_key.diffie_hellman(destination);

        let certificate = common::Certificate {
            certificate: self.my_certificate.encoded_certificate().to_vec(),
            signature: self.my_certificate.signature().to_vec(),
        };

        let session_params = messages::SessionParameters {
            origin: Some(certificate),
            params: Some(enc_params),
            key_exchange,
        };

        let encoded_session = session_params
            .encode()
            .map_err(|cause| ProtocolError::FailedSerialisation { cause })?;
        let encrypted_session = encryption::encrypt(&shared_secret[..], &encoded_session[..]);

        Ok((eph_key.public_key().clone(), encrypted_session))
    }

    pub fn decrypt_session(
        &self,
        eph_key: PublicKey,
        encrypted_session: &[u8],
    ) -> Result<messages::SessionParameters, ProtocolError> {
        let shared_secret = self.my_key.diffie_hellman(&eph_key);

        let encoded_session = encryption::decrypt(&shared_secret[..], encrypted_session);
        messages::SessionParameters::decode(encoded_session)
            .map_err(|cause| ProtocolError::FailedSerialisation { cause })
    }

    pub fn sign_challenge(&self) -> Result<common::SignedChallenge, ProtocolError> {
        let timestamp = crate::time::now().map_err(|cause| ProtocolError::CommonFailure {
            message: "Failed to get time".to_string(),
            cause,
        })?;

        let public_key = self.my_key.public_key();
        let challenge_dto = common::signed_challenge::Challenge {
            identity: Some(public_key.into_peer()),
            timestamp,
        };

        let challenge = challenge_dto
            .encode()
            .map_err(|cause| ProtocolError::FailedSerialisation { cause })?;

        let signature = self.my_key.sign(&challenge[..]).map_err(|cause| {
            ProtocolError::FailedCryptography {
                message: "Failed to sign challenge".to_string(),
                cause,
            }
        })?;

        public_key
            .verify(&challenge[..], &signature[..])
            .map_err(|cause| ProtocolError::FailedCryptography {
                message: "Failed to verify challenge signature".to_string(),
                cause,
            })?;

        Ok(common::SignedChallenge {
            challenge,
            signature,
        })
    }
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    use crate::crypto::certificates::certificate_tests::create_self_signed_cert;

    #[test]
    fn test_public_serialise_deserialise() {
        let data: &[u8] = b"testdata is overrated";
        let enc_params = messages::EncryptionParameters {
            ratchet_key: data.to_vec(),
            chain_idx: 0,
            prev_chain_count: 0,
        };

        let (alices_key, alices_cert) = create_self_signed_cert();
        let alices_identity = MyIdentity {
            my_key: alices_key,
            my_certificate: alices_cert,
        };
        let (bobs_key, bobs_cert) = create_self_signed_cert();
        let bobs_identity = MyIdentity {
            my_key: bobs_key,
            my_certificate: bobs_cert,
        };

        let (eph_key, encrypted_session) = alices_identity
            .encrypt_session(bobs_identity.my_key.public_key(), enc_params, None)
            .unwrap();

        let recylced_session = bobs_identity
            .decrypt_session(eph_key, &encrypted_session)
            .unwrap();
        let recycled_params = recylced_session.params.unwrap();

        assert_eq!(data.to_vec(), recycled_params.ratchet_key)
    }
}
