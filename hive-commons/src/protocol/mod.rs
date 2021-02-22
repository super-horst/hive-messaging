use crate::crypto::*;
use crate::model::*;

mod error;

use hkdf::Hkdf;
use sha2::Sha512;

pub use error::*;

pub mod session;

pub use session::*;

// TODO add error::advice field to maybe mitigate error

pub trait KeyAccess {
    fn identity_access(&self) -> &PrivateKey;

    fn pre_key_access(&self) -> &PrivateKey;

    fn one_time_key_access(&self, public: &PublicKey) -> Option<PrivateKey>;
}

pub struct MyIdentity {
    my_key: PrivateKey,
    // TODO append certificate
    //my_certificate: Certificate,
}

impl MyIdentity {
    pub fn encrypt_session(
        &self,
        destination: &PublicKey,
        enc_params: messages::EncryptionParameters,
        key_exchange: Option<messages::KeyExchange>,
    ) -> Result<(PublicKey, Vec<u8>), ProtocolError> {
        let (eph_key_data, eph_key) = {
            let tmp_key =
                PrivateKey::generate().map_err(|cause| ProtocolError::FailedCryptography {
                    message: "Generate ephemeral key".to_string(),
                    cause,
                })?;

            let mut salt = Vec::with_capacity(2 * 32);
            salt.extend_from_slice(&destination.id_bytes());
            salt.extend_from_slice(&tmp_key.public_key().id_bytes());

            let shared_secret = tmp_key.diffie_hellman(destination);

            let kdf = Hkdf::<Sha512>::new(Some(&salt), &shared_secret);
            let mut okm = [0u8; 32];
            // ignore the error, length should always match
            let _r = kdf.expand(&[0u8; 0], &mut okm);
            (okm, tmp_key.public_key().clone())
        };

        let session_msg = messages::SessionMessage {
            origin: Some(self.my_key.public_key().into_peer()),
            params: Some(enc_params),
            key_exchange,
        };

        let encoded_session = session_msg
            .encode()
            .map_err(|cause| ProtocolError::FailedSerialisation { cause })?;
        let encrypted_session = encryption::encrypt(&eph_key_data[..], &encoded_session[..]);

        Ok((eph_key, encrypted_session))
    }

    pub fn decrypt_session(
        &self,
        eph_key: PublicKey,
        encrypted_session: &[u8],
    ) -> Result<messages::SessionMessage, ProtocolError> {
        let eph_key_data = {
            let mut salt = Vec::with_capacity(2 * 32);
            salt.extend_from_slice(&self.my_key.public_key().id_bytes());
            salt.extend_from_slice(&eph_key.id_bytes());

            let shared_secret = self.my_key.diffie_hellman(&eph_key);

            let kdf = Hkdf::<Sha512>::new(Some(&salt), &shared_secret);
            let mut okm = [0u8; 32];
            // ignore the error, length should always match
            let _r = kdf.expand(&[0u8; 0], &mut okm);
            okm
        };

        let encoded_session = encryption::decrypt(&eph_key_data[..], encrypted_session);
        messages::SessionMessage::decode(encoded_session)
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

    #[test]
    fn test_public_serialise_deserialise() {
        let data: &[u8] = b"testdata is overrated";
        let enc_params = messages::EncryptionParameters {
            ratchet_key: data.to_vec(),
            chain_idx: 0,
            prev_chain_count: 0,
        };

        let alices_identity = MyIdentity {
            my_key: PrivateKey::generate().unwrap(),
        };
        let bobs_identity = MyIdentity {
            my_key: PrivateKey::generate().unwrap(),
        };

        let (eph_key, encrypted_session) = alices_identity
            .encrypt_session(bobs_identity.my_key.public_key(), enc_params, None)
            .unwrap();

        let recylced_session = bobs_identity.decrypt_session(eph_key, &encrypted_session).unwrap();
        let recycled_params = recylced_session.params.unwrap();

        assert_eq!(data.to_vec(), recycled_params.ratchet_key)
    }
}
