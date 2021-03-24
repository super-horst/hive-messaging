use serde::{Deserialize, Serialize};

use crate::crypto::*;
use crate::model::*;

mod error;

pub use error::*;

mod session;

pub use session::*;
use std::sync::Arc;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrivatePreKeys {
    pub(crate) pre_key: PrivateKey,
    pub(crate) one_time_keys: Vec<PrivateKey>,
}

// TODO add error::advice field to maybe mitigate error
pub trait KeyAccess: KeyAgreement {
    fn pre_key_access(&self) -> &PrivateKey;

    fn one_time_key_access(&self, public: &PublicKey) -> Option<PrivateKey>;
}

pub fn encrypt_session(
    destination: &PublicKey,
    session_params: messages::SessionParameters,
) -> Result<(PublicKey, Vec<u8>), ProtocolError> {
    let eph_key = PrivateKey::generate().map_err(|cause| ProtocolError::FailedCryptography {
        message: "Generate ephemeral key".to_string(),
        cause,
    })?;

    let shared_secret = eph_key.agree(destination);

    let encoded_session =
        session_params.encode().map_err(|cause| ProtocolError::FailedSerialisation { cause })?;
    let encrypted_session = encryption::encrypt(&shared_secret[..], &encoded_session[..]);

    Ok((eph_key.public_key().clone(), encrypted_session))
}

pub fn decrypt_session(
    my_key: &impl KeyAgreement,
    ephemeral_key: PublicKey,
    encrypted_session: &[u8],
) -> Result<messages::SessionParameters, ProtocolError> {
    let shared_secret = my_key.agree(&ephemeral_key);

    let encoded_session = encryption::decrypt(&shared_secret[..], encrypted_session);
    messages::SessionParameters::decode(encoded_session)
        .map_err(|cause| ProtocolError::FailedSerialisation { cause })
}

pub fn sign_challenge(
    signature_key: &impl Signer,
) -> Result<common::SignedChallenge, ProtocolError> {
    let timestamp = crate::time::now().map_err(|cause| ProtocolError::CommonFailure {
        message: "Failed to get time".to_string(),
        cause,
    })?;

    let public_key = signature_key.public_key();
    let challenge_dto = common::signed_challenge::Challenge {
        identity: Some(public_key.into_peer()),
        timestamp,
    };

    let challenge = challenge_dto
        .encode()
        .map_err(|cause| ProtocolError::FailedSerialisation { cause })?;

    let signature =
        signature_key
            .sign(&challenge[..])
            .map_err(|cause| ProtocolError::FailedCryptography {
                message: "Failed to sign challenge".to_string(),
                cause,
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

pub fn create_pre_key_bundle(
    identity: &impl Signer,
) -> Result<(common::PreKeyBundle, PrivatePreKeys), CryptoError> {
    let pre_private_key = PrivateKey::generate()?;
    let pre_public_key = pre_private_key.public_key().clone();
    let pre_public_key_bytes = pre_public_key.id_bytes();

    let signed_pre_key = identity.sign(&pre_public_key_bytes[..])?;

    let mut count = 0;
    let otps = std::iter::from_fn(move || {
        count += 1;

        if count < 10 {
            return PrivateKey::generate().ok();
        }
        return None;
    })
        .collect::<Vec<PrivateKey>>();

    let publics = otps
        .iter()
        .map(PrivateKey::public_key.clone())
        .map(PublicKey::id_bytes)
        .collect();

    let pre_key_bundle = common::PreKeyBundle {
        identity: Some(identity.public_key().into_peer()),
        pre_key: pre_public_key_bytes,
        pre_key_signature: signed_pre_key,
        one_time_pre_keys: publics,
    };

    let privates = PrivatePreKeys {
        pre_key: pre_private_key,
        one_time_keys: otps,
    };

    Ok((pre_key_bundle, privates))
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

        let (bobs_key, bobs_cert) = create_self_signed_cert();

        let session_params = messages::SessionParameters {
            origin: None,
            params: Some(enc_params),
            key_exchange: None,
        };

        let (eph_key, encrypted_session) =
            encrypt_session(bobs_key.public_key(), session_params).unwrap();

        let recylced_session = decrypt_session(&bobs_key, eph_key, &encrypted_session).unwrap();
        let recycled_params = recylced_session.params.unwrap();

        assert_eq!(data.to_vec(), recycled_params.ratchet_key)
    }
}
