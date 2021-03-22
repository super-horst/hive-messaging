use crate::crypto::*;
use crate::model::*;

mod error;

pub use error::*;

mod session;

pub use session::*;

// TODO add error::advice field to maybe mitigate error

pub trait KeyAccess {
    //TODO refactor ... make identity key inaccessible
    fn identity_access(&self) -> &PrivateKey;

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

    let encoded_session = session_params
        .encode()
        .map_err(|cause| ProtocolError::FailedSerialisation { cause })?;
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
    signature_key: impl Signer,
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
