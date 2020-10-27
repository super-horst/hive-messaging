use crate::crypto::error::*;
use crate::crypto::{PrivateKey, PublicKey};

use crate::model::*;

pub fn sign_challenge(identity: &PrivateKey) -> Result<common::SignedChallenge, CryptoError> {
    let timestamp = crate::time::now().map_err(|e| CryptoError::Common {
        message: "Failed to get time".to_string(),
        cause: e,
    })?;

    let public_key = identity.id();

    let peer_dto = common::Peer {
        identity: public_key.id_bytes(),
        namespace: public_key.namespace(),
    };

    let challenge_dto = common::signed_challenge::Challenge {
        identity: Some(peer_dto),
        timestamp,
    };

    let challenge = challenge_dto
        .encode()
        .map_err(|e| CryptoError::Serialisation {
            message: "Failed to serialise challenge".to_string(),
            cause: e,
        })?;

    let signature = identity.sign(&challenge[..])?;

    public_key.verify(&challenge[..], &signature[..])?;

    Ok(common::SignedChallenge {
        challenge,
        signature,
    })
}
