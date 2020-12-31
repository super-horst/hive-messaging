use serde::{Deserialize, Serialize};

use crate::crypto::error::*;
use crate::crypto::{FromBytes, ManagedRatchet, PrivateKey, PublicKey};

use crate::model::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrivatePreKeys {
    pre_key: PrivateKey,
    one_time_keys: Vec<PrivateKey>,
}

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

pub fn create_pre_key_bundle(
    identity: &PrivateKey,
) -> Result<(common::PreKeyBundle, PrivatePreKeys), CryptoError> {
    let pre_private_key = PrivateKey::generate()?;
    let pre_public_key = pre_private_key.id().clone();

    let signed_pre_key = identity.sign(&pre_public_key.id_bytes()[..]).unwrap();

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
        .map(PrivateKey::id.clone())
        .map(PublicKey::id_bytes)
        .collect();

    let pre_key_bundle = common::PreKeyBundle {
        identity: Some(identity.id().into_peer()),
        pre_key: pre_public_key.id_bytes(),
        pre_key_signature: signed_pre_key,
        one_time_pre_keys: publics,
    };

    let privates = PrivatePreKeys {
        pre_key: pre_private_key,
        one_time_keys: otps,
    };

    Ok((pre_key_bundle, privates))
}

pub fn initialise_ratchet_to_send(
    identity: &PrivateKey,
    bundle: common::PreKeyBundle,
) -> Result<ManagedRatchet, CryptoError> {
    let other_identity;
    if let Some(id) = bundle.identity {
        other_identity = PublicKey::from_bytes(&id.identity[..])?;
    } else {
        return Err(CryptoError::Message {
            message: "found no identity in bundle".to_string(),
        });
    }

    let dh = identity.diffie_hellman(&other_identity);
    ManagedRatchet::initialise_to_send(&dh, &other_identity)
}
