use serde::{Deserialize, Serialize};

use crate::crypto::error::*;
use crate::crypto::{PrivateKey, PublicKey, Signer};

use crate::model::*;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PrivatePreKeys {
    pub(crate) pre_key: PrivateKey,
    pub(crate) one_time_keys: Vec<PrivateKey>,
}

pub fn create_pre_key_bundle(
    identity: &PrivateKey,
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
