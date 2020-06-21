use std::{io, fmt, sync, borrow};
use sync::Arc;
use io::Write;
use borrow::Borrow;

use ed25519_dalek;
use sha2::Sha512;
use rand::rngs::OsRng;

use crate::crypto::interfaces::*;

//TODO initial implementation is not ready for production!


/// Simple Identities object
#[derive(Debug)]
pub struct SimpleDalekIdentities {
    my_id: Arc<dyn PrivateIdentity>,
}

/// Dalek identities provider
impl SimpleDalekIdentities {
    pub fn new(private: Arc<dyn PrivateIdentity>) -> SimpleDalekIdentities {
        return SimpleDalekIdentities { my_id: private };
    }
}

#[async_trait::async_trait]
impl Identities for SimpleDalekIdentities {
    async fn resolve_id(&self, id: &[u8]) -> Result<Box<dyn PublicIdentity>, CryptoError> {
        let public = ed25519_dalek::PublicKey::from_bytes(id)
            .map_err(|e| CryptoError::Signature {
                message: "Failed to decode public key".to_string(),
                cause: e,
            })?;

        Ok(Box::new(DalekEd25519PublicId { inner: public }))
    }

    fn my_id(&self) -> &dyn PrivateIdentity {
        self.my_id.borrow()
    }
}

/// Dalek public key
pub struct DalekEd25519PublicId {
    inner: ed25519_dalek::PublicKey,
}

impl PublicIdentity for DalekEd25519PublicId {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let signature = ed25519_dalek::Signature::from_bytes(signature)
            .map_err(|e| CryptoError::Signature {
                message: "Failed to convert signature".to_string(),
                cause: e,
            })?;

        self.inner.verify::<Sha512>(&data[..], &signature)
            .map_err(|e| CryptoError::Signature {
                message: "Failed to verify signature".to_string(),
                cause: e,
            })?;

        Ok(())
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

impl Identity for DalekEd25519PublicId {
    fn id(&self) -> String {
        hex::encode(self.inner.as_bytes())
    }
    fn namespace(&self) -> String {
        "my::namespace".to_string()
    }
}

impl fmt::Debug for DalekEd25519PublicId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 dalek public key: {}", self.id())
    }
}

/// Dalek private key
pub struct DalekEd25519PrivateId {
    secret: ed25519_dalek::SecretKey,
    public: DalekEd25519PublicId,
}

impl PrivateIdentity for DalekEd25519PrivateId {
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = self.secret.expand::<Sha512>()
                            .sign::<Sha512>(data, &self.public.inner);

        Ok(Vec::from(&signature.to_bytes()[..]))
    }

    fn public_id(&self) -> &dyn PublicIdentity {
        &self.public
    }
}

impl PublicIdentity for DalekEd25519PrivateId {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        self.public.verify(data, signature)
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.public.as_bytes()
    }
}

impl Identity for DalekEd25519PrivateId {
    fn id(&self) -> String {
        self.public.id()
    }

    fn namespace(&self) -> String {
        "my::namespace".to_string()
    }
}

impl DalekEd25519PrivateId {
    pub fn generate() -> DalekEd25519PrivateId {
        // TODO handle error
        let private = ed25519_dalek::SecretKey::generate(&mut OsRng::new().unwrap());

        let public = DalekEd25519PublicId { inner: ed25519_dalek::PublicKey::from_secret::<Sha512>(&private) };

        DalekEd25519PrivateId { secret: private, public }
    }

    pub fn new(private: ed25519_dalek::SecretKey) -> DalekEd25519PrivateId {
        let public = DalekEd25519PublicId { inner: ed25519_dalek::PublicKey::from_secret::<Sha512>(&private) };

        DalekEd25519PrivateId { secret: private, public }
    }
}

impl fmt::Debug for DalekEd25519PrivateId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 dalek private key: {}", self.id())
    }
}


#[cfg(test)]
mod dalek_crypto_tests {
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn test_dalek_sign_verify() {
        let data: &[u8] = b"testdata is overrated";

        let wrapped_privates = DalekEd25519PrivateId::generate();

        let signed = wrapped_privates.sign(data).unwrap();

        wrapped_privates.verify(data, &signed).unwrap();
    }
}