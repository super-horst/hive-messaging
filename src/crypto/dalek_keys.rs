use crate::prelude::*;
use std::sync::Arc;
use std::borrow::Borrow;

use x25519_dalek;
use ed25519_dalek;
use sha2::Sha512;

// TODO resolve cycle
use super::*;

//TODO initial implementation is not ready for production!
//TODO [UPDATE] ... coming closer to be ready for production!

const COMBINED_PUBLIC_KEY_SIZE: usize = 64;

/// Simple Identities object
#[derive(Debug)]
pub struct SimpleDalekIdentities<'a> {
    my_id: PrivateKey,
    my_certificate: Certificate<'a>,
}

/// Dalek identities provider
impl SimpleDalekIdentities<'_> {
    pub fn new(private: PrivateKey, certificate: Certificate<'_>) -> SimpleDalekIdentities<'_> {
        return SimpleDalekIdentities { my_id: private, my_certificate: certificate };
    }
}

#[async_trait::async_trait]
impl<'a> Identities for SimpleDalekIdentities<'a> {
    async fn resolve_id(&self, id: &[u8]) -> Result<PublicKey, CryptoError> {
        PublicKey::from_raw_bytes(id)
    }

    fn my_id(&self) -> &PrivateKey {
        &self.my_id
    }

    fn my_certificate(&self) -> &Certificate<'_> {
        self.my_certificate.borrow()
    }
}

/// Dalek public key
pub struct PublicKey {
    ed_public: ed25519_dalek::PublicKey,
    x_public: x25519_dalek::PublicKey,
}

impl PublicKey {
    /// parse an identity from raw bytes
    pub fn from_raw_bytes(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
        if bytes.len() < COMBINED_PUBLIC_KEY_SIZE {
            return Err(CryptoError::Message { message: "Invalid public key format".to_string() });
        }

        let mut ed_bytes = [0u8; 32];
        let mut x_bytes = [0u8; 32];

        ed_bytes.clone_from_slice(&bytes[..32]);
        x_bytes.clone_from_slice(&bytes[32..]);

        let ed_public = ed25519_dalek::PublicKey::from_bytes(&ed_bytes[..])
            .map_err(|e| CryptoError::Key {
                message: "ed25519 decode failed".to_string(),
                cause: e,
            })?;

        let x_public = x25519_dalek::PublicKey::from(x_bytes);

        Ok(PublicKey { ed_public, x_public })
    }

    fn new(ed_public: ed25519_dalek::PublicKey, x_public: x25519_dalek::PublicKey) -> Result<PublicKey, CryptoError> {
        Ok(PublicKey { ed_public, x_public })
    }

    /// encode public identity as string
    pub fn id_string(&self) -> String {
        hex::encode(self.ed_public.as_bytes())
    }

    /// encode public identity as bytes
    pub fn id_bytes(&self) -> Vec<u8> {
        let ed_bytes = self.ed_public.as_bytes();
        let x_bytes = self.x_public.as_bytes();

        let mut buffer = ed_bytes.to_vec();
        buffer.append(&mut x_bytes.to_vec());

        buffer
    }

    /// this identity's namespace
    pub fn namespace(&self) -> String {
        //TODO
        "my::namespace".to_string()
    }

    ///Verify a raw byte signature
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        let signature = ed25519_dalek::Signature::from_bytes(signature)
            .map_err(|e| CryptoError::Signature {
                message: "Failed to convert signature".to_string(),
                cause: e,
            })?;

        self.ed_public.verify::<Sha512>(&data[..], &signature)
            .map_err(|e| CryptoError::Signature {
                message: "Failed to verify signature".to_string(),
                cause: e,
            })?;

        Ok(())
    }

    /// make a copy of myself
    pub fn copy(&self) -> PublicKey {
        let bytes = self.id_bytes();

        // expect no errors ... just recycling
        PublicKey::from_raw_bytes(&bytes[..])
            .expect("Failed to copy DalekEd25519PublicId")
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 dalek public key: {}", self.id_string())
    }
}

/// Dalek private key
pub struct PrivateKey {
    ed_secret: ed25519_dalek::SecretKey,
    x_secret: x25519_dalek::StaticSecret,
    public: PublicKey,
}

impl PrivateKey {
    pub fn generate() -> Result<PrivateKey, CryptoError> {
        // just use x25519 for key generation
        use rand_core::OsRng;
        let raw_privates = x25519_dalek::StaticSecret::new(&mut OsRng).to_bytes();

        PrivateKey::from_raw_bytes(raw_privates)
    }

    pub(crate) fn from_raw_bytes(private: [u8; 32]) -> Result<PrivateKey, CryptoError> {
        let ed_private = ed25519_dalek::SecretKey::from_bytes(&private[..])
            .map_err(|e| CryptoError::Key {
                message: "Failed to process secret key bytes".to_string(),
                cause: e,
            })?;

        PrivateKey::new(ed_private)
    }

    pub fn new(ed_private: ed25519_dalek::SecretKey) -> Result<PrivateKey, CryptoError> {
        let x_private = x25519_dalek::StaticSecret::from(ed_private.to_bytes());

        let ed_public = ed25519_dalek::PublicKey::from_secret::<Sha512>(&ed_private);
        let x_public = x25519_dalek::PublicKey::from(&x_private);

        let public = PublicKey::new(ed_public, x_public)?;

        Ok(PrivateKey { ed_secret: ed_private, x_secret: x_private, public })
    }

    pub fn diffie_hellman(&self, public: &PublicKey) -> x25519_dalek::SharedSecret {
        self.x_secret.diffie_hellman(&public.x_public)
    }


    /// Sign some data using the underlying private key.
    /// Since the digest used is SHA512, output will be 64 bytes
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = self.ed_secret.expand::<Sha512>()
                            .sign::<Sha512>(data, &self.public.ed_public);

        Ok(Vec::from(&signature.to_bytes()[..]))
    }

    /// corresponding public key
    pub fn id(&self) -> &PublicKey {
        &self.public
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 dalek private key: {}", self.public.id_string())
    }
}

#[cfg(test)]
mod dalek_crypto_tests {
    use super::*;

    #[test]
    fn test_dalek_sign_verify() {
        let data: &[u8] = b"testdata is overrated";

        let wrapped_privates = PrivateKey::generate().unwrap();

        let signed = wrapped_privates.sign(data).unwrap();

        wrapped_privates.id().verify(data, &signed).unwrap();
    }

    #[test]
    fn test_public_key_encoding_decoding() {
        let wrapped_privates = PrivateKey::generate().unwrap();

        let original_public = wrapped_privates.public;

        let buffer = original_public.id_bytes();

        let recycled_public = PublicKey::from_raw_bytes(&buffer[..]).unwrap();

        assert_eq!(original_public.ed_public.to_bytes(), recycled_public.ed_public.to_bytes());
        assert_eq!(original_public.x_public.as_bytes(), recycled_public.x_public.as_bytes());
    }

    #[test]
    fn test_dalek_dh() {
        use x25519_dalek;
        use rand_core::OsRng;
        let a_x_privates = x25519_dalek::StaticSecret::new(&mut OsRng);
        let a_my_privates = PrivateKey::from_raw_bytes(a_x_privates.to_bytes()).unwrap();

        let b_x_privates = x25519_dalek::StaticSecret::new(&mut OsRng);
        let b_my_privates = PrivateKey::from_raw_bytes(b_x_privates.to_bytes()).unwrap();

        let dh1 = a_my_privates.diffie_hellman(&b_my_privates.public);
        let dh2 = b_my_privates.diffie_hellman(&a_my_privates.public);

        let dh3 = a_x_privates.diffie_hellman(&x25519_dalek::PublicKey::from(&b_x_privates));
        let dh4 = b_x_privates.diffie_hellman(&x25519_dalek::PublicKey::from(&a_x_privates));

        assert_eq!(dh1.as_bytes(), dh2.as_bytes());
        assert_eq!(dh1.as_bytes(), dh3.as_bytes());
        assert_eq!(dh1.as_bytes(), dh4.as_bytes());
        assert_eq!(dh2.as_bytes(), dh3.as_bytes());
        assert_eq!(dh2.as_bytes(), dh4.as_bytes());
        assert_eq!(dh3.as_bytes(), dh4.as_bytes());
    }
}