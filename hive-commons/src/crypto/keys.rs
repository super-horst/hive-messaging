use std::fmt;
use std::hash::Hasher;

use ed25519_dalek;
use sha2::Sha512;
use x25519_dalek;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::error::*;
use std::marker::PhantomData;

const COMBINED_PUBLIC_KEY_SIZE: usize = 64;

pub trait FromBytes: Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError>;
}

struct FromBytesVisitor<K> {
    _a: PhantomData<K>,
}

impl<K> FromBytesVisitor<K> {
    fn new() -> FromBytesVisitor<K>
    where
        K: FromBytes,
    {
        FromBytesVisitor { _a: PhantomData }
    }
}

impl<'de, K> Visitor<'de> for FromBytesVisitor<K>
where
    K: FromBytes,
{
    type Value = K;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("some bytes")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        K::from_bytes(v).map_err(|_ce| E::invalid_length(v.len(), &self))
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
        A::Error: serde::de::Error,
    {
        let mut buff = seq
            .size_hint()
            .map_or_else(|| Vec::new(), |size| Vec::with_capacity(size));

        // Update the max while there are additional values.
        while let Some(value) = seq.next_element()? {
            buff.push(value);
        }

        self.visit_bytes(&buff[..])
    }
}

/// Dalek public key
pub struct PublicKey {
    ed_public: ed25519_dalek::PublicKey,
    x_public: x25519_dalek::PublicKey,
}

impl PublicKey {
    fn new(
        ed_public: ed25519_dalek::PublicKey,
        x_public: x25519_dalek::PublicKey,
    ) -> Result<PublicKey, CryptoError> {
        Ok(PublicKey {
            ed_public,
            x_public,
        })
    }

    /// encode public identity as string
    pub fn id_string(&self) -> String {
        hex::encode(self.id_bytes())
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
        let signature = ed25519_dalek::Signature::from_bytes(signature).map_err(|e| {
            CryptoError::Signature {
                message: "Failed to convert signature".to_string(),
                cause: e,
            }
        })?;

        self.ed_public
            .verify::<Sha512>(&data[..], &signature)
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
        PublicKey::from_bytes(&bytes[..]).expect("Failed to copy DalekEd25519PublicId")
    }
}

impl FromBytes for PublicKey {
    /// parse an identity from raw bytes
    fn from_bytes(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
        if bytes.len() < COMBINED_PUBLIC_KEY_SIZE {
            return Err(CryptoError::Message {
                message: "Invalid public key format".to_string(),
            });
        }

        let mut ed_bytes = [0u8; 32];
        let mut x_bytes = [0u8; 32];

        ed_bytes.clone_from_slice(&bytes[..32]);
        x_bytes.clone_from_slice(&bytes[32..]);

        let ed_public =
            ed25519_dalek::PublicKey::from_bytes(&ed_bytes[..]).map_err(|e| CryptoError::Key {
                message: "ed25519 decode failed".to_string(),
                cause: e,
            })?;

        let x_public = x25519_dalek::PublicKey::from(x_bytes);

        Ok(PublicKey {
            ed_public,
            x_public,
        })
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.id_bytes()[..])
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(FromBytesVisitor::<PublicKey>::new())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 dalek public key: {}", self.id_string())
    }
}

impl std::cmp::PartialEq<PublicKey> for PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.id_bytes() == other.id_bytes()
    }
}

impl<'a> std::cmp::PartialEq<PublicKey> for &'a PublicKey {
    fn eq(&self, other: &PublicKey) -> bool {
        self.id_bytes() == other.id_bytes()
    }
}

impl Eq for PublicKey {}

impl std::hash::Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id_bytes().hash(state);
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

        PrivateKey::from_bytes(&raw_privates[..])
    }

    pub fn new(ed_private: ed25519_dalek::SecretKey) -> Result<PrivateKey, CryptoError> {
        let x_private = x25519_dalek::StaticSecret::from(ed_private.to_bytes());

        let ed_public = ed25519_dalek::PublicKey::from_secret::<Sha512>(&ed_private);
        let x_public = x25519_dalek::PublicKey::from(&x_private);

        let public = PublicKey::new(ed_public, x_public)?;

        Ok(PrivateKey {
            ed_secret: ed_private,
            x_secret: x_private,
            public,
        })
    }

    /// corresponding public key
    pub fn id(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret_bytes(&self) -> &[u8] {
        self.ed_secret.as_bytes()
    }

    pub fn diffie_hellman(&self, public: &PublicKey) -> [u8; 32] {
        self.x_secret
            .diffie_hellman(&public.x_public)
            .as_bytes()
            .clone()
    }

    /// Sign some data using the underlying private key.
    /// Since the digest used is SHA512, output will be 64 bytes
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature = self
            .ed_secret
            .expand::<Sha512>()
            .sign::<Sha512>(data, &self.public.ed_public);

        Ok(Vec::from(&signature.to_bytes()[..]))
    }
}

impl FromBytes for PrivateKey {
    fn from_bytes(private: &[u8]) -> Result<PrivateKey, CryptoError> {
        let ed_private =
            ed25519_dalek::SecretKey::from_bytes(private).map_err(|e| CryptoError::Key {
                message: "Failed to process secret key bytes".to_string(),
                cause: e,
            })?;

        PrivateKey::new(ed_private)
    }
}

impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.secret_bytes()[..])
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(FromBytesVisitor::<PrivateKey>::new())
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 dalek private key: {}", self.public.id_string())
    }
}

impl std::cmp::PartialEq<PrivateKey> for PrivateKey {
    fn eq(&self, other: &PrivateKey) -> bool {
        self.secret_bytes() == other.secret_bytes()
    }
}

impl<'a> std::cmp::PartialEq<PrivateKey> for &'a PrivateKey {
    fn eq(&self, other: &PrivateKey) -> bool {
        self.secret_bytes() == other.secret_bytes()
    }
}

impl Eq for PrivateKey {}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn test_public_serialise_deserialise() {
        let wrapped_privates = PrivateKey::generate().unwrap();

        // Serialize it to a JSON string.
        let j = serde_json::to_string(&wrapped_privates.public).unwrap();

        let recycled: PublicKey = serde_json::from_str(&j).unwrap();

        assert_eq!(wrapped_privates.public, recycled)
    }

    #[test]
    fn test_private_serialise_deserialise() {
        let wrapped_privates = PrivateKey::generate().unwrap();

        // Serialize it to a JSON string.
        let j = serde_json::to_string(&wrapped_privates).unwrap();

        let recycled: PrivateKey = serde_json::from_str(&j).unwrap();

        assert_eq!(wrapped_privates, recycled)
    }

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

        let recycled_public = PublicKey::from_bytes(&buffer[..]).unwrap();

        assert_eq!(
            original_public.ed_public.to_bytes(),
            recycled_public.ed_public.to_bytes()
        );
        assert_eq!(
            original_public.x_public.as_bytes(),
            recycled_public.x_public.as_bytes()
        );
    }

    #[test]
    fn test_private_key_encoding_decoding() {
        let wrapped_privates = PrivateKey::generate().unwrap();

        let original_public = wrapped_privates.public;

        let buffer = original_public.id_bytes();

        let recycled_public = PublicKey::from_bytes(&buffer[..]).unwrap();

        assert_eq!(
            original_public.ed_public.to_bytes(),
            recycled_public.ed_public.to_bytes()
        );
        assert_eq!(
            original_public.x_public.as_bytes(),
            recycled_public.x_public.as_bytes()
        );
    }

    #[test]
    fn test_dalek_dh() {
        use rand_core::OsRng;
        use x25519_dalek;
        let a_x_privates = x25519_dalek::StaticSecret::new(&mut OsRng);
        let a_my_privates = PrivateKey::from_bytes(&a_x_privates.to_bytes()[..]).unwrap();

        let b_x_privates = x25519_dalek::StaticSecret::new(&mut OsRng);
        let b_my_privates = PrivateKey::from_bytes(&b_x_privates.to_bytes()[..]).unwrap();

        let dh1 = a_my_privates.diffie_hellman(&b_my_privates.public);
        let dh2 = b_my_privates.diffie_hellman(&a_my_privates.public);

        let dh3 = a_x_privates
            .diffie_hellman(&x25519_dalek::PublicKey::from(&b_x_privates))
            .as_bytes()
            .clone();
        let dh4 = b_x_privates
            .diffie_hellman(&x25519_dalek::PublicKey::from(&a_x_privates))
            .as_bytes()
            .clone();

        assert_eq!(dh1, dh2);
        assert_eq!(dh1, dh3);
        assert_eq!(dh1, dh4);
        assert_eq!(dh2, dh3);
        assert_eq!(dh2, dh4);
        assert_eq!(dh3, dh4);
    }
}
