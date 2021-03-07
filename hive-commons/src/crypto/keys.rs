use std::fmt;
use std::hash::Hasher;
use std::marker::PhantomData;

use sha2::{Digest, Sha512};

use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::crypto::error::*;
use crate::crypto::{FromBytes, KeyAgreement, Signer, Verifier};

const KEY_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

/// Dalek public key
#[derive(Copy, Clone)]
pub struct PublicKey {
    x_public: MontgomeryPoint,
    ed_public: EdwardsPoint,
}

impl PublicKey {
    fn new(ed_public: EdwardsPoint) -> Result<PublicKey, CryptoError> {
        Ok(PublicKey {
            x_public: ed_public.to_montgomery(),
            ed_public,
        })
    }

    /// encode public identity as string
    pub fn id_string(&self) -> String {
        hex::encode(self.id_bytes())
    }

    /// encode public identity as bytes
    pub fn id_bytes(&self) -> Vec<u8> {
        self.ed_public.compress().as_bytes().to_vec()
    }

    /// this identity's namespace
    pub fn namespace(&self) -> String {
        //TODO
        "my::namespace".to_string()
    }
}

impl Verifier for PublicKey {
    ///Verify a raw byte signature
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        if signature.len() != SIGNATURE_LENGTH {
            return Err(CryptoError::Message {
                message: "Invalid signature format".to_string(),
            });
        }

        // decode signature
        let mut lower: [u8; 32] = [0u8; 32];
        let mut upper: [u8; 32] = [0u8; 32];

        lower.copy_from_slice(&signature[..32]);
        upper.copy_from_slice(&signature[32..]);

        if upper[31] & 0b1110_0000_u8 != 0 {
            return Err(CryptoError::Message {
                message: "Invalid scalar format".to_string(),
            });
        }

        let signature_r = CompressedEdwardsY(lower);
        let signature_s = Scalar::from_bits(upper);

        let mut hash = Sha512::new();
        hash.update(signature_r.as_bytes());
        hash.update(self.ed_public.compress().as_bytes());
        hash.update(&data);
        let h = Scalar::from_hash(hash);

        let r =
            EdwardsPoint::vartime_double_scalar_mul_basepoint(&h, &(-self.ed_public), &signature_s);

        if r.compress() != signature_r {
            return Err(CryptoError::Message {
                message: "Failed to verify signature".to_string(),
            });
        }

        Ok(())
    }
}

impl FromBytes for PublicKey {
    /// parse an identity from raw bytes
    fn from_bytes(bytes: &[u8]) -> Result<PublicKey, CryptoError> {
        if bytes.len() != KEY_LENGTH {
            return Err(CryptoError::Message {
                message: "Invalid public key length".to_string(),
            });
        }

        let ed_public = CompressedEdwardsY::from_slice(bytes)
            .decompress()
            .ok_or_else(|| CryptoError::Message {
                message: "Invalid public key format".to_string(),
            })?;

        PublicKey::new(ed_public)
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
        write!(f, "Curve25519 public key: {}", self.id_string())
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
#[derive(Copy, Clone)]
pub struct PrivateKey {
    ed_private: Scalar,
    public: PublicKey,
}

impl PrivateKey {
    pub fn generate() -> Result<PrivateKey, CryptoError> {
        use rand_core::{OsRng, RngCore};

        let mut bytes = [0u8; 32];
        OsRng::default().fill_bytes(&mut bytes);

        bytes[0] &= 0b1111_1000_u8;
        bytes[31] &= 0b0111_1111_u8;
        bytes[31] |= 0b0100_0000_u8;

        PrivateKey::new(bytes)
    }

    fn new(secret_bytes: [u8; 32]) -> Result<PrivateKey, CryptoError> {
        let a = Scalar::from_bits(secret_bytes);
        let public = PublicKey::new(&a * &ED25519_BASEPOINT_TABLE)?;

        Ok(PrivateKey {
            ed_private: a,
            public,
        })
    }

    /// corresponding public key
    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub(crate) fn secret_bytes(&self) -> &[u8; 32] {
        self.ed_private.as_bytes()
    }
}

impl Signer for PrivateKey {
    /// Sign some data using the underlying private key.
    /// Signature output will be 64 bytes
    /// XEdDSA derived from https://signal.org/docs/specifications/xeddsa
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use rand_core::{OsRng, RngCore};

        let mut random_bytes = [0u8; 64];
        OsRng::default().fill_bytes(&mut random_bytes);

        let mut hash1 = Sha512::new();
        hash1.update(&self.ed_private.to_bytes());
        hash1.update(&data);
        hash1.update(&random_bytes[..]);

        let r = Scalar::from_hash(hash1);
        let signature_r = (&r * &ED25519_BASEPOINT_TABLE).compress();

        let ed_public_point = self.public.ed_public.compress().to_bytes();

        let mut hash = Sha512::new();
        hash.update(signature_r.as_bytes());
        hash.update(&ed_public_point);
        hash.update(&data);

        let h = Scalar::from_hash(hash);
        let signature_s = (h * self.ed_private) + r;

        let mut result = [0u8; SIGNATURE_LENGTH];
        result[..32].copy_from_slice(signature_r.as_bytes());
        result[32..].copy_from_slice(signature_s.as_bytes());

        Ok(Vec::from(&result[..]))
    }
}

impl KeyAgreement for PrivateKey {
    fn agree(&self, their_public: &PublicKey) -> [u8; 32] {
        (self.ed_private * their_public.x_public).to_bytes()
    }
}

impl FromBytes for PrivateKey {
    fn from_bytes(private: &[u8]) -> Result<PrivateKey, CryptoError> {
        let mut bytes = [0u8; KEY_LENGTH];
        bytes.copy_from_slice(private);

        PrivateKey::new(bytes)
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
        write!(f, "Curve25519 private key: {}", self.public.id_string())
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

impl std::hash::Hash for PrivateKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ed_private.hash(state);
    }
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
    fn test_signature_verify() {
        let data: &[u8] = b"testdata is overrated";

        let wrapped_privates = PrivateKey::generate().unwrap();

        let signed = wrapped_privates.sign(data).unwrap();

        let verify_res = wrapped_privates.public_key().verify(data, &signed);
        assert!(verify_res.is_ok());
    }

    #[test]
    fn test_signature_modified_signature() {
        let data: &[u8] = b"testdata is overrated";

        let wrapped_privates = PrivateKey::generate().unwrap();

        let mut signed = wrapped_privates.sign(data).unwrap();
        signed[5] &= 0;

        let verify_res = wrapped_privates.public_key().verify(data, &signed);
        assert!(verify_res.is_err());
    }

    #[test]
    fn test_signature_modified_data() {
        let data: &[u8] = b"testdata is overrated";

        let wrapped_privates = PrivateKey::generate().unwrap();

        let signed = wrapped_privates.sign(data).unwrap();

        let data = b"testdata is an illusion";
        let verify_res = wrapped_privates.public_key().verify(data, &signed);
        assert!(verify_res.is_err());
    }

    #[test]
    fn test_public_key_encoding_decoding() {
        let wrapped_privates = PrivateKey::generate().unwrap();

        let original_public = wrapped_privates.public;

        let buffer = original_public.id_bytes();

        let recycled_public = PublicKey::from_bytes(&buffer[..]).unwrap();

        assert_eq!(original_public.id_bytes(), recycled_public.id_bytes());
    }

    #[test]
    fn test_private_key_encoding_decoding() {
        let original_privates = PrivateKey::generate().unwrap();

        let recycled_privates =
            PrivateKey::from_bytes(&original_privates.secret_bytes()[..]).unwrap();

        assert_eq!(
            original_privates.secret_bytes(),
            recycled_privates.secret_bytes()
        );
    }

    #[test]
    fn test_dh() {
        let a_privates = PrivateKey::generate().unwrap();
        let b_privates = PrivateKey::generate().unwrap();

        let dh1 = a_privates.agree(&b_privates.public);
        let dh2 = b_privates.agree(&a_privates.public);

        assert_eq!(dh1, dh2);
    }
}
