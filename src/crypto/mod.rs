use ed25519_dalek::*;
use hkdf::*;
use sha2::Sha256;
use sha2::Sha512;

use rand_core::{CryptoRng, RngCore};
use rand::rngs::OsRng;

use std::fmt;
use hex;
use std::sync::Arc;
use std::error::Error;
use std::io::Write;
use std::cmp::min;
use std::borrow::Borrow;

/// Identity provider
#[async_trait::async_trait]
pub trait Identities: Send + Sync {
    /// resolve identity from the given bytes
    /// async covers I/O use cases
    async fn resolve_id(&self, id: &[u8]) -> Result<Box<dyn PublicIdentity>, Box<dyn std::error::Error>>;

    fn my_id(&self) -> &dyn PrivateIdentity;
}

/// Simple Identities object
#[derive(Debug)]
pub struct SimpleIdentities {
    my_id: Arc<dyn PrivateIdentity>,
}

#[async_trait::async_trait]
impl Identities for SimpleIdentities {
    async fn resolve_id(&self, id: &[u8]) -> Result<Box<dyn PublicIdentity>, Box<dyn Error>> {
        //TODO error handling
        let public = ed25519_dalek::PublicKey::from_bytes(id).unwrap();

        Ok(Box::new(DalekPublicId { inner: public }))
    }

    fn my_id(&self) -> &dyn PrivateIdentity {
        self.my_id.borrow()
    }
}

impl SimpleIdentities {
    pub fn new(private: Arc<dyn PrivateIdentity>) -> SimpleIdentities {
        return SimpleIdentities { my_id: private };
    }
}

/// A cryptographic identity
pub trait Identity: fmt::Debug + Send + Sync {
    /// Hexstring of this cryptographic identity
    fn id(&self) -> String;
}

pub trait PublicIdentity: Identity {
    ///Verify a raw byte signature
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), String>;

    fn as_bytes(&self) -> Vec<u8>;
}

pub trait PrivateIdentity: PublicIdentity {
    /// Sign some data using the underlying private key.
    /// Since the digest used is SHA512, output will be 64 bytes
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}

pub struct DalekEd25519PrivateId {
    secret: ed25519_dalek::SecretKey,
    public: DalekPublicId,
}

impl PrivateIdentity for DalekEd25519PrivateId {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        //TODO error handling?
        let signature = self.secret.expand::<Sha512>().sign::<Sha512>(data, &self.public.inner);

        Vec::from(&signature.to_bytes()[..])
    }
}

impl PublicIdentity for DalekEd25519PrivateId {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), String> {
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
}

impl DalekEd25519PrivateId {
    pub fn generate() -> DalekEd25519PrivateId {
        // TODO handle error
        let private = ed25519_dalek::SecretKey::generate(&mut OsRng::new().unwrap());

        let public = DalekPublicId { inner: ed25519_dalek::PublicKey::from_secret::<Sha512>(&private) };

        DalekEd25519PrivateId { secret: private, public }
    }

    pub fn new(private: ed25519_dalek::SecretKey) -> DalekEd25519PrivateId {
        let public = DalekPublicId { inner: ed25519_dalek::PublicKey::from_secret::<Sha512>(&private) };

        DalekEd25519PrivateId { secret: private, public }
    }
}

impl fmt::Debug for DalekEd25519PrivateId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 dalek private key: {}", self.id())
    }
}

pub struct DalekPublicId {
    inner: ed25519_dalek::PublicKey,
}

impl PublicIdentity for DalekPublicId {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), String> {
        //TODO error handling
        let signature = ed25519_dalek::Signature::from_bytes(signature).unwrap();

        self.inner.verify::<Sha512>(&data[..], &signature).unwrap();

        Ok(())
    }

    fn as_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }
}

impl Identity for DalekPublicId {
    fn id(&self) -> String {
        hex::encode(self.inner.as_bytes())
    }
}

impl fmt::Debug for DalekPublicId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Ed25519 dalek public key: {}", self.id())
    }
}

//TODO initial implementation is not ready for production!

// max dh buffer size needed
const DH_BUFFER_SIZE: usize = 128;
/*
pub struct DhKeyPair<'a> {
    mine: &'a StaticSecret,
    other: &'a x25519_dalek::PublicKey,
}

impl<'a> DhKeyPair<'a> {
    pub fn mine_dh(&self, public_key: &x25519_dalek::PublicKey) -> SharedSecret {
        self.mine.diffie_hellman(public_key)
    }

    pub fn other_dh(&self, private_key: &StaticSecret) -> SharedSecret {
        private_key.diffie_hellman(&self.other)
    }
}*/

/*
pub fn x3dh_agree_initial(identities: &DhKeyPair,
                          pre_key: &x25519_dalek::PublicKey,
                          onetime_pre_key: Option<x25519_dalek::PublicKey>) -> (x25519_dalek::PublicKey, [u8; 32]) {
// static secret but ephemeral
    let eph = StaticSecret::new(&mut OsRng::new().unwrap());

    let dh1 = identities.mine_dh(&pre_key);
    let dh2 = identities.other_dh(&eph);
    let dh3 = eph.diffie_hellman(&pre_key);

    let mut dh = Vec::with_capacity(DH_BUFFER_SIZE);
    dh.extend_from_slice(dh1.as_bytes());
    dh.extend_from_slice(dh2.as_bytes());
    dh.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = onetime_pre_key {
        let dh4 = eph.diffie_hellman(&opk);

        dh.extend_from_slice(dh4.as_bytes());
    }

// shrink buffer if necessary
    dh.shrink_to_fit();

    let h = Hkdf::<Sha256>::new(None, &dh);
    let mut okm = [0u8; 32];
    h.expand(&[0u8; 0], &mut okm).unwrap();

    return (x25519_dalek::PublicKey::from(&eph), okm);
}

pub fn x3dh_agree_respond(identities: &DhKeyPair,
                          ephemeral_key: &x25519_dalek::PublicKey,
                          pre_key: &StaticSecret,
                          onetime_pre_key: Option<StaticSecret>) -> [u8; 32] {
    let dh1 = identities.other_dh(&pre_key);
    let dh2 = identities.mine_dh(&ephemeral_key);
    let dh3 = pre_key.diffie_hellman(&ephemeral_key);

    let mut dh = Vec::with_capacity(DH_BUFFER_SIZE);
    dh.extend_from_slice(dh1.as_bytes());
    dh.extend_from_slice(dh2.as_bytes());
    dh.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = onetime_pre_key {
        let dh4 = opk.diffie_hellman(&ephemeral_key);

        dh.extend_from_slice(dh4.as_bytes());
    }

// shrink buffer if necessary
    dh.shrink_to_fit();

    let h = Hkdf::<Sha256>::new(None, &dh);
    let mut okm = [0u8; 32];
    h.expand(&[0u8; 0], &mut okm).unwrap();

    return okm;
}*/

#[cfg(test)]
mod crypto_tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use rand_core::RngCore;

    #[test]
    fn test_dalek_sign_verify() {
        let data: &[u8] = b"testdata is overrated";

        let wrapped_privates = DalekEd25519PrivateId::generate();

        let signed = wrapped_privates.sign(data);

        wrapped_privates.verify(data, &signed).unwrap();
    }

    /*
        #[test]
        fn test_dh_without_onetimekey() {
            let a_priv = StaticSecret::new(&mut  OsRng::new().unwrap());
            let a_pub = x25519_dalek::PublicKey::from(&a_priv);

            let b_priv = StaticSecret::new(&mut  OsRng::new().unwrap());
            let b_pub = x25519_dalek::PublicKey::from(&b_priv);

            let pre_key_priv = StaticSecret::new(&mut  OsRng::new().unwrap());
            let pre_key_pub = x25519_dalek::PublicKey::from(&pre_key_priv);

            let from_a = DhKeyPair { mine: &a_priv, other: &b_pub };
            let from_b = DhKeyPair { mine: &b_priv, other: &a_pub };

            let (eph_pub, dh1) = x3dh_agree_initial(&from_a, &pre_key_pub, None);
            let dh2 = x3dh_agree_respond(&from_b, &eph_pub, &pre_key_priv, None);

            assert_eq!(dh1, dh2);
        }

        #[test]
        fn test_dh_with_onetimekey() {
            let a_priv = StaticSecret::new(&mut  OsRng::new().unwrap());
            let a_pub = x25519_dalek::PublicKey::from(&a_priv);

            let b_priv = StaticSecret::new(&mut  OsRng::new().unwrap());
            let b_pub = x25519_dalek::PublicKey::from(&b_priv);

            let pre_key_priv = StaticSecret::new(&mut  OsRng::new().unwrap());
            let pre_key_pub = x25519_dalek::PublicKey::from(&pre_key_priv);

            let otk_priv = StaticSecret::new(&mut  OsRng::new().unwrap());
            let otk_pub = x25519_dalek::PublicKey::from(&otk_priv);

            let from_a = DhKeyPair { mine: &a_priv, other: &b_pub };
            let from_b = DhKeyPair { mine: &b_priv, other: &a_pub };

            let (eph_pub, dh1) = x3dh_agree_initial(&from_a, &pre_key_pub, Some(otk_pub));
            let dh2 = x3dh_agree_respond(&from_b, &eph_pub, &pre_key_priv, Some(otk_priv));

            assert_eq!(dh1, dh2);
        }*/
}