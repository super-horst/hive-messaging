use std::fmt;

use failure::{Error, Fail};
use std::borrow::Borrow;
use std::time::SystemTime;

#[derive(Debug, Fail)]
pub enum CryptoError {
    #[fail(display = "Error message: {}", message)]
    Message {
        message: String,
    },
    #[fail(display = "Unspecified error: {}", message)]
    GenericError {
        message: String,
        #[fail(cause)] cause: Error,
    },
    #[fail(display = "Encoding failed: {}", message)]
    Encoding {
        message: String,
        #[fail(cause)] cause: prost::EncodeError,
    },
    #[fail(display = "Failed to process key: {}", message)]
    Key {
        message: String,
        #[fail(cause)] cause: ed25519_dalek::errors::SignatureError,
    },
    #[fail(display = "Failed to process signature: {}", message)]
    Signature {
        message: String,
        #[fail(cause)] cause: ed25519_dalek::errors::SignatureError,
    },
}

/// A certificate representation.
///
/// Carries an encoded certificate, signature and some decoded
/// additional information.
///
#[derive(Debug)]
pub struct Certificate<'a> {
    pub(crate) cert: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) infos: CertificateInfoBundle<'a>,
}

impl<'a> Certificate<'a> {
    /// get the encoded certificate
    pub fn encoded_certificate(&self) -> &[u8] {
        self.cert.as_slice()
    }

    /// get the certificate's signature
    pub fn signature(&self) -> &[u8] {
        self.signature.as_slice()
    }

    /// get the public key represented by this certificate
    pub fn public_key(&self) -> &dyn PublicIdentity {
        self.infos.identity.borrow()
    }

    /// get the optional signer certificate
    pub fn signer_certificate(&self) -> &Option<&'_ Certificate<'_>> {
        &self.infos.signer_certificate
    }
}

/// An inner certificate.
///
/// Contains parsed information about a certificate.
#[derive(Debug)]
pub struct CertificateInfoBundle<'a> {
    pub(crate) identity: Box<dyn PublicIdentity>,
    pub(crate) expiration: SystemTime,
    pub(crate) serial: String,
    pub(crate) signer_certificate: Option<&'a Certificate<'a>>,
}

impl<'a> CertificateInfoBundle<'a> {
    pub fn public_key(&self) -> &dyn PublicIdentity {
        self.identity.borrow()
    }

    pub fn expires(&self) -> &SystemTime {
        &self.expiration
    }

    pub fn serial(&self) -> &str {
        &self.serial
    }

    pub fn signer_certificate(&self) -> &Option<&'_ Certificate<'_>> {
        &self.signer_certificate
    }
}

/// Identity provider
#[async_trait::async_trait]
pub trait Identities: Send + Sync {
    /// resolve identity from the given bytes
    /// async covers I/O use cases
    async fn resolve_id(&self, id: &[u8]) -> Result<Box<dyn PublicIdentity>, CryptoError>;

    /// the current main identity
    fn my_id(&self) -> &dyn PrivateIdentity;

    /// the current main identity
    fn my_certificate(&self) -> &Certificate;
}

/// A cryptographic identity
pub trait Identity: fmt::Debug + Send + Sync {
    /// Hexstring of this cryptographic identity
    fn id(&self) -> String;

    /// this identity's namespace
    fn namespace(&self) -> String;
}

pub trait PublicIdentity: Identity {
    ///Verify a raw byte signature
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), CryptoError>;

    /// encode public identities as bytes
    fn as_bytes(&self) -> Vec<u8>;

    /// make a copy of myself
    fn copy(&self) -> Box<dyn PublicIdentity>;
}

pub trait PrivateIdentity: fmt::Debug + Send + Sync {
    /// Sign some data using the underlying private key.
    /// Since the digest used is SHA512, output will be 64 bytes
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// corresponding public key
    fn public_id(&self) -> &dyn PublicIdentity;
}