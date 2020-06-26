use crate::prelude::*;

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::ops::{Add, Deref};

use uuid::Uuid;

use super::*;
use std::hash::Hasher;
use std::sync::Arc;


/// A certificate representation.
///
/// Carries an encoded certificate, signature and some decoded
/// additional information.
#[derive(Debug)]
pub struct Certificate {
    pub(crate) cert: Vec<u8>,
    pub(crate) signature: Vec<u8>,
    pub(crate) infos: CertificateInfoBundle,
}

impl Certificate {
    /// get the encoded certificate
    pub fn encoded_certificate(&self) -> &[u8] {
        self.cert.as_slice()
    }

    /// get the certificate's signature
    pub fn signature(&self) -> &[u8] {
        self.signature.as_slice()
    }

    /// get the public key represented by this certificate
    pub fn public_key(&self) -> &PublicKey {
        &self.infos.identity
    }

    /// get the optional signer certificate
    pub fn signer_certificate(&self) -> &Option<Arc<Certificate>> {
        &self.infos.signer_certificate
    }
}

impl std::cmp::PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        // quick and dirty -> change this to support inter-codec Eq
        (self.cert == other.cert) &&
            (self.signature == other.signature)
    }
}

impl Eq for Certificate {}

impl std::hash::Hash for Certificate {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.cert.hash(state);
        self.signature.hash(state);
    }
}

/// An inner certificate.
///
/// Contains parsed information about a certificate.
#[derive(Debug)]
pub struct CertificateInfoBundle {
    pub(crate) identity: PublicKey,
    pub(crate) expiration: SystemTime,
    pub(crate) serial: String,
    pub(crate) signer_certificate: Option<Arc<Certificate>>,
}

impl CertificateInfoBundle {
    pub fn public_key(&self) -> &PublicKey {
        &self.identity
    }

    pub fn expires(&self) -> &SystemTime {
        &self.expiration
    }

    pub fn serial(&self) -> &str {
        &self.serial
    }

    pub fn signer_certificate(&self) -> &Option<Arc<Certificate>> {
        &self.signer_certificate
    }
}

/// Certificate encoding trait
pub trait CertificateEncoding {
    type CertificateType;

    /// encode the raw certicate data that is to be signed
    fn serialise_tbs(infos: &CertificateInfoBundle) -> Result<Vec<u8>, CryptoError>;

    /// encode certificate
    fn serialise(data: &Certificate) -> Result<Vec<u8>, CryptoError>;

    fn decode_partial(serialised: Self::CertificateType) -> Result<(Certificate, Option<Self::CertificateType>), CryptoError>;

    /// partially parse a certificate
    /// returns the certificate itself and an optional (unparsed) signer
    fn deserialise(bytes: Vec<u8>) -> Result<Self::CertificateType, CryptoError>;
}

/// Build-a-certificate.
///
/// Add all ingredients and decide how to sign it!
#[derive(Default)]
pub struct CertificateFactory {
    certified: Option<PublicKey>,
    validity: Duration,
}

impl CertificateFactory {
    /// Certify the given identity
    pub fn certified(mut self, certified: PublicKey)
                     -> CertificateFactory {
        self.certified = Some(certified);

        self
    }

    /// Define when the new certificate expires
    pub fn expiration(mut self, validity: Duration)
                      -> CertificateFactory {
        self.validity = validity;

        self
    }
    /// Self-sign the certificate information with the given private key.
    /// The resulting certificate will not carry a signer certificate.
    pub fn self_sign<E>(self,
                        signer: &PrivateKey)
                        -> Result<Certificate, CryptoError>
        where E: CertificateEncoding {
        self.sign::<E>(signer, None)
    }

    /// Sign the certificate information with the given private key and an
    /// optional certificate
    pub fn sign<E>(self,
                   signer: &PrivateKey,
                   signer_cert: Option<&Arc<Certificate>>)
                   -> Result<Certificate, CryptoError>
        where E: CertificateEncoding {
        let certified = self.certified.ok_or(
            CryptoError::Message {
                message: "cannot create a certificate without a given identity".to_string()
            })?;

        // calculate expiration timestamp
        let expiration = SystemTime::now()
            .checked_add(self.validity)
            .ok_or(CryptoError::Message {
                message: "error handling validity".to_string()
            })?;

        let serial = Uuid::new_v4().to_string();

        let infos = CertificateInfoBundle {
            identity: certified,
            expiration,
            serial,
            signer_certificate: signer_cert.map(Arc::clone),
        };

        let tbs = E::serialise_tbs(&infos)?;

        let signature = signer.sign(&tbs[..])?;

        Ok(Certificate { cert: tbs, signature, infos })
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::*;
    use crate::crypto::PrivateKey;
    use crate::accounts::GrpcCertificateEncoding;

    #[test]
    fn test_create_self_signed() {
        let private = PrivateKey::generate().unwrap();

        let cert = CertificateFactory::default()
            .certified(private.id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&private).unwrap();

        private.id().verify(cert.encoded_certificate(), cert.signature()).unwrap();
    }

    #[test]
    fn test_create_signed() {
        let signer_private = PrivateKey::generate().unwrap();

        let signer_cert = CertificateFactory::default()
            .certified(signer_private.id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&signer_private).unwrap();

        signer_private.id().verify(signer_cert.encoded_certificate(), signer_cert.signature()).unwrap();

        // Sign a foreign certificate
        let signed_private = PrivateKey::generate().unwrap();

        let signed = CertificateFactory::default()
            .certified(signed_private.id().copy())
            .expiration(Duration::from_secs(1000))
            .sign::<GrpcCertificateEncoding>(&signer_private, Some(&Arc::new(signer_cert))).unwrap();

        signer_private.id().verify(signed.encoded_certificate(), signed.signature()).unwrap();
    }
}
