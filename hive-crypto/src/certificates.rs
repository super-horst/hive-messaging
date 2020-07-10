use std::hash::Hasher;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use uuid::Uuid;

use crate::*;

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
    pub fn new(cert: Vec<u8>, signature: Vec<u8>, infos: CertificateInfoBundle) -> Certificate {
        Certificate {
            cert,
            signature,
            infos,
        }
    }

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
    /// construct a new CertificateInfoBundle
    pub fn new(identity: PublicKey, expiration: SystemTime, serial: String, signer_certificate: Option<Arc<Certificate>>) -> CertificateInfoBundle {
        CertificateInfoBundle {
            identity,
            expiration,
            serial,
            signer_certificate,
        }
    }

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
    fn serialise_tbs(infos: &CertificateInfoBundle) -> Result<Vec<u8>, failure::Error>;

    /// encode certificate
    fn serialise(data: &Certificate) -> Result<Vec<u8>, failure::Error>;

    /// partially decode a certificate
    /// returns the certificate itself and an optional (encoded) signer
    fn decode_partial(serialised: Self::CertificateType) -> Result<(Certificate, Option<Self::CertificateType>), failure::Error>;

    /// partially parse a certificate
    /// returns the certificate itself and an optional (unparsed) signer
    fn deserialise(bytes: Vec<u8>) -> Result<Self::CertificateType, failure::Error>;
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

        let tbs = E::serialise_tbs(&infos)
            .map_err(|e| CryptoError::Unspecified {
                message: "failed to serialise tbs certificate".to_string(),
                cause: e,
            })?;

        let signature = signer.sign(&tbs[..])?;

        Ok(Certificate { cert: tbs, signature, infos })
    }
}

#[cfg(test)]
pub mod certificate_tests {
    use super::*;
    use crate::PrivateKey;
    use crate::test_utils::GrpcCertificateEncoding;

    /// convenience method to create any signed certificate
    pub fn create_signed_cert() -> Certificate {
        let signer_key = PrivateKey::generate().unwrap();

        let signer_cert = CertificateFactory::default()
            .certified(signer_key.id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&signer_key).map(Arc::new).unwrap();

        let leaf_key = PrivateKey::generate().unwrap();

        let leaf_cert = CertificateFactory::default()
            .certified(leaf_key.id().copy())
            .expiration(Duration::from_secs(1000))
            .sign::<GrpcCertificateEncoding>(&signer_key, Some(&signer_cert)).unwrap();

        return leaf_cert;
    }

    /// convenience method to create two certificate with the same signer
    pub fn create_two_signed_certs() -> (Certificate, Certificate) {
        let signer_key = PrivateKey::generate().unwrap();

        let signer_cert = CertificateFactory::default()
            .certified(signer_key.id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&signer_key).map(Arc::new).unwrap();

        let leaf_key_1 = PrivateKey::generate().unwrap();

        let leaf_cert_1 = CertificateFactory::default()
            .certified(leaf_key_1.id().copy())
            .expiration(Duration::from_secs(1000))
            .sign::<GrpcCertificateEncoding>(&signer_key, Some(&signer_cert)).unwrap();

        let leaf_key_2 = PrivateKey::generate().unwrap();

        let leaf_cert_2 = CertificateFactory::default()
            .certified(leaf_key_2.id().copy())
            .expiration(Duration::from_secs(1000))
            .sign::<GrpcCertificateEncoding>(&signer_key, Some(&signer_cert)).unwrap();

        return (leaf_cert_1, leaf_cert_2);
    }

    /// convenience method to create any self signed certificate
    pub fn create_self_signed_cert() -> Certificate {
        let private = PrivateKey::generate().unwrap();

        let cert = CertificateFactory::default()
            .certified(private.id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&private).unwrap();

        return cert;
    }

    #[test]
    fn test_create_self_signed() {
        let cert = create_self_signed_cert();

        cert.public_key().verify(cert.encoded_certificate(), cert.signature()).unwrap();
    }

    #[test]
    fn test_create_signed() {
        let signed = create_signed_cert();

        let sig_cert = signed.infos.signer_certificate.unwrap();

        sig_cert.public_key().verify(sig_cert.encoded_certificate(), sig_cert.signature()).unwrap();
    }
}
