use std::hash::Hasher;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

use serde::{Deserialize, Serialize};

use rand_core::RngCore;

use crate::crypto::{CryptoError, FromBytes, PrivateKey, PublicKey};
use crate::model::{common, Decodable, Encodable};

/// A certificate representation.
///
/// Carries an encoded certificate, signature and some decoded
/// additional information.
#[derive(Serialize, Deserialize, Clone, Debug)]
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

    /// get the certificate's information
    pub fn infos(&self) -> &CertificateInfoBundle {
        &self.infos
    }

    /// get the public key represented by this certificate
    pub fn public_key(&self) -> &PublicKey {
        &self.infos.identity
    }

    /// get the optional signer certificate
    pub fn signer_certificate(&self) -> &Option<Arc<Certificate>> {
        &self.infos.signer_certificate
    }
    /// get the optional signer certificate
    pub fn expires(&self) -> &SystemTime {
        &self.infos.expires()
    }
}

impl std::cmp::PartialEq for Certificate {
    fn eq(&self, other: &Self) -> bool {
        // quick and dirty -> change this to support inter-codec Eq
        (self.cert == other.cert) && (self.signature == other.signature)
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
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CertificateInfoBundle {
    pub(crate) identity: PublicKey,
    pub(crate) expiration: SystemTime,
    pub(crate) serial: String,
    pub(crate) signer_certificate: Option<Arc<Certificate>>,
}

impl CertificateInfoBundle {
    /// construct a new CertificateInfoBundle
    pub fn new(
        identity: PublicKey,
        expiration: SystemTime,
        serial: String,
        signer_certificate: Option<Arc<Certificate>>,
    ) -> CertificateInfoBundle {
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

/// Build-a-certificate.
///
/// Add all ingredients and decide how to sign it!
#[derive(Default)]
pub struct CertificateFactory {
    certified: Option<PublicKey>,
    validity: Duration,
}

impl CertificateFactory {
    /// decode a certificate from DTO
    /// TODO resolve dependency to model::common
    pub fn decode(
        serialised: common::Certificate,
    ) -> Result<(Certificate, Option<common::Certificate>), CryptoError> {
        let tbs_cert = common::certificate::TbsCertificate::decode(serialised.certificate.to_vec())
            .map_err(|e| CryptoError::Unspecified {
                message: "failed to decode certificate".to_string(),
                cause: e.into(),
            })?;

        let signed_identity = PublicKey::from_bytes(&tbs_cert.identity[..])?;

        let expiration = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(tbs_cert.expires))
            .ok_or(CryptoError::Message {
                message: format!("is invalid system time '{}'", tbs_cert.expires),
            })?;

        let cert_info =
            CertificateInfoBundle::new(signed_identity, expiration, tbs_cert.uuid, None);

        let cert = Certificate::new(serialised.certificate, serialised.signature, cert_info);

        Ok((cert, tbs_cert.signer))
    }

    /// Certify the given identity
    pub fn certified(mut self, certified: PublicKey) -> CertificateFactory {
        self.certified = Some(certified);

        self
    }

    /// Define when the new certificate expires
    pub fn expiration(mut self, validity: Duration) -> CertificateFactory {
        self.validity = validity;

        self
    }

    /// Self-sign the certificate information with the given private key.
    /// The resulting certificate will not carry a signer certificate.
    pub fn self_sign(self, signer: &PrivateKey) -> Result<Certificate, CryptoError> {
        self.sign(signer, None)
    }

    /// Sign the certificate information with the given private key and an
    /// optional certificate
    pub fn sign(
        self,
        signer: &PrivateKey,
        signer_cert: Option<&Arc<Certificate>>,
    ) -> Result<Certificate, CryptoError> {
        use rand_core::OsRng;

        let certified = self.certified.ok_or(CryptoError::Message {
            message: "cannot create a certificate without a given identity".to_string(),
        })?;

        // calculate expiration timestamp
        let expiration =
            SystemTime::now()
                .checked_add(self.validity)
                .ok_or(CryptoError::Message {
                    message: "error handling validity".to_string(),
                })?;

        let mut bytes = [0; 16];
        OsRng::default().fill_bytes(&mut bytes);

        let serial = Uuid::new_v4().to_string();

        let infos = CertificateInfoBundle {
            identity: certified,
            expiration,
            serial,
            signer_certificate: signer_cert.map(Arc::clone),
        };

        let tbs = infos.encode().map_err(|e| CryptoError::Unspecified {
            message: "failed to serialise tbs certificate".to_string(),
            cause: e.into(),
        })?;

        let signature = signer.sign(&tbs[..])?;

        Ok(Certificate {
            cert: tbs,
            signature,
            infos,
        })
    }
}

#[cfg(test)]
pub mod certificate_tests {
    use super::*;
    use crate::crypto::PrivateKey;

    /// convenience method to create any signed certificate
    pub fn create_signed_cert() -> Certificate {
        let signer_key = PrivateKey::generate().unwrap();

        let signer_cert = CertificateFactory::default()
            .certified(signer_key.public_key().clone())
            .expiration(Duration::from_secs(1000))
            .self_sign(&signer_key)
            .map(Arc::new)
            .unwrap();

        let leaf_key = PrivateKey::generate().unwrap();

        let leaf_cert = CertificateFactory::default()
            .certified(leaf_key.public_key().clone())
            .expiration(Duration::from_secs(1000))
            .sign(&signer_key, Some(&signer_cert))
            .unwrap();

        return leaf_cert;
    }

    /// convenience method to create two certificate with the same signer
    pub fn create_two_signed_certs() -> (Certificate, Certificate) {
        let signer_key = PrivateKey::generate().unwrap();

        let signer_cert = CertificateFactory::default()
            .certified(signer_key.public_key().clone())
            .expiration(Duration::from_secs(1000))
            .self_sign(&signer_key)
            .map(Arc::new)
            .unwrap();

        let leaf_key_1 = PrivateKey::generate().unwrap();

        let leaf_cert_1 = CertificateFactory::default()
            .certified(leaf_key_1.public_key().clone())
            .expiration(Duration::from_secs(1000))
            .sign(&signer_key, Some(&signer_cert))
            .unwrap();

        let leaf_key_2 = PrivateKey::generate().unwrap();

        let leaf_cert_2 = CertificateFactory::default()
            .certified(leaf_key_2.public_key().clone())
            .expiration(Duration::from_secs(1000))
            .sign(&signer_key, Some(&signer_cert))
            .unwrap();

        return (leaf_cert_1, leaf_cert_2);
    }

    /// convenience method to create any self signed certificate
    pub fn create_self_signed_cert() -> (PrivateKey, Certificate) {
        let private = PrivateKey::generate().unwrap();

        let cert = CertificateFactory::default()
            .certified(private.public_key().clone())
            .expiration(Duration::from_secs(1000))
            .self_sign(&private)
            .unwrap();

        return (private, cert);
    }

    #[test]
    fn test_create_self_signed() {
        let (private, cert) = create_self_signed_cert();

        private
            .public_key()
            .verify(cert.encoded_certificate(), cert.signature())
            .unwrap();
    }

    #[test]
    fn test_create_signed() {
        let signed = create_signed_cert();

        let sig_cert = signed.infos.signer_certificate.unwrap();

        sig_cert
            .public_key()
            .verify(sig_cert.encoded_certificate(), sig_cert.signature())
            .unwrap();
    }

    #[test]
    fn test_self_signed_serialise_deserialise() {
        let (_private, cert) = create_self_signed_cert();

        // Serialize it to a JSON string.
        let j = serde_json::to_string(&cert).unwrap();

        let recycled: Certificate = serde_json::from_str(&j).unwrap();

        assert_eq!(cert, recycled)
    }

    #[test]
    fn test_signed_serialise_deserialise() {
        let cert = create_signed_cert();

        // Serialize it to a JSON string.
        let j = serde_json::to_string(&cert).unwrap();

        let recycled: Certificate = serde_json::from_str(&j).unwrap();

        assert_eq!(cert, recycled)
    }

    #[test]
    #[ignore = "only invoke to manually create server key / certificate pair"]
    fn create_key_certificate_files() {
        use std::fs::File;
        use std::io::Write;

        let (private, cert) = create_self_signed_cert();

        // Serialize it to a JSON string.
        let private_json = serde_json::to_vec(&private).unwrap();
        let cert_json = serde_json::to_vec(&cert).unwrap();

        let mut output = File::create("privates.json").unwrap();
        output.write_all(&private_json[..]).unwrap();

        let mut output = File::create("certificate.json").unwrap();
        output.write_all(&cert_json[..]).unwrap();
    }
}
