use std::hash::Hasher;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::crypto::*;
use crate::model::*;
use rand_core::RngCore;

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
    /// get the optional signer certificate
    pub fn expires(&self) -> &SystemTime {
        &self.infos.expires()
    }
}

impl Encodable for Certificate {
    fn encode(&self) -> Result<Vec<u8>, SerialisationError> {
        common::Certificate {
            certificate: self.encoded_certificate().to_vec(),
            signature: self.signature().to_vec(),
        }
        .encode()
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
#[derive(Debug)]
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

impl Encodable for CertificateInfoBundle {
    fn encode(&self) -> Result<Vec<u8>, SerialisationError> {
        let expires = self
            .expiration
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| SerialisationError::Message {
                message: e.to_string(),
            })?;

        let mut tbs_cert = common::certificate::TbsCertificate {
            identity: self.identity.id_bytes(),
            namespace: self.identity.namespace(),
            expires,
            uuid: self.serial.clone(),
            signer: None,
        };

        match &self.signer_certificate {
            Some(c) => {
                let gc = common::Certificate {
                    certificate: c.encoded_certificate().to_vec(),
                    signature: c.signature().to_vec(),
                };
                tbs_cert.signer = Some(gc);
            }
            None => (),
        }

        tbs_cert.encode()
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
            .certified(signer_key.id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign(&signer_key)
            .map(Arc::new)
            .unwrap();

        let leaf_key = PrivateKey::generate().unwrap();

        let leaf_cert = CertificateFactory::default()
            .certified(leaf_key.id().copy())
            .expiration(Duration::from_secs(1000))
            .sign(&signer_key, Some(&signer_cert))
            .unwrap();

        return leaf_cert;
    }

    /// convenience method to create two certificate with the same signer
    pub fn create_two_signed_certs() -> (Certificate, Certificate) {
        let signer_key = PrivateKey::generate().unwrap();

        let signer_cert = CertificateFactory::default()
            .certified(signer_key.id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign(&signer_key)
            .map(Arc::new)
            .unwrap();

        let leaf_key_1 = PrivateKey::generate().unwrap();

        let leaf_cert_1 = CertificateFactory::default()
            .certified(leaf_key_1.id().copy())
            .expiration(Duration::from_secs(1000))
            .sign(&signer_key, Some(&signer_cert))
            .unwrap();

        let leaf_key_2 = PrivateKey::generate().unwrap();

        let leaf_cert_2 = CertificateFactory::default()
            .certified(leaf_key_2.id().copy())
            .expiration(Duration::from_secs(1000))
            .sign(&signer_key, Some(&signer_cert))
            .unwrap();

        return (leaf_cert_1, leaf_cert_2);
    }

    /// convenience method to create any self signed certificate
    pub fn create_self_signed_cert() -> Certificate {
        let private = PrivateKey::generate().unwrap();

        let cert = CertificateFactory::default()
            .certified(private.id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign(&private)
            .unwrap();

        return cert;
    }

    #[test]
    fn test_create_self_signed() {
        let cert = create_self_signed_cert();

        cert.public_key()
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
}
