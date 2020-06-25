use crate::prelude::*;

use std::borrow::Borrow;
use std::convert::TryFrom;
use std::ops::Add;

use uuid::Uuid;

use crate::crypto::interfaces::*;


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

/// Certificate encoding trait
pub trait CertificateEncoding {
    /// encode the raw certicate data that is to be signed
    fn encode_tbs(infos: &CertificateInfoBundle) -> Result<Vec<u8>, CryptoError>;

    /// encode certificate
    fn encode(data: &Certificate) -> Result<Vec<u8>, CryptoError>;
}

/// Build-a-certificate.
///
/// Add all ingredients and decide how to sign it!
#[derive(Default)]
pub struct CertificateFactory {
    certified: Option<Box<dyn PublicIdentity>>,
    validity: Duration,
}

impl CertificateFactory {
    /// Certify the given identity
    pub fn certified(mut self, certified: Box<dyn PublicIdentity>)
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
    pub fn self_sign<'a, E>(self,
                            signer: &dyn PrivateIdentity)
                            -> Result<Certificate<'a>, CryptoError>
        where E: CertificateEncoding {
        self.sign::<E>(signer, None)
    }

    /// Sign the certificate information with the given private key and an
    /// optional certificate
    pub fn sign<'a, E>(self,
                       signer: &dyn PrivateIdentity,
                       signer_cert: Option<&'a Certificate<'a>>)
                       -> Result<Certificate<'a>, CryptoError>
        where E: CertificateEncoding {
        let certified = self.certified.ok_or(
            CryptoError::Message {
                message: "Cannot create a certificate without identity".to_string()
            })?;

        // calculate expiration timestamp
        let expiration = SystemTime::now()
            .checked_add(self.validity)
            .ok_or(CryptoError::Message {
                message: "Error handling validity".to_string()
            })?;

        let serial = Uuid::new_v4().to_string();

        let infos = CertificateInfoBundle {
            identity: certified,
            expiration,
            serial,
            signer_certificate: signer_cert,
        };

        let tbs = E::encode_tbs(&infos)?;

        let signature = signer.sign(&tbs[..])?;

        Ok(Certificate { cert: tbs, signature, infos })
    }
}

#[cfg(test)]
mod certificate_tests {
    use super::*;
    use crate::crypto::DalekEd25519PrivateId;
    use crate::accounts::GrpcCertificateEncoding;

    #[test]
    fn test_create_self_signed() {
        let private = DalekEd25519PrivateId::generate().unwrap();

        let cert = CertificateFactory::default()
            .certified(private.public_id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&private).unwrap();

        private.public_id().verify(cert.encoded_certificate(), cert.signature()).unwrap();
    }

    #[test]
    fn test_create_signed() {
        let signer_private = DalekEd25519PrivateId::generate().unwrap();

        let signer_cert = CertificateFactory::default()
            .certified(signer_private.public_id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&signer_private).unwrap();

        signer_private.public_id().verify(signer_cert.encoded_certificate(), signer_cert.signature()).unwrap();

        // Sign a foreign certificate
        let signed_private = DalekEd25519PrivateId::generate().unwrap();

        let signed = CertificateFactory::default()
            .certified(signed_private.public_id().copy())
            .expiration(Duration::from_secs(1000))
            .sign::<GrpcCertificateEncoding>(&signer_private, Some(&signer_cert)).unwrap();

        signer_private.public_id().verify(signed.encoded_certificate(), signed.signature()).unwrap();
    }
}
