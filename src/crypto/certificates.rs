use std::borrow::Borrow;
use std::convert::TryFrom;
use std::ops::Add;

use uuid::Uuid;

use crate::prelude::*;
use crate::crypto::interfaces::*;

/// Certificate encoding trait
pub trait CertificateEncoding {
    /// encode the raw certicate data that is to be signed
    fn encode_tbs(infos: &CertificateInfoBundle) -> Result<Vec<u8>, CryptoError>;

    /// encode certificate
    fn encode(data: &Certificate) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Default)]
pub struct CertificateFactory {
    certified: Option<Box<dyn PublicIdentity>>,
    validity: Duration,
}

impl CertificateFactory {
    /// certify the given identity
    pub fn certified(mut self, certified: Box<dyn PublicIdentity>)
                     -> CertificateFactory {
        self.certified = Some(certified);

        self
    }

    pub fn expiration(mut self, validity: Duration)
                      -> CertificateFactory {
        self.validity = validity;

        self
    }

    pub fn self_sign<'a, E>(self,
                        signer: &dyn PrivateIdentity)
                        -> Result<Certificate<'a>, CryptoError>
        where E: CertificateEncoding {
        self.sign::<E>(signer, None)
    }

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

        Ok(Certificate {
            cert: tbs,
            signature,
            infos,
        })
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
