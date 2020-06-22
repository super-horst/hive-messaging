use std::{io, vec, error, fmt, time};

use std::borrow::Borrow;
use std::marker::PhantomData;
use std::convert::TryFrom;
use std::ops::Add;

use uuid::Uuid;

use crate::prelude::*;
use crate::crypto::interfaces::*;


pub struct Certificate<'a> {
    cert: Vec<u8>,
    signature: Vec<u8>,
    expiration: u64,
    serial: String,
    public: Box<dyn PublicIdentity>,
    signer_certificate: Option<&'a Certificate<'a>>,
}

impl<'a> Certificate<'a> {
    pub fn encoded_certificate(&self) -> &[u8] {
        self.cert.as_slice()
    }

    pub fn signature(&self) -> &[u8] {
        self.signature.as_slice()
    }

    pub fn public_key(&self) -> &dyn PublicIdentity {
        self.public.borrow()
    }

    pub fn signer_certificate(&self) -> &Option<&'_ Certificate<'_>> {
        &self.signer_certificate
    }
}

#[derive(Default)]
pub struct CertificateBuilder<'a> {
    cert: Option<Vec<u8>>,
    signature: Option<Vec<u8>>,
    public: Option<Box<dyn PublicIdentity>>,
    signer: Option<Box<dyn PublicIdentity>>,
    signer_cert: Option<&'a Certificate<'a>>,
}

impl<'a> CertificateBuilder<'a> {
    fn certified(&mut self, cert: Vec<u8>, public: Box<dyn PublicIdentity>)
                 -> &mut CertificateBuilder<'a> {
        self.cert = Some(cert);
        self.public = Some(public);

        self
    }

    fn signature(&mut self, signature: Vec<u8>) -> &mut CertificateBuilder<'a> {
        self.signature = Some(signature);

        self
    }

    fn signer_certificate<'b: 'a>(&mut self, signer_cert: &'b Certificate<'b>)
                                  -> &mut CertificateBuilder<'a> {
        self.signer_cert = Some(signer_cert);

        self
    }

    fn build(self) -> Result<Certificate<'a>, CryptoError> {
        let certified = self.cert.ok_or(
            CryptoError::Message {
                message: "Builder was given no certificate".to_string()
            })?;
        let certified_key = self.public.ok_or(
            CryptoError::Message {
                message: "Builder was given no key".to_string()
            })?;
        let signature = self.signature.ok_or(
            CryptoError::Message {
                message: "Builder was given no signature".to_string()
            })?;

        Ok(Certificate {
            cert: certified,
            public: certified_key,
            signature,
            //TODO expiration
            expiration: 0,
            signer_certificate: self.signer_cert,
            //TODO serial
            serial: Uuid::new_v4().to_string(),
        })
    }
}


/// Wrapper for certificate information & a signer to provide a serialisation
pub struct CertificateBundle<'a, T> {
    pub certificate: T,
    pub signer: &'a dyn PrivateIdentity,
}

impl<'a, T> CertificateBundle<'a, T> {
    pub fn new(inner: T, signer: &'a dyn PrivateIdentity) -> CertificateBundle<'a, T> {
        CertificateBundle { certificate: inner, signer }
    }
}

/// server certificate information
pub struct ServerCertificate<'a> {
    pub uuid: String,
    pub identity: &'a dyn PublicIdentity,
}

/// client certificate information
pub struct ClientCertificate<'a> {
    pub uuid: String,
    pub identity: &'a dyn PublicIdentity,
    pub expiration: u64,
    pub signer: &'a ServerCertificate<'a>,
}

pub struct CertificateFactory<'a> {
    certification_target: &'a dyn PublicIdentity,
    signer: &'a dyn PrivateIdentity,
}

impl<'a> CertificateFactory<'a> {
    /// create a new certificate factory for the identity-to-be-certified
    pub fn build_for<'b: 'a>(identity: &'b dyn PublicIdentity,
                             signer: &'b dyn PrivateIdentity)
                             -> CertificateFactory<'a> {
        CertificateFactory {
            certification_target: identity,
            signer,
        }
    }

    pub fn server_certificate<E>(self) -> Result<E, CryptoError>
        where E: TryFrom<CertificateBundle<'a, ServerCertificate<'a>>, Error=CryptoError> {
        let inner_cert = ServerCertificate {
            uuid: Uuid::new_v4().to_string(),
            identity: self.certification_target,
        };

        E::try_from(CertificateBundle { certificate: inner_cert, signer: self.signer })
    }

    pub fn client_certificate<'b: 'a, E>(self,
                                         signer_cert: &'b ServerCertificate<'_>,
                                         validity: Duration)
                                         -> Result<E, CryptoError>
        where E: TryFrom<CertificateBundle<'a, ClientCertificate<'a>>, Error=CryptoError> {

        // calculate expiration timestamp
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.add(validity).as_secs())
            .map_err(|e| CryptoError::Message { message: e.to_string() })?;

        let inner_cert = ClientCertificate {
            uuid: Uuid::new_v4().to_string(),
            identity: self.certification_target,
            expiration,
            signer: signer_cert,
        };

        E::try_from(CertificateBundle { certificate: inner_cert, signer: self.signer })
    }
}
