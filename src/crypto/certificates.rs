use std::{io, vec, error, fmt, time};

use time::{SystemTime, Duration, UNIX_EPOCH};
use uuid::Uuid;

use super::{Identity, PrivateIdentity, PublicIdentity};
use std::marker::PhantomData;
use std::convert::TryFrom;
use std::ops::Add;

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
    pub identity: &'a dyn Identity,
}

/// client certificate information
pub struct ClientCertificate<'a> {
    pub uuid: String,
    pub identity: &'a dyn Identity,
    pub expiration: u64,
    pub signer: &'a ServerCertificate<'a>,
}

pub struct CertificateFactory<'a> {
    certification_target: &'a dyn Identity,
    signer: &'a dyn PrivateIdentity,
}

impl<'a> CertificateFactory<'a> {
    /// create a new certificate factory for the identity-to-be-certified
    pub fn build_for<'b: 'a>(identity: &'b dyn Identity, signer: &'b dyn PrivateIdentity) -> CertificateFactory<'a> {
        CertificateFactory {
            certification_target: identity,
            signer,
        }
    }

    pub fn server_certificate(self) -> Result<CertificateBundle<'a, ServerCertificate<'a>>, Box<dyn error::Error>> {
        let inner_cert = ServerCertificate { uuid: Uuid::new_v4().to_string(), identity: self.certification_target };

        Ok(CertificateBundle { certificate: inner_cert, signer: self.signer })
    }

    pub fn client_certificate<'b: 'a>(self,
                                      signer_cert: &'b ServerCertificate<'_>,
                                      validity: time::Duration)
                                      -> Result<CertificateBundle<'a, ClientCertificate<'a>>, Box<dyn error::Error>> {
        // calculate expiration timestamp
        let expiration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.add(validity).as_secs())?;

        let inner_cert = ClientCertificate {
            uuid: Uuid::new_v4().to_string(),
            identity: self.certification_target,
            expiration,
            signer: signer_cert,
        };

        Ok(CertificateBundle { certificate: inner_cert, signer: self.signer })
    }
}
