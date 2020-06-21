use std::{io, vec, error, fmt, time};

use std::marker::PhantomData;
use std::convert::TryFrom;
use std::ops::Add;

use crate::prelude::*;
use crate::crypto::interfaces::*;

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
