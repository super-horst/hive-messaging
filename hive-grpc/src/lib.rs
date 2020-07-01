use std::time::{SystemTime, UNIX_EPOCH, Duration};

use bytes::Bytes;

use failure::{Error, Fail};
use prost::Message;

use hive_crypto::{CryptoError,
                  PublicKey,
                  CertificateInfoBundle,
                  CertificateEncoding};

use std::hash::{Hash, Hasher};

pub mod common {
    tonic::include_proto!("common");
}

pub mod accounts {
    tonic::include_proto!("accounts");
}

pub mod messages {
    tonic::include_proto!("messages");
}

impl Eq for messages::MessageEnvelope {}

impl std::hash::Hash for messages::MessageEnvelope {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ratchet_key.hash(state);

        state.write_u64(self.chain_idx);
    }
}

impl Eq for common::Peer {}

impl std::hash::Hash for common::Peer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
        self.namespace.hash(state);
    }
}


#[derive(Debug, Fail)]
pub enum GrpcEncodingError {
    #[fail(display = "Decoding failed: {}", message)]
    Decoding {
        message: String,
        #[fail(cause)] cause: prost::DecodeError,
    },
    #[fail(display = "Encoding failed: {}", message)]
    Encoding {
        message: String,
        #[fail(cause)] cause: prost::EncodeError,
    },
}

pub struct GrpcCertificateEncoding;

impl CertificateEncoding for GrpcCertificateEncoding {
    type CertificateType = common::Certificate;

    fn serialise_tbs(infos: &CertificateInfoBundle) -> Result<Vec<u8>, failure::Error> {
        let expires = infos.expires().duration_since(UNIX_EPOCH)
                           .map(|d| d.as_secs())
                           .map_err(|e| CryptoError::Message { message: e.to_string() })?;

        let id = infos.public_key();

        let mut tbs_cert = common::certificate::TbsCertificate {
            identity: id.id_bytes(),
            namespace: id.namespace(),
            expires,
            uuid: infos.serial().to_string(),
            signer: None,
        };

        match infos.signer_certificate() {
            Some(c) => {
                let gc = common::Certificate {
                    certificate: c.encoded_certificate().to_vec(),
                    signature: c.signature().to_vec(),
                };
                tbs_cert.signer = Some(gc);
            }
            None => (),
        }

        let mut buf: Vec<u8> = Vec::with_capacity(tbs_cert.encoded_len());
        tbs_cert.encode(&mut buf).map_err(|e| GrpcEncodingError::Encoding {
            message: "failed to encode TBS certificate".to_string(),
            cause: e,
        })?;

        Ok(buf)
    }

    fn serialise(data: &hive_crypto::Certificate) -> Result<Vec<u8>, failure::Error> {
        let cert = common::Certificate {
            certificate: data.encoded_certificate().to_vec(),
            signature: data.signature().to_vec(),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(cert.encoded_len());
        cert.encode(&mut buf).map_err(|e| GrpcEncodingError::Encoding {
            message: "failed to encode certificate".to_string(),
            cause: e,
        })?;

        Ok(buf)
    }

    fn decode_partial(serialised: common::Certificate)
                      -> Result<(hive_crypto::Certificate, Option<common::Certificate>), failure::Error> {
        let buf = Bytes::from(serialised.certificate.to_vec());
        let tbs_cert = common::certificate::TbsCertificate::decode(buf)
            .map_err(|e| GrpcEncodingError::Decoding {
                message: "failed to decode certificate".to_string(),
                cause: e,
            })?;

        let signed_identity = PublicKey::from_raw_bytes(&tbs_cert.identity[..])?;

        let expiration = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(tbs_cert.expires))
            .ok_or(CryptoError::Message {
                message: format!("is invalid system time '{}'", tbs_cert.expires)
            })?;

        let cert_info = CertificateInfoBundle::new(signed_identity,
                                                   expiration,
                                                   tbs_cert.uuid,
                                                   None);

        let cert = hive_crypto::Certificate::new(serialised.certificate,
                                                 serialised.signature,
                                                 cert_info);

        Ok((cert, tbs_cert.signer))
    }

    fn deserialise(bytes: Vec<u8>) -> Result<common::Certificate, failure::Error> {
        let buf = Bytes::from(bytes);
        let cert = common::Certificate::decode(buf)
            .map_err(|e| GrpcEncodingError::Decoding {
                message: "failed to decode certificate".to_string(),
                cause: e,
            })?;

        Ok(cert)
    }
}
