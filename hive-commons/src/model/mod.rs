use bytes::Bytes;
use std::hash::{Hash, Hasher};

mod error;
pub use error::*;

/// common protos
pub mod common;

/// account protos
pub mod accounts;

/// message protos
pub mod messages;

impl Eq for messages::Envelope {}

impl Hash for messages::Envelope {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.dst.hash(state);
    }
}

impl Eq for common::Peer {}

impl Hash for common::Peer {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.identity.hash(state);
        self.namespace.hash(state);
    }
}

pub trait Encodable {
    fn encode(&self) -> Result<Vec<u8>, SerialisationError>;
}

impl<T: prost::Message> Encodable for T {
    fn encode(&self) -> Result<Vec<u8>, SerialisationError> {
        let mut buf: Vec<u8> = Vec::with_capacity(self.encoded_len());
        self.encode(&mut buf)
            .map_err(|e| SerialisationError::Encoding {
                message: "failed to encode TBS certificate".to_string(),
                cause: e,
            })?;
        Ok(buf)
    }
}

pub trait Decodable<T> {
    fn decode(bytes: Vec<u8>) -> Result<T, SerialisationError>;
}

impl<T: prost::Message + Default> Decodable<T> for T {
    fn decode(bytes: Vec<u8>) -> Result<T, SerialisationError> {
        let buf = Bytes::from(bytes);

        Self::decode(buf).map_err(|e| SerialisationError::Decoding {
            message: "failed to decode object".to_string(),
            cause: e,
        })
    }
}
