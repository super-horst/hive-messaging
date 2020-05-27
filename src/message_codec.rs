use std::io;
use std::fmt;
use std::error;

use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use protobuf::Message;
use crate::messages::*;

const PROTOBUF_MARKER: u8 = 0x0a;

pub mod encoding {
    use super::*;
    use bytes::Buf;

    #[derive(Debug)]
    pub enum CodecError {
        /// any invalid message
        InvalidMessageError(protobuf::ProtobufError),
        /// I/O error when reading or writing
        IoError(io::Error),
    }

    impl fmt::Display for CodecError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            match self {
                // TODO do useful stuff
                &CodecError::InvalidMessageError(ref e) => write!(f, "Invalid message error: {}", e),
                &CodecError::IoError(ref e) => write!(f, "I/O error: {}", e),
            }
        }
    }

    impl error::Error for CodecError {
        #[allow(deprecated)] // call to `description`
        fn description(&self) -> &str {
            match self {
                // TODO do useful stuff
                &CodecError::InvalidMessageError(ref e) => e.description(),
                &CodecError::IoError(ref e) => e.description(),
            }
        }

        fn cause(&self) -> Option<&dyn error::Error> {
            match self {
                // TODO do useful stuff
                &CodecError::InvalidMessageError(ref e) => Some(e),
                &CodecError::IoError(ref e) => Some(e),
            }
        }
    }

    impl From<io::Error> for CodecError {
        fn from(err: io::Error) -> Self {
            CodecError::IoError(err)
        }
    }

    /// Codec implementing tokio_util::codec ... for Envelope protobuf message
    #[derive(Debug)]
    pub struct EnvelopeCodec {}

    impl EnvelopeCodec {
        pub fn new() -> EnvelopeCodec {
            EnvelopeCodec {}
        }
    }

    impl Encoder<Envelope> for EnvelopeCodec {
        type Error = CodecError;

        fn encode(&mut self, item: Envelope, dst: &mut BytesMut) -> Result<(), CodecError> {
            //to_bytes
            let bytes = item.write_to_bytes();
            match bytes {
                Ok(b) => {
                    dst.extend(b);
                    Ok(())
                }
                Err(e) => Err(CodecError::InvalidMessageError(e))
            }
        }
    }

    impl Decoder for EnvelopeCodec {
        type Item = Envelope;
        type Error = CodecError;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            while src.remaining() >= 1 && PROTOBUF_MARKER != src.bytes()[0] {
                src.advance(1);
            }

            if src.remaining() < 2 {
                return Ok(None);
            }

            // get length from protobuf message + offset
            let length = src.bytes()[1] as usize + 2;

            if src.remaining() < length {
                return Ok(None);
            }

            // single message
            let mut msg_buffer = src.split_to(length);
            let proto_result = protobuf::parse_from_bytes(&msg_buffer);

            match proto_result {
                Ok(v) => Ok(Some(v)),
                Err(e) => Err(CodecError::InvalidMessageError(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    static NAME: &'static str = "Name1";

    use super::*;
    use super::encoding::*;

    #[test]
    fn test_decode() {
        let mut rmsg = Envelope::new();
        rmsg.set_name(NAME.to_string());

        let data = rmsg.write_to_bytes().unwrap();

        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&data[..]);
        let mut codec = EnvelopeCodec::new();

        let result = codec.decode(&mut bytes);

        match result {
            Ok(v) => {
                match v {
                    None => panic!("Decoder did not return a message"),
                    Some(message) => {
                        assert_eq!(NAME.to_string(), message.get_name());
                    }
                }
            }
            Err(e) => {
                panic!(e)
            }
        }
    }

    #[test]
    fn test_decode_cleanup() {
        let mut rmsg = Envelope::new();
        rmsg.set_name(NAME.to_string());

        let data = rmsg.write_to_bytes().unwrap();
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&data[..]);
        let mut codec = EnvelopeCodec::new();

        let _result = codec.decode(&mut bytes);

        assert!(bytes.is_empty());
    }

    #[test]
    fn test_decode_incomplete() {
        let mut rmsg = Envelope::new();
        rmsg.set_name(NAME.to_string());

        let data = rmsg.write_to_bytes().unwrap();
        let mut bytes = BytesMut::new();

        // complete message
        bytes.extend_from_slice(&data[..]);

        // incomplete message
        bytes.extend_from_slice(&data[0..2]);

        let mut codec = EnvelopeCodec::new();

        let _result = codec.decode(&mut bytes);

        // incomplete message remains
        assert_eq!(bytes.len(), 2);
        assert!(_result.is_ok());

        // remaining message
        bytes.extend_from_slice(&data[2..]);
        let _result = codec.decode(&mut bytes);

        assert!(bytes.is_empty());
        assert!(_result.is_ok());
    }

    #[test]
    fn test_encode() {
        let mut rmsg = Envelope::new();
        rmsg.set_name(NAME.to_string());

        let mut bytes = BytesMut::new();
        let mut codec = EnvelopeCodec::new();
        let _result = codec.encode(rmsg, &mut bytes);
        assert!(_result.is_ok());

        let proto_result = protobuf::parse_from_bytes(&bytes[..]);

        assert!(proto_result.is_ok());
        let message: Envelope = proto_result.unwrap();
        assert_eq!(NAME.to_string(), message.get_name());
    }

    #[test]
    fn test_roundtrip() {
        let mut rmsg = Envelope::new();
        rmsg.set_name(NAME.to_string());

        let mut bytes = BytesMut::new();
        let mut codec = EnvelopeCodec::new();
        let _result = codec.encode(rmsg, &mut bytes);
        assert!(_result.is_ok());

        let recycled =  codec.decode(&mut bytes);

        match recycled {
            Ok(v) => {
                match v {
                    None => panic!("Decoder did not return a message"),
                    Some(message) => {
                        assert_eq!(NAME.to_string(), message.get_name());
                    }
                }
            }
            Err(e) => {
                panic!(e)
            }
        }
    }
}
