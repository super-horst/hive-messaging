use std::io;
use std::fmt;
use std::error;

use bytes::{ Buf, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use protobuf::{Message as protobuf_msg_for_fns, CodedInputStream};
use crate::messages::*;

const VARINT_THRESHOLD: u8 = 0x80;

pub mod encoding {
    use super::*;

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

    impl From<protobuf::ProtobufError> for CodecError {
        fn from(err: protobuf::ProtobufError) -> Self {
            CodecError::InvalidMessageError(err)
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
            // keep length delimited
            let bytes = item.write_length_delimited_to_bytes();
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
            // length delimited protobuf is prefixed by a length varint,
            // this counts all bytes of the encoded length
            let mut i: usize = 0;
            for &byte in &src[..] {
                i += 1;
                if byte < VARINT_THRESHOLD {
                    break;
                }
            }

            if i >= src.remaining() {
                // incomplete message
                return Ok(None);
            }

            // get encoded message length
            let length: usize;
            match CodedInputStream::from_bytes(&src[..i]).read_raw_varint64() {
                Ok(msg_len) => length = msg_len as usize + i,
                Err(e) => return Err(CodecError::from(e)),
            }

            if src.remaining() < length {
                // incomplete message
                return Ok(None);
            }

            // single message
            let msg_buffer = src.split_to(length).freeze();
            let mut stream = CodedInputStream::from_carllerche_bytes(&msg_buffer);

            return match stream.read_message() {
                Ok(parsed) => Ok(Some(parsed)),
                Err(e) => Err(CodecError::from(e)),
            };
        }
    }
}

#[cfg(test)]
mod codec_tests {
    use super::*;
    use super::encoding::*;

    #[test]
    fn test_decode() {
        let mut rmsg = Envelope::new();
        rmsg.set_field_type(Envelope_Type::RECEIPT);

        let data = rmsg.write_length_delimited_to_bytes().unwrap();

        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&data[..]);
        let mut codec = EnvelopeCodec::new();

        let result = codec.decode(&mut bytes);

        match result {
            Ok(v) => {
                match v {
                    None => panic!("Decoder did not return a message"),
                    Some(message) => {
                        assert_eq!(Envelope_Type::RECEIPT, message.get_field_type());
                    }
                }
            }
            Err(e) => {
                eprintln!("{}", e);
                panic!(e)
            }
        }
    }

    #[test]
    fn test_decode_cleanup() {
        let mut rmsg = Envelope::new();
        rmsg.set_field_type(Envelope_Type::RECEIPT);

        let data = rmsg.write_length_delimited_to_bytes().unwrap();
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&data[..]);
        let mut codec = EnvelopeCodec::new();

        let _result = codec.decode(&mut bytes);

        assert!(bytes.is_empty());
    }

    #[test]
    fn test_decode_incomplete() {
        let mut rmsg = Envelope::new();
        rmsg.set_field_type(Envelope_Type::RECEIPT);

        let data = rmsg.write_length_delimited_to_bytes().unwrap();
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
        rmsg.set_field_type(Envelope_Type::RECEIPT);
        //rmsg.set_client(SenderCertificate::new());

        let mut bytes = BytesMut::new();
        let mut codec = EnvelopeCodec::new();
        let _result = codec.encode(rmsg, &mut bytes);
        assert!(_result.is_ok());

        let b = bytes.split().freeze();

        let proto_result = CodedInputStream::from_carllerche_bytes(&b).read_message();

        assert!(proto_result.is_ok());
        let message: Envelope = proto_result.unwrap();
        assert_eq!(Envelope_Type::RECEIPT, message.get_field_type());
    }

    #[test]
    fn test_roundtrip() {
        let mut rmsg = Envelope::new();
        rmsg.set_field_type(Envelope_Type::RECEIPT);

        let mut bytes = BytesMut::new();
        let mut codec = EnvelopeCodec::new();
        let _result = codec.encode(rmsg, &mut bytes);
        assert!(_result.is_ok());

        let recycled = codec.decode(&mut bytes);

        match recycled {
            Ok(v) => {
                match v {
                    None => panic!("Decoder did not return a message"),
                    Some(message) => {
                        assert_eq!(Envelope_Type::RECEIPT, message.get_field_type());
                    }
                }
            }
            Err(e) => {
                panic!(e)
            }
        }
    }
}
