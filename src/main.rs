use futures::stream::StreamExt;

use std::io::{stdout, BufWriter};
use std::{env, error::Error, fmt, io};

use tokio::{
    prelude::*,
    net::{TcpListener, TcpStream},
    stream::Stream,
    time::delay_for,
};

use bytes::BytesMut;
use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

use futures::{Sink, SinkExt};
use tokio_util::codec::{Decoder, Encoder, Framed, FramedWrite};

use std::time::Duration;
use std::io::prelude::*;

use std::fs::File;

mod messages;
mod crypto;

use self::messages::Envelope;
use protobuf::CodedOutputStream;
use protobuf::Message as Message_imported_for_functions;

mod message_codec;

use self::message_codec::encoding::*;

mod key_mgmt;
use self::key_mgmt::{ast::*, visit::*, Interpreter};


async fn process(stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let codec = EnvelopeCodec {};

    let mut transport = Framed::new(stream, codec);

    while let Some(message) = transport.next().await {
        match message {
            Ok(message) => {
                println!("accept success = {:?}", message.get_name());
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let addr = "127.0.0.1:6142";
    let mut listener = TcpListener::bind(addr).await.unwrap();

    // Here we convert the `TcpListener` to a stream of incoming connections
    // with the `incoming` method.
    let server = {
        async move {
            let mut incoming = listener.incoming();
            while let Some(conn) = incoming.next().await {
                match conn {
                    Err(e) => eprintln!("accept failed = {:?}", e),
                    Ok(mut sock) => {
                        tokio::spawn(async move {
                            let codec = EnvelopeCodec {};
                            let mut transport = Framed::new(sock, codec);

                            while let Some(msg) = transport.next().await {
                                match msg {
                                    Err(e) => eprintln!("frame failed = {:?}", e),
                                    Ok(mut m) => {
                                        transport.send(m).await.unwrap();
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    };

    println!("Server running on localhost:6142");

    // Start the server and block this async fn until `server` spins down.
    server.await;
}

async fn write_data(data: &[u8]) {
    let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

    let result = stream.write_all(data).await;
    println!("wrote to stream; success={:?}", result.is_ok());
}

/**
 * Session is a single TCP connection and exists for it's lifetime.
 *
 */
pub struct Session {
    session: String,
    transport: Framed<TcpStream, EnvelopeCodec>,
}

impl Session {
    pub async fn initialise(peer: String, mut socket: TcpStream) {
        let codec = EnvelopeCodec {};
        let mut transport = Framed::new(socket, codec);

        let s = Session { session: peer , transport };

        let session_secret = EphemeralSecret::new(&mut OsRng);
        let session_public = PublicKey::from(&session_secret);
        //let key = session_public.as_bytes().iter().cloned().collect();
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    //#[tokio::test]
    async fn test_write_data() {
        let mut stream = TcpStream::connect("127.0.0.1:6142").await.unwrap();

        let mut rmsg = Envelope::new();
        //rmsg.set_senderGuid("1234".to_string());
        let data = rmsg.write_to_bytes().unwrap();

        let result = stream.write_all(&data[..]).await;
        println!("wrote to stream; success={:?}", result.is_ok());


        delay_for(Duration::from_millis(1000)).await;


        let mut rmsg = Envelope::new();
        //rmsg.set_senderGuid("5678".to_string());
        let data = rmsg.write_to_bytes().unwrap();

        let result = stream.write_all(&data[..]).await;
        println!("wrote to stream; success={:?}", result.is_ok());
    }

    #[tokio::test]
    async fn test_echo() {
        let stream = TcpStream::connect("127.0.0.1:6142").await.unwrap();

        let codec = EnvelopeCodec {};
        let mut transport = Framed::new(stream, codec);

        let mut rmsg = Envelope::new();
        rmsg.set_name("testingsumoah".to_string());

        transport.send(rmsg).await.unwrap();

        println!("send success");

        while let Some(message) = transport.next().await {
            match message {
                Ok(message) => {
                    println!("echo success = {:?}", message.get_name());
                    break;
                }
                Err(e) => println!("{}", e),
            }
        }
    }
}
