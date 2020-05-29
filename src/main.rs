use std::error::Error;

use tokio::{
    prelude::*,
    net::{TcpListener, TcpStream},
    time::delay_for,
};
use tokio_util::codec::Framed;
use futures::{SinkExt, stream::StreamExt};

use rand_core::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey};

mod messages;
use crate::messages::Envelope;

mod crypto;

mod message_codec;
use crate::message_codec::encoding::*;

mod key_mgmt;
use crate::key_mgmt::*;

async fn process(stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let codec = EnvelopeCodec {};

    let mut transport = Framed::new(stream, codec);

    while let Some(message) = transport.next().await {
        match message {
            Ok(message) => {
                println!("accept success");
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

    let server = {
        async move {
            let mut incoming = listener.incoming();
            while let Some(conn) = incoming.next().await {
                match conn {
                    Err(e) => eprintln!("accept failed = {:?}", e),
                    Ok(mut sock) => {
                        tokio::spawn(async move {
                            let codec = EnvelopeCodec::new();
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

        let s = Session { session: peer, transport };

        let session_secret = EphemeralSecret::new(&mut OsRng);
        let session_public = PublicKey::from(&session_secret);
        //let key = session_public.as_bytes().iter().cloned().collect();
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::messages::Envelope_Type;

    #[tokio::test]
    async fn test_echo() {
        let stream = TcpStream::connect("127.0.0.1:6142").await.unwrap();

        let codec = EnvelopeCodec::new();
        let mut transport = Framed::new(stream, codec);

        let mut rmsg = Envelope::new();
        rmsg.set_field_type(Envelope_Type::RECEIPT);

        transport.send(rmsg).await.unwrap();

        println!("send success");

        while let Some(message) = transport.next().await {
            match message {
                Ok(message) => {
                    println!("echo success = {:?}", message.get_field_type());
                    break;
                }
                Err(e) => println!("{}", e),
            }
        }
    }
}
