mod messages;

use self::messages::*;

mod message_codec;

use self::message_codec::encoding::*;

use async_trait::async_trait;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use futures::{SinkExt, stream::StreamExt};

use log::*;

use uuid::Uuid;
use protobuf::*;

use dashmap::*;

use std::sync::Arc;
use std::sync::mpsc::Receiver;

// TODO move this
pub struct PreKeys {
    identity: Vec<u8>,
    pre_key: Vec<u8>,
    one_time_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
pub struct TransportContextBuilder {
    addr: String,
    //handler: Box<ContextHandler>,
}

impl TransportContextBuilder {
    pub fn address(mut self, addr: String) -> Self {
        self.addr = addr;
        self
    }

    pub fn server(self) -> impl TransportContext {
        ServerContext { addr: self.addr, sessions: Arc::new(DashMap::new()) }
    }

    //pub fn client(self) -> impl TransportContext {}
}


/// Context for any message transport
#[async_trait]
pub trait TransportContext {
    /// Run this context
    async fn work(mut self) -> Result<(), Box<dyn std::error::Error>>;
}

struct ServerContext {
    addr: String,
    sessions: Arc<DashMap<Vec<u8>, PreKeys>>,
}

#[async_trait]
impl TransportContext for ServerContext {
    async fn work(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut listener = TcpListener::bind(self.addr).await?;

        let mut incoming = listener.incoming();
        while let Some(conn) = incoming.next().await {
            match conn {
                Err(e) => error!("Accept failed {}", e),
                Ok(sock) => {
                    let uuid = Uuid::new_v4();
                    let s = ServerConnection::new(uuid.to_string(), sock, Arc::clone(&self.sessions));

                    tokio::spawn(async move { s.work().await.unwrap() });
                }
            }
        }

        Ok(())
    }
}

/// Incoming TCP server connection
struct ServerConnection {
    session: String,
    transport: Framed<TcpStream, EnvelopeCodec>,
    sessions: Arc<DashMap<Vec<u8>, PreKeys>>,
}

impl ToString for ServerConnection {
    fn to_string(&self) -> String {
        self.session.clone()
    }
}

impl ServerConnection {
    pub fn new(peer: String, socket: TcpStream, sessions: Arc<DashMap<Vec<u8>, PreKeys>>) -> ServerConnection {
        let codec = EnvelopeCodec::default();
        let transport = Framed::new(socket, codec);

        ServerConnection { session: peer, transport, sessions }
    }
}

#[async_trait]
impl TransportContext for ServerConnection {
    async fn work(mut self) -> Result<(), Box<dyn std::error::Error>> {
        while let Some(msg) = self.transport.next().await {
            match msg {
                Err(e) => return Err(Box::new(e)),
                Ok(m) => {
                    let e: Envelope = m;

                    info!("Message {} from {}", e.get_field_type().value(), &self.session);
                }
            }
        }

        // connection closed
        Ok(())
    }
}


struct ClientContext {
    addr: String,
}

#[async_trait]
impl TransportContext for ClientContext {
    async fn work(mut self) -> Result<(), Box<dyn std::error::Error>> {
        let stream = TcpStream::connect("127.0.0.1:6142").await?;

        Ok(())
    }
}


/// TODO refine fn signatures
#[async_trait]
pub trait ContextHandler {
    async fn receive_pre_key(&self, data: Envelope);

    async fn send_pre_key(&self, data: Envelope);

    async fn receive_attestation(&self, data: Envelope);

    async fn send_attestation(&self, data: Envelope);
}


/*
#[async_trait]
pub trait MessageHandler {
    fn handle_chipertext(&mut self, data: Envelope);

    fn handle_exchange(&mut self, data: Envelope);

    async fn handle_pre_key(&mut self, data: Envelope);

    fn handle_receipt(&mut self, data: Envelope);
}
*/


#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use x25519_dalek::*;
    use protobuf::*;
    use rand_core::OsRng;

    struct PrivateKeys {
        id_key: StaticSecret,
        pre_key: StaticSecret,
        one_time_pre_key: StaticSecret,
    }

    struct PublicKeys {
        id_key: PublicKey,
        pre_key: PublicKey,
        one_time_pre_key: PublicKey,
    }

    struct TestKeys {
        alice: Option<PublicKeys>,
        alice_priv: Option<PrivateKeys>,

        bob: Option<PublicKeys>,
        bob_priv: Option<PrivateKeys>,
    }

    fn fill_test_keys(keys: &mut TestKeys) -> Payload {
        let a_priv_id = StaticSecret::new(&mut OsRng);
        let a_pub_id = PublicKey::from(&a_priv_id);

        let a_priv_pre_key = StaticSecret::new(&mut OsRng);
        let a_pub_pre_key = PublicKey::from(&a_priv_pre_key);

        let a_priv_otpkey = StaticSecret::new(&mut OsRng);
        let a_pub_otpkey = PublicKey::from(&a_priv_otpkey);

        let mut pre_key_bundle = PreKeyBundle::new();
        pre_key_bundle.set_identity(a_pub_id.as_bytes().to_vec());
        pre_key_bundle.set_prekey(a_pub_pre_key.as_bytes().to_vec());

        let otp = RepeatedField::from_vec(vec![a_pub_otpkey.as_bytes().to_vec()]);
        pre_key_bundle.set_one_time_prekey(otp);

        let mut payload = Payload::new();
        payload.set_pre_key(pre_key_bundle);

        let b_priv_id = StaticSecret::new(&mut OsRng);
        let b_pub_id = PublicKey::from(&a_priv_id);

        let b_priv_pre_key = StaticSecret::new(&mut OsRng);
        let b_pub_pre_key = PublicKey::from(&a_priv_pre_key);

        let b_priv_otpkey = StaticSecret::new(&mut OsRng);
        let b_pub_otpkey = PublicKey::from(&a_priv_otpkey);

        keys.alice_priv = Some(PrivateKeys { id_key: a_priv_id, pre_key: a_priv_pre_key, one_time_pre_key: a_priv_otpkey });
        keys.bob_priv = Some(PrivateKeys { id_key: b_priv_id, pre_key: b_priv_pre_key, one_time_pre_key: b_priv_otpkey });

        keys.alice = Some(PublicKeys { id_key: a_pub_id, pre_key: a_pub_pre_key, one_time_pre_key: a_pub_otpkey });
        keys.bob = Some(PublicKeys { id_key: b_pub_id, pre_key: b_pub_pre_key, one_time_pre_key: b_pub_otpkey });

        return payload;
    }

    #[tokio::test]
    async fn test_echo() {
        let mut test_keys = TestKeys { alice: None, alice_priv: None, bob: None, bob_priv: None };
        let payload = fill_test_keys(&mut test_keys);

        let alice_stream = TcpStream::connect("127.0.0.1:6142").await.unwrap();
        let mut alice_transport = Framed::new(alice_stream, EnvelopeCodec::default());

        let bob_stream = TcpStream::connect("127.0.0.1:6142").await.unwrap();
        let mut bob_transport = Framed::new(bob_stream, EnvelopeCodec::default());

        let mut a_pub_pre_key = Envelope::new();
        a_pub_pre_key.set_cmd(Envelope_Command::SEND);
        a_pub_pre_key.set_field_type(Envelope_Type::PREKEY_BUNDLE);
        a_pub_pre_key.set_content(payload);

        alice_transport.send(a_pub_pre_key).await.unwrap();

        println!("publish success");

        let mut a_peer = Peer::new();
        a_peer.set_identity(test_keys.alice.unwrap().id_key.as_bytes().to_vec());

        let mut b_req_pre_key = Envelope::new();
        b_req_pre_key.set_cmd(Envelope_Command::REQUEST);
        b_req_pre_key.set_field_type(Envelope_Type::PREKEY_BUNDLE);
        b_req_pre_key.set_peer(a_peer);

        bob_transport.send(b_req_pre_key).await.unwrap();

        println!("request sent");

        while let Some(message) = bob_transport.next().await {
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


