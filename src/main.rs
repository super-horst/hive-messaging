use std::io;
use std::fmt;
use std::error;

use log::*;
use simple_logger;
use uuid::Uuid;

use tokio::net::{TcpListener, TcpStream};
use tokio_util::codec::Framed;
use futures::{SinkExt, stream::StreamExt};

use x25519_dalek::*;
use rand_core::OsRng;
use async_trait::async_trait;

use protobuf::*;

use dashmap::*;

mod messages;

use crate::messages::*;

mod crypto;

mod message_codec;

use crate::message_codec::encoding::*;
use std::sync::Arc;
use std::sync::mpsc::Receiver;

#[tokio::main]
async fn main() {
    simple_logger::init().unwrap();

    let addr = "127.0.0.1:6142";
    let mut listener = TcpListener::bind(addr).await.unwrap();

    let server = {
        async move {
            ServerContext::new(listener).work().await
        }
    };

    info!("Server running on {}", addr);

    // Start the server and block this async fn until `server` spins down.
    server.await;
}

struct ServerContext {
    listener: TcpListener,
    sessions: Arc<DashMap<Vec<u8>, PreKeys>>,
}

impl ServerContext {
    fn new(listener: TcpListener) -> ServerContext {
        ServerContext { listener, sessions: Arc::new(DashMap::new()) }
    }

    async fn work(mut self) {
        let mut incoming = self.listener.incoming();
        while let Some(conn) = incoming.next().await {
            match conn {
                Err(e) => error!("accept failed = {:?}", e),
                Ok(sock) => {
                    let uuid = Uuid::new_v4();
                    let mut s = Session::new(uuid.to_string(), sock, Arc::clone(&self.sessions));

                    let task_handle = tokio::spawn(async move { s.work().await });
                }
            }
        }
    }
}

#[async_trait]
pub trait MessageHandler {
    fn handle_chipertext(&mut self, data: Envelope);

    fn handle_exchange(&mut self, data: Envelope);

    async fn handle_pre_key(&mut self, data: Envelope);

    fn handle_receipt(&mut self, data: Envelope);
}

pub struct PreKeys {
    identity: Vec<u8>,
    pre_key: Vec<u8>,
    one_time_keys: Vec<Vec<u8>>,
}

#[derive(Debug)]
pub enum SessionError {
    /// no key available
    NoKeyAvailable(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            // TODO do useful stuff
            SessionError::NoKeyAvailable(ref e) => write!(f, "No key available: {}", e),
        }
    }
}

impl error::Error for SessionError {
    #[allow(deprecated)] // call to `description`
    fn description(&self) -> &str {
        match self {
            // TODO do useful stuff
            SessionError::NoKeyAvailable(ref e) => e,
        }
    }

    fn cause(&self) -> Option<&dyn error::Error> {
        match self {
            // TODO do useful stuff
            SessionError::NoKeyAvailable(e) => None,
        }
    }
}

/**
 * Session is a single TCP connection and exists for it's lifetime.
 *
 */
pub struct Session {
    session: String,
    transport: Framed<TcpStream, EnvelopeCodec>,
    sessions: Arc<DashMap<Vec<u8>, PreKeys>>,
}

impl ToString for Session {
    fn to_string(&self) -> String {
        self.session.clone()
    }
}

#[async_trait]
impl MessageHandler for Session {
    fn handle_chipertext(&mut self, data: Envelope) {}

    fn handle_exchange(&mut self, data: Envelope) {}

    async fn handle_pre_key(&mut self, data: Envelope) {
        match data.get_cmd() {
            Envelope_Command::UNKNOWN_CMD => {
                error!("Received unknown command from {}", &self.session);
            }
            Envelope_Command::PUBLISH => self.update_pre_key(data),
            Envelope_Command::REQUEST => self.publish_pre_key_bundle(data).await.unwrap(),
            Envelope_Command::SEND => (),
        }
    }

    fn handle_receipt(&mut self, data: Envelope) {
        // NOOP
    }
}

impl Session {
    pub fn new(peer: String, socket: TcpStream, sessions: Arc<DashMap<Vec<u8>, PreKeys>>) -> Session {
        let codec = EnvelopeCodec::new();
        let transport = Framed::new(socket, codec);

        Session { session: peer, transport, sessions }
    }

    fn update_pre_key(&mut self, mut data: Envelope) {
        let bundle = data.mut_content().mut_pre_key();

        let id = bundle.take_identity();
        let pre_key = bundle.take_prekey();
        let one_time_key = bundle.take_one_time_prekey();

        let pre_key_bundle = PreKeys { identity: id.clone(), pre_key, one_time_keys: one_time_key.into_vec() };

        self.sessions.insert(id.clone(), pre_key_bundle);

        debug!("Inserted pre key for {}", base64::encode(id));
    }

    async fn publish_pre_key_bundle(&mut self, mut data: Envelope) -> Result<(), Box<error::Error>> {
        let peer_id = data.take_peer().take_identity();

        debug!("Requested pre key for {}", base64::encode(peer_id.clone()));

        let mut pre_keys;
        match self.sessions.get_mut(&peer_id) {
            None => return Err(SessionError::NoKeyAvailable("No pre key bundle available".to_string()).into()),
            Some(v) => {
                pre_keys = v;
            }
        }

        let mut pre_key_bundle = PreKeyBundle::new();
        pre_key_bundle.set_identity(pre_keys.identity.clone());
        pre_key_bundle.set_prekey(pre_keys.pre_key.clone());

        let a = &mut pre_keys.one_time_keys;
        if a.len() > 1 {
            pre_key_bundle.mut_one_time_prekey().push(a.remove(0));
        }

        let mut payload = Payload::new();
        payload.set_pre_key(pre_key_bundle);

        let mut rmsg = Envelope::new();
        rmsg.set_cmd(Envelope_Command::SEND);
        rmsg.set_field_type(Envelope_Type::PREKEY_BUNDLE);
        rmsg.set_content(payload);

        self.transport.send(rmsg).await.map_err(Into::into)
    }

    pub async fn work(&mut self) {
        while let Some(msg) = self.transport.next().await {
            match msg {
                Err(e) => warn!("frame failed = {:?}", e),
                Ok(m) => {
                    let e: Envelope = m;

                    match e.get_field_type() {
                        Envelope_Type::UNKNOWN_TYPE => {
                            error!("Received unknown message from {}", &self.session);
                            continue;
                        }
                        Envelope_Type::KEY_EXCHANGE => self.handle_exchange(e),
                        Envelope_Type::PREKEY_BUNDLE => self.handle_pre_key(e).await,
                        Envelope_Type::RECEIPT => {
                            info!("Receipt message from {}", &self.session);
                            continue;
                        }
                        Envelope_Type::ATTESTATION => {
                            info!("ATTESTATION message from {}", &self.session);
                            continue;
                        }
                        Envelope_Type::CIPHERTEXT => self.handle_chipertext(e),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use crate::messages::Envelope_Type;

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
        let mut alice_transport = Framed::new(alice_stream, EnvelopeCodec::new());

        let bob_stream = TcpStream::connect("127.0.0.1:6142").await.unwrap();
        let mut bob_transport = Framed::new(bob_stream, EnvelopeCodec::new());

        let mut a_pub_pre_key = Envelope::new();
        a_pub_pre_key.set_cmd(Envelope_Command::PUBLISH);
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
