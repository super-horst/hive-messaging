mod messages;
mod accounts;

use env_logger;

use std::{error::Error, io};
use tracing::{debug, error, info, span, warn, Level};
fn main() {

    /*env_logger::builder()
        .format(|buf, record| {
            writeln!(buf, "{}: {}", record.level(), record.args())
        })
        .init();#*/


    shave(5).unwrap();
}


#[tracing::instrument]
pub fn shave(yak: usize) -> Result<(), Box<dyn Error + 'static>> {

    debug!(excitement = "yay!", "hello! I'm gonna shave a yak.");
    if yak == 3 {
        warn!("could not locate yak!");
        return Err(io::Error::new(io::ErrorKind::Other, "shaving yak failed!").into());
    } else {
        debug!("yak shaved successfully");
    }
    Ok(())
}

pub fn shave_all(yaks: usize) -> usize {
    let span = span!(Level::TRACE, "shaving_yaks", yaks);
    let _enter = span.enter();

    info!("shaving yaks");

    let mut yaks_shaved = 0;
    for yak in 1..=yaks {
        let res = shave(yak);
        debug!(yak, shaved = res.is_ok());

        if let Err(ref error) = res {
            error!(yak, error = error.as_ref(), "failed to shave yak!");
        } else {
            yaks_shaved += 1;
        }
        debug!(yaks_shaved);
    }

    yaks_shaved
}



/*#[tokio::main]
async fn main() {
    simple_logger::init().unwrap();

    let addr = "127.0.0.1:6142";
    let ctx = TransportContextBuilder::default().address(addr.to_string()).server();

    let server = {
        async move { ctx.work().await }
    };

    info!("Server running on {}", addr);

    // Start the server and block this async fn until `server` spins down.
    server.await;
}*/


/*
#[async_trait]
pub trait MessageHandler {
    fn handle_chipertext(&mut self, data: Envelope);

    fn handle_exchange(&mut self, data: Envelope);

    async fn handle_pre_key(&mut self, data: Envelope);

    fn handle_receipt(&mut self, data: Envelope);
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


#[async_trait]
impl MessageHandler for Session {
    fn handle_chipertext(&mut self, data: Envelope) {}

    fn handle_exchange(&mut self, data: Envelope) {}

    async fn handle_pre_key(&mut self, data: Envelope) {
        match data.get_cmd() {
            Envelope_Command::UNKNOWN_CMD => {
                error!("Received unknown command from {}", &self.session);
            }
            Envelope_Command::SEND => self.update_pre_key(data),
            Envelope_Command::REQUEST => self.publish_pre_key_bundle(data).await.unwrap(),
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

    async fn publish_pre_key_bundle(&mut self, mut data: Envelope) -> Result<(), Box<dyn error::Error>> {
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
*/