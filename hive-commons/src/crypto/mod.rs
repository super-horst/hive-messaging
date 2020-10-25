use std::sync::Arc;

mod error;
pub use error::*;

mod keys;
pub use keys::{FromBytes, PrivateKey, PublicKey};

mod certificates;
pub use certificates::{Certificate, CertificateFactory, CertificateInfoBundle};

mod cryptostorage;
pub use cryptostorage::*;

mod x3dh;
pub use x3dh::*;

mod ratchet;
pub use ratchet::{ManagedRatchet, RecvStep, SendStep};

pub mod signing;

/// Identity provider
/// TODO obsolete
pub trait Identities: Send + Sync {
    /// resolve identity from the given bytes
    fn resolve_id(&self, id: &[u8]) -> Result<PublicKey, CryptoError>;

    /// the current main identity
    fn my_id(&self) -> &PrivateKey;

    /// the current main identity
    fn my_certificate(&self) -> &Arc<Certificate>;

    /// is there any known private key
    fn known_private(&self, public: &PublicKey) -> Option<Arc<PrivateKey>>;
}
