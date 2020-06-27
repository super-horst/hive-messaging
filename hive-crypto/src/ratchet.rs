use hkdf::Hkdf;
use sha2::Sha512;

use crate::error::*;
use crate::{PrivateKey, PublicKey};

pub struct DoubleRatchet {
    current_private: PrivateKey,
    current_other: PublicKey,

    root_chain: KdfChain,

    send_chain: CountingChain,
    recv_chain: CountingChain,
}

impl DoubleRatchet {
    pub fn initialise_to_send(root_key: &[u8; 32], other_public: &PublicKey)
                              -> Result<DoubleRatchet, CryptoError> {
        let init_private = PrivateKey::generate()?;

        let root_chain = KdfChain(root_key.clone());
        let send_chain = CountingChain::new(init_private.diffie_hellman(other_public));

        // leave the receiving chain detached
        Ok(DoubleRatchet {
            send_chain,
            recv_chain: CountingChain::new(root_key.clone()),
            root_chain,
            current_private: init_private,
            current_other: other_public.copy(),
        })
    }

    pub fn initialise_received(root_key: &[u8; 32], my_private: &PrivateKey, other_public: &PublicKey)
                               -> Result<DoubleRatchet, CryptoError> {
        let mut root_chain = KdfChain(root_key.clone());
        let recv_chain = CountingChain::new(my_private.diffie_hellman(other_public));

        let init_private = PrivateKey::generate()?;
        let init_dh = init_private.diffie_hellman(other_public);
        let send_chain = CountingChain::new(root_chain.update(&init_dh));

        Ok(DoubleRatchet {
            send_chain,
            recv_chain,
            root_chain,
            current_private: init_private,
            current_other: other_public.copy(),
        })
    }

    /// the DH ratchet's current public key
    pub fn current_public(&self) -> &PublicKey {
        self.current_private.id()
    }

    /// step the DH ratchet & cycle sending/receiving chains
    /// TODO handle lost steps
    pub fn asymmetric_step(&mut self, other_public: &PublicKey) -> Result<(), CryptoError> {
        if self.current_other == *other_public {
            // no update -> NOOP
            return Ok(());
        }

        let dh_current = self.current_private.diffie_hellman(other_public);

        self.recv_chain.reset(self.root_chain.update(&dh_current));

        let new_private = PrivateKey::generate()?;
        let dh_new = new_private.diffie_hellman(other_public);

        self.send_chain.reset(self.root_chain.update(&dh_new));

        self.current_private = new_private;
        self.current_other = other_public.copy();

        Ok(())
    }

    /// step the sending ratchet
    pub fn send_step(&mut self) -> (u64, [u8; 32]) {
        self.send_chain.update(&[0u8; 0])
    }

    /// step the receiving ratchet
    pub fn recv_step(&mut self) -> (u64, [u8; 32]) {
        self.recv_chain.update(&[0u8; 0])
    }
}


struct CountingChain {
    chain: KdfChain,
    counter: u64,
}

impl CountingChain {
    fn new(key: [u8; 32]) -> CountingChain {
        CountingChain {
            chain: KdfChain(key),
            counter: 0,
        }
    }

    fn update(&mut self, info: &[u8]) -> (u64, [u8; 32]) {
        let chain_key = self.chain.update(info);
        self.counter += 1;
        (self.counter, chain_key)
    }

    fn reset(&mut self, key: [u8; 32]) {
        self.chain.0 = key;
        self.counter = 0;
    }
}

struct KdfChain([u8; 32]);

impl KdfChain {
    /// update the secret and return the step's output
    fn update(&mut self, info: &[u8]) -> [u8; 32] {
        let h = Hkdf::<Sha512>::new(None, &self.0);

        let mut okm = [0u8; 64];
        // ignore the error, length should always match
        let _r = h.expand(info, &mut okm);

        let mut kdf_update = [0u8; 32];
        let mut output = [0u8; 32];

        kdf_update.clone_from_slice(&okm[..32]);
        output.clone_from_slice(&okm[32..]);

        self.0 = kdf_update;

        output
    }
}

#[cfg(test)]
pub mod ratchet_tests {
    use super::*;
    use crate::PrivateKey;
    use rand_core::RngCore;

    #[test]
    fn test_double_ratchet_interaction() {
        let a = PrivateKey::generate().unwrap();
        let b = PrivateKey::generate().unwrap();

        let root = a.diffie_hellman(b.id());


        // alice starts the conversation & sends bob her current ratchet key
        let mut alice = DoubleRatchet::initialise_to_send(&root, b.id()).unwrap();
        let mut bob = DoubleRatchet::initialise_received(&root, &b, alice.current_public()).unwrap();

        assert_eq!(alice.send_step(), bob.recv_step());
        assert_eq!(alice.send_step(), bob.recv_step());
        assert_eq!(alice.send_step(), bob.recv_step());

        // bob answers with his new ratchet key, which alice needs to include before processing the step
        alice.asymmetric_step(bob.current_public()).unwrap();
        assert_eq!(bob.send_step(), alice.recv_step());
        assert_eq!(bob.send_step(), alice.recv_step());
        assert_eq!(bob.send_step(), alice.recv_step());

        bob.asymmetric_step(alice.current_public()).unwrap();
        assert_eq!(alice.send_step(), bob.recv_step());

        alice.asymmetric_step(bob.current_public()).unwrap();

        alice.asymmetric_step(bob.current_public()).unwrap();
        bob.asymmetric_step(alice.current_public()).unwrap();
        assert_eq!(alice.send_step(), bob.recv_step());
    }

    #[test]
    fn test_kdf_chain_determinism() {
        use rand_core::OsRng;

        let mut initial_key = [0u8; 32];
        OsRng::default().fill_bytes(&mut initial_key[..]);

        let mut chain1 = KdfChain(initial_key.clone());
        let mut chain2 = KdfChain(initial_key.clone());

        let dummy_info = [0u8; 0];

        assert_eq!(chain1.update(&dummy_info), chain2.update(&dummy_info));
        assert_eq!(chain1.update(&dummy_info), chain2.update(&dummy_info));
        assert_eq!(chain1.update(&dummy_info), chain2.update(&dummy_info));
    }
}
