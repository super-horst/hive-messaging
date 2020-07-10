use std::collections::HashSet;
use std::hash::{Hash, Hasher};

use hkdf::Hkdf;
use sha2::Sha512;

use serde::{Serialize, Deserialize};

use crate::error::*;
use crate::{PrivateKey, PublicKey};


/// a single sending ratchet step
#[derive(Debug)]
pub struct SendStep {
    pub counter: u64,
    pub prev_ratchet_counter: u64,
    pub secret: [u8; 32],
    pub ratchet_key: PublicKey,
}

/// a single receiving ratchet step
#[derive(Serialize, Deserialize, Debug)]
pub struct RecvStep {
    pub counter: u64,
    pub secret: [u8; 32],
    pub ratchet_key: PublicKey,
}

impl Hash for RecvStep {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // don't hash by secret
        state.write_u64(self.counter);
        self.ratchet_key.hash(state);
    }
}

impl std::cmp::PartialEq<RecvStep> for RecvStep {
    fn eq(&self, other: &Self) -> bool {
        if self.counter == other.counter {
            return self.ratchet_key == other.ratchet_key;
        }

        false
    }
}

impl Eq for RecvStep {}

/// manage a double ratchet and cache lost steps
#[derive(Serialize, Deserialize, Debug)]
pub struct ManagedRatchet {
    ratchet: DoubleRatchet,
    unused_keys: HashSet<RecvStep>,
}

impl ManagedRatchet {
    /// Initialise a ratchet prior to the first send
    pub fn initialise_to_send(root_key: &[u8; 32], other_public: &PublicKey)
                              -> Result<ManagedRatchet, CryptoError> {
        let ratchet = DoubleRatchet::initialise_to_send(root_key, other_public)?;

        Ok(ManagedRatchet {
            ratchet,
            unused_keys: HashSet::new(),
        })
    }

    /// Initialise a ratchet after the initial message is received
    pub fn initialise_received(root_key: &[u8; 32], my_private: &PrivateKey, other_public: PublicKey)
                               -> Result<ManagedRatchet, CryptoError> {
        let ratchet = DoubleRatchet::initialise_received(root_key, my_private, other_public)?;

        Ok(ManagedRatchet {
            ratchet,
            unused_keys: HashSet::new(),
        })
    }

    /// step the sending ratchet
    pub fn send_step(&mut self) -> SendStep {
        let (c, s) = self.ratchet.send_step();

        // my ratchet key
        SendStep {
            counter: c,
            prev_ratchet_counter: self.ratchet.prev_send_counter,
            ratchet_key: self.ratchet.current_public.copy(),
            secret: s,
        }
    }

    fn save_recv_until(&mut self, counter: u64) {
        while self.ratchet.recv_chain.1 < counter {
            let (counter, secret) = self.ratchet.recv_step();

            // save for later, mapped by other ratchet key
            self.unused_keys.insert(
                RecvStep {
                    counter,
                    ratchet_key: self.ratchet.current_other.copy(),
                    secret,
                });
        }
    }

    /// step the receiving ratchet
    pub fn recv_step_for(&mut self, ratchet_key: PublicKey, counter: u64, prev_counter: u64) -> Result<RecvStep, CryptoError> {
        // is it already saved?
        let step_dummy = RecvStep { counter, ratchet_key: ratchet_key.copy(), secret: [0u8; 32] };
        let unused = self.unused_keys.take(&step_dummy);
        if unused.is_some() {
            return Ok(unused.unwrap());
        }

        if ratchet_key != self.ratchet.current_other {
            self.save_recv_until(prev_counter);
        }

        self.ratchet.asymmetric_step(ratchet_key)?;

        self.save_recv_until(counter - 1);

        let (counter, secret) = self.ratchet.recv_step();

        // other ratchet key
        Ok(RecvStep {
            counter,
            ratchet_key: self.ratchet.current_other.copy(),
            secret,
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct DoubleRatchet {
    current_private: PrivateKey,
    current_public: PublicKey,

    current_other: PublicKey,

    root_chain: KdfChain,

    send_chain: CountingChain,
    prev_send_counter: u64,

    recv_chain: CountingChain,
}

impl DoubleRatchet {
    fn initialise_to_send(root_key: &[u8; 32], other_public: &PublicKey)
                          -> Result<DoubleRatchet, CryptoError> {
        let init_private = PrivateKey::generate()?;
        let init_public = init_private.id().copy();

        let root_chain = KdfChain(root_key.clone());
        let send_chain = CountingChain::new(init_private.diffie_hellman(other_public));

        Ok(DoubleRatchet {
            send_chain,
            prev_send_counter: 0,
            // leave the receiving chain detached
            // the next asymmetric step will sync all chains
            recv_chain: CountingChain::new([0u8; 32]),
            root_chain,
            current_private: init_private,
            current_public: init_public,
            current_other: other_public.copy(),
        })
    }

    fn initialise_received(root_key: &[u8; 32], my_private: &PrivateKey, other_public: PublicKey)
                           -> Result<DoubleRatchet, CryptoError> {
        let mut root_chain = KdfChain(root_key.clone());
        let recv_chain = CountingChain::new(my_private.diffie_hellman(&other_public));

        let init_private = PrivateKey::generate()?;
        let init_public = init_private.id().copy();

        let init_dh = init_private.diffie_hellman(&other_public);
        let send_chain = CountingChain::new(root_chain.update(&init_dh));

        Ok(DoubleRatchet {
            send_chain,
            prev_send_counter: 0,
            recv_chain,
            root_chain,
            current_private: init_private,
            current_public: init_public,
            current_other: other_public,
        })
    }

    /// step the DH ratchet & cycle sending/receiving chains
    fn asymmetric_step(&mut self, other_public: PublicKey) -> Result<(), CryptoError> {
        if self.current_other == other_public {
            // no update -> NOOP
            return Ok(());
        }

        let dh_current = self.current_private.diffie_hellman(&other_public);

        self.recv_chain.reset(self.root_chain.update(&dh_current));

        let new_private = PrivateKey::generate()?;
        let dh_new = new_private.diffie_hellman(&other_public);

        self.prev_send_counter = self.send_chain.1;
        self.send_chain.reset(self.root_chain.update(&dh_new));

        self.current_public = new_private.id().copy();
        self.current_private = new_private;
        self.current_other = other_public;

        Ok(())
    }

    /// step the sending ratchet
    fn send_step(&mut self) -> (u64, [u8; 32]) {
        self.send_chain.update()
    }

    /// step the receiving ratchet
    fn recv_step(&mut self) -> (u64, [u8; 32]) {
        self.recv_chain.update()
    }
}

/// 1-based counting chain
#[derive(Serialize, Deserialize, Debug)]
struct CountingChain([u8; 32], u64);

impl CountingChain {
    fn new(key: [u8; 32]) -> CountingChain {
        CountingChain(key, 0)
    }

    fn update(&mut self) -> (u64, [u8; 32]) {
        let h = Hkdf::<Sha512>::new(None, &self.0);

        let mut okm = [0u8; 64];
        // ignore the error, length should always match
        let _r = h.expand(&[0u8; 32], &mut okm);

        let mut kdf_update = [0u8; 32];
        let mut output = [0u8; 32];

        kdf_update.clone_from_slice(&okm[..32]);
        output.clone_from_slice(&okm[32..]);

        self.0 = kdf_update;
        self.1 += 1;

        (self.1, output)
    }

    fn reset(&mut self, key: [u8; 32]) {
        self.0 = key;
        self.1 = 0;
    }
}

/// simple HKDF chain
#[derive(Serialize, Deserialize, Debug)]
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

    fn entangled_ratchets() -> (DoubleRatchet, DoubleRatchet) {
        let a = PrivateKey::generate().unwrap();
        let b = PrivateKey::generate().unwrap();

        let root = a.diffie_hellman(b.id());

        // alice starts the conversation & sends bob her current ratchet key
        let alice = DoubleRatchet::initialise_to_send(&root, b.id()).unwrap();
        let bob = DoubleRatchet::initialise_received(&root, &b, alice.current_public.copy()).unwrap();

        (alice, bob)
    }

    #[test]
    fn test_ratchet_manager_lost_messages_across_multiple_ratchet_keys() {
        let (alice, bob) = entangled_ratchets();

        let mut alice_mgmt = ManagedRatchet { ratchet: alice, unused_keys: HashSet::new() };
        let mut bob_mgmt = ManagedRatchet { ratchet: bob, unused_keys: HashSet::new() };

        let a1 = alice_mgmt.send_step();
        let b1 = bob_mgmt.recv_step_for(a1.ratchet_key.copy(), a1.counter, alice_mgmt.ratchet.prev_send_counter).unwrap();
        assert_eq!(a1.secret, b1.secret);

        let b1 = bob_mgmt.send_step();
        let a1 = alice_mgmt.recv_step_for(b1.ratchet_key.copy(), b1.counter, bob_mgmt.ratchet.prev_send_counter).unwrap();
        assert_eq!(a1.secret, b1.secret);

        let a2 = alice_mgmt.send_step();
        let a3 = alice_mgmt.send_step();
        let a4 = alice_mgmt.send_step();

        // "loose" a2 & a3
        let b4 = bob_mgmt.recv_step_for(a4.ratchet_key.copy(), a4.counter, alice_mgmt.ratchet.prev_send_counter).unwrap();

        assert_eq!(a4.secret, b4.secret);

        let b5 = bob_mgmt.send_step();
        let b6 = bob_mgmt.send_step();
        let b7 = bob_mgmt.send_step();

        // "loose" b5 & b6
        let a7 = alice_mgmt.recv_step_for(b7.ratchet_key.copy(), b7.counter, b7.prev_ratchet_counter).unwrap();

        assert_eq!(a7.secret, b7.secret);

        // recover "lost" keys
        let b2 = bob_mgmt.recv_step_for(a2.ratchet_key.copy(), a2.counter, a2.prev_ratchet_counter).unwrap();
        let b3 = bob_mgmt.recv_step_for(a3.ratchet_key.copy(), a3.counter, a3.prev_ratchet_counter).unwrap();

        let a5 = alice_mgmt.recv_step_for(b5.ratchet_key.copy(), b5.counter, b5.prev_ratchet_counter).unwrap();
        let a6 = alice_mgmt.recv_step_for(b6.ratchet_key.copy(), b6.counter, b6.prev_ratchet_counter).unwrap();

        assert_eq!(a2.secret, b2.secret);
        assert_eq!(a3.secret, b3.secret);
        assert_eq!(a5.secret, b5.secret);
        assert_eq!(a6.secret, b6.secret);

        // key caches should be empty
        assert_eq!(0, bob_mgmt.unused_keys.len());
        assert_eq!(0, alice_mgmt.unused_keys.len());
    }

    #[test]
    fn test_ratchet_manager_lost_messages() {
        let (alice, bob) = entangled_ratchets();

        let mut alice_mgmt = ManagedRatchet { ratchet: alice, unused_keys: HashSet::new() };
        let mut bob_mgmt = ManagedRatchet { ratchet: bob, unused_keys: HashSet::new() };

        let a1 = alice_mgmt.send_step();
        let b1 = bob_mgmt.recv_step_for(a1.ratchet_key.copy(), a1.counter, a1.prev_ratchet_counter).unwrap();
        assert_eq!(a1.secret, b1.secret);

        let a2 = alice_mgmt.send_step();
        let a3 = alice_mgmt.send_step();
        let a4 = alice_mgmt.send_step();

        // "loose" a2 & a3
        let b4 = bob_mgmt.recv_step_for(a4.ratchet_key.copy(), a4.counter, a4.prev_ratchet_counter).unwrap();

        assert_eq!(a4.secret, b4.secret);

        let b2 = bob_mgmt.recv_step_for(a2.ratchet_key.copy(), a2.counter, a2.prev_ratchet_counter).unwrap();
        let b3 = bob_mgmt.recv_step_for(a3.ratchet_key.copy(), a3.counter, a3.prev_ratchet_counter).unwrap();

        assert_eq!(a2.secret, b2.secret);
        assert_eq!(a3.secret, b3.secret);
    }

    #[test]
    fn test_ratchet_manager_linear_operation() {
        let (alice, bob) = entangled_ratchets();

        let mut alice_mgmt = ManagedRatchet { ratchet: alice, unused_keys: HashSet::new() };
        let mut bob_mgmt = ManagedRatchet { ratchet: bob, unused_keys: HashSet::new() };

        let a1 = alice_mgmt.send_step();
        let b1 = bob_mgmt.recv_step_for(a1.ratchet_key.copy(), a1.counter, a1.prev_ratchet_counter).unwrap();

        assert_eq!(a1.secret, b1.secret);

        let b2 = bob_mgmt.send_step();
        let a2 = alice_mgmt.recv_step_for(b2.ratchet_key.copy(), b2.counter, b2.prev_ratchet_counter).unwrap();

        assert_eq!(a2.secret, b2.secret);

        let a3 = alice_mgmt.send_step();
        let a4 = alice_mgmt.send_step();
        let a5 = alice_mgmt.send_step();

        let b3 = bob_mgmt.recv_step_for(a3.ratchet_key.copy(), a3.counter, a3.prev_ratchet_counter).unwrap();
        let b4 = bob_mgmt.recv_step_for(a4.ratchet_key.copy(), a4.counter, a4.prev_ratchet_counter).unwrap();
        let b5 = bob_mgmt.recv_step_for(a5.ratchet_key.copy(), a5.counter, a5.prev_ratchet_counter).unwrap();

        assert_eq!(a3.secret, b3.secret);
        assert_eq!(a4.secret, b4.secret);
        assert_eq!(a5.secret, b5.secret);
    }

    #[test]
    fn test_double_ratchet_interaction() {
        let (mut alice, mut bob) = entangled_ratchets();

        assert_eq!(alice.send_step(), bob.recv_step());
        assert_eq!(alice.send_step(), bob.recv_step());
        assert_eq!(alice.send_step(), bob.recv_step());

        // bob answers with his new ratchet key, which alice needs to include before processing the step
        alice.asymmetric_step(bob.current_public.copy()).unwrap();
        assert_eq!(bob.send_step(), alice.recv_step());
        assert_eq!(bob.send_step(), alice.recv_step());
        assert_eq!(bob.send_step(), alice.recv_step());

        bob.asymmetric_step(alice.current_public.copy()).unwrap();
        assert_eq!(alice.send_step(), bob.recv_step());

        alice.asymmetric_step(bob.current_public.copy()).unwrap();

        alice.asymmetric_step(bob.current_public.copy()).unwrap();
        bob.asymmetric_step(alice.current_public.copy()).unwrap();
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
