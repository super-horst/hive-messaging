use x25519_dalek::*;
use hkdf::*;
use sha2::Sha256;
use rand_core::OsRng;

//TODO initial implementation is not ready for production!

// max dh buffer size needed
const DH_BUFFER_SIZE: usize = 128;

pub struct DhKeyPair<'a> {
    mine: &'a StaticSecret,
    other: &'a PublicKey,
}

impl<'a> DhKeyPair<'a> {
    pub fn mine_dh(&self, public_key: &PublicKey) -> SharedSecret {
        self.mine.diffie_hellman(public_key)
    }

    pub fn other_dh(&self, private_key: &StaticSecret) -> SharedSecret {
        private_key.diffie_hellman(&self.other)
    }
}

pub fn x3dh_agree_initial(identities: &DhKeyPair,
                          pre_key: &PublicKey,
                          onetime_pre_key: Option<PublicKey>) -> (PublicKey, [u8; 32]) {
    // static secret but ephemeral
    let eph = StaticSecret::new(&mut OsRng);

    let dh1 = identities.mine_dh(&pre_key);
    let dh2 = identities.other_dh(&eph);
    let dh3 = eph.diffie_hellman(&pre_key);

    let mut dh = Vec::with_capacity(DH_BUFFER_SIZE);
    dh.extend_from_slice(dh1.as_bytes());
    dh.extend_from_slice(dh2.as_bytes());
    dh.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = onetime_pre_key {
        let dh4 = eph.diffie_hellman(&opk);

        dh.extend_from_slice(dh4.as_bytes());
    }

    // shrink buffer if necessary
    dh.shrink_to_fit();

    let h = Hkdf::<Sha256>::new(None, &dh);
    let mut okm = [0u8; 32];
    h.expand(&[0u8; 0], &mut okm).unwrap();

    return (PublicKey::from(&eph), okm);
}

pub fn x3dh_agree_respond(identities: &DhKeyPair,
                          ephemeral_key: &PublicKey,
                          pre_key: &StaticSecret,
                          onetime_pre_key: Option<StaticSecret>) -> [u8; 32] {
    let dh1 = identities.other_dh(&pre_key);
    let dh2 = identities.mine_dh(&ephemeral_key);
    let dh3 = pre_key.diffie_hellman(&ephemeral_key);

    let mut dh = Vec::with_capacity(DH_BUFFER_SIZE);
    dh.extend_from_slice(dh1.as_bytes());
    dh.extend_from_slice(dh2.as_bytes());
    dh.extend_from_slice(dh3.as_bytes());

    if let Some(opk) = onetime_pre_key {
        let dh4 = opk.diffie_hellman(&ephemeral_key);

        dh.extend_from_slice(dh4.as_bytes());
    }

    // shrink buffer if necessary
    dh.shrink_to_fit();

    let h = Hkdf::<Sha256>::new(None, &dh);
    let mut okm = [0u8; 32];
    h.expand(&[0u8; 0], &mut okm).unwrap();

    return okm;
}

#[cfg(test)]
mod crypto_tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_dh_without_onetimekey() {
        let a_priv = StaticSecret::new(&mut OsRng);
        let a_pub = PublicKey::from(&a_priv);

        let b_priv = StaticSecret::new(&mut OsRng);
        let b_pub = PublicKey::from(&b_priv);

        let pre_key_priv = StaticSecret::new(&mut OsRng);
        let pre_key_pub = PublicKey::from(&pre_key_priv);

        let from_a = DhKeyPair { mine: &a_priv, other: &b_pub };
        let from_b = DhKeyPair { mine: &b_priv, other: &a_pub };

        let (eph_pub, dh1) = x3dh_agree_initial(&from_a, &pre_key_pub, None);
        let dh2 = x3dh_agree_respond(&from_b, &eph_pub, &pre_key_priv, None);

        assert_eq!(dh1, dh2);
    }

    #[test]
    fn test_dh_with_onetimekey() {
        let a_priv = StaticSecret::new(&mut OsRng);
        let a_pub = PublicKey::from(&a_priv);

        let b_priv = StaticSecret::new(&mut OsRng);
        let b_pub = PublicKey::from(&b_priv);

        let pre_key_priv = StaticSecret::new(&mut OsRng);
        let pre_key_pub = PublicKey::from(&pre_key_priv);

        let otk_priv = StaticSecret::new(&mut OsRng);
        let otk_pub = PublicKey::from(&otk_priv);

        let from_a = DhKeyPair { mine: &a_priv, other: &b_pub };
        let from_b = DhKeyPair { mine: &b_priv, other: &a_pub };

        let (eph_pub, dh1) = x3dh_agree_initial(&from_a, &pre_key_pub, Some(otk_pub));
        let dh2 = x3dh_agree_respond(&from_b, &eph_pub, &pre_key_priv, Some(otk_priv));

        assert_eq!(dh1, dh2);
    }
}