use crate::*;

use hkdf::Hkdf;
use sha2::Sha256;

// max dh buffer size needed
const DH_BUFFER_SIZE: usize = 128;

pub fn x3dh_agree_initial(ik_a: &PrivateKey,
                          ik_b: &PublicKey,
                          pre_key: &PublicKey,
                          onetime_pre_key: Option<PublicKey>) -> (PublicKey, [u8; 32]) {
    let ek_a = PrivateKey::generate().unwrap();

    let dh1 = ik_a.diffie_hellman(pre_key);
    let dh2 = ek_a.diffie_hellman(ik_b);
    let dh3 = ek_a.diffie_hellman(pre_key);

    let mut dh = Vec::with_capacity(DH_BUFFER_SIZE);
    dh.extend_from_slice(&dh1[..]);
    dh.extend_from_slice(&dh2[..]);
    dh.extend_from_slice(&dh3[..]);

    if let Some(opk) = onetime_pre_key {
        let dh4 = ek_a.diffie_hellman(&opk);

        dh.extend_from_slice(&dh4[..]);
    }

// shrink buffer if necessary
    dh.shrink_to_fit();

    let h = Hkdf::<Sha256>::new(None, &dh);
    let mut okm = [0u8; 32];
    h.expand(&[0u8; 0], &mut okm).unwrap();

    return (ek_a.id().copy(), okm);
}

pub fn x3dh_agree_respond(ik_a: &PublicKey,
                          ik_b: &PrivateKey,
                          ek_a: &PublicKey,
                          pre_key: &PrivateKey,
                          onetime_pre_key: Option<PrivateKey>) -> [u8; 32] {
    let dh1 = pre_key.diffie_hellman(&ik_a);
    let dh2 = ik_b.diffie_hellman(ek_a);
    let dh3 = pre_key.diffie_hellman(ek_a);

    let mut dh = Vec::with_capacity(DH_BUFFER_SIZE);
    dh.extend_from_slice(&dh1[..]);
    dh.extend_from_slice(&dh2[..]);
    dh.extend_from_slice(&dh3[..]);

    if let Some(opk) = onetime_pre_key {
        let dh4 = opk.diffie_hellman(&ek_a);

        dh.extend_from_slice(&dh4[..]);
    }

    // shrink buffer if necessary
    dh.shrink_to_fit();

    let h = Hkdf::<Sha256>::new(None, &dh);
    let mut okm = [0u8; 32];
    h.expand(&[0u8; 0], &mut okm).unwrap();

    return okm;
}


#[cfg(test)]
mod x3dh_tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_dh_without_onetimekey() {
        let ik_a = PrivateKey::generate().unwrap();
        let ik_b = PrivateKey::generate().unwrap();
        let pre_key = PrivateKey::generate().unwrap();

        let (eph_pub, dh1) = x3dh_agree_initial(&ik_a, ik_b.id(), pre_key.id(), None);
        let dh2 = x3dh_agree_respond(&ik_a.id(), &ik_b, &eph_pub, &pre_key, None);

        assert_eq!(dh1, dh2);
    }

    #[test]
    fn test_dh_with_onetimekey() {
        let ik_a = PrivateKey::generate().unwrap();
        let ik_b = PrivateKey::generate().unwrap();
        let pre_key = PrivateKey::generate().unwrap();
        let opk = PrivateKey::generate().unwrap();

        let (eph_pub, dh1) = x3dh_agree_initial(&ik_a, ik_b.id(), pre_key.id(), Some(opk.id().copy()));
        let dh2 = x3dh_agree_respond(&ik_a.id(), &ik_b, &eph_pub, &pre_key, Some(opk));

        assert_eq!(dh1, dh2);
    }
}
