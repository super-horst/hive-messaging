use std::sync::Arc;

use dashmap::DashMap;

use crate::*;

pub struct CryptoStore {
    certificates: DashMap<PublicKey, Arc<Certificate>>,
    keys: DashMap<PublicKey, PrivateKey>,
}

impl CryptoStore {
    pub fn new() -> CryptoStore {
        CryptoStore {
            certificates: DashMap::new(),
            keys: DashMap::new(),
        }
    }

    pub async fn init_key(&self, contents: &[u8]) -> Result<(), CryptoError> {
        let mut key_buf = [0u8; 32];
        if key_buf.len() > contents.len() {
            return Err(CryptoError::Message {
                message: format!("received invalid key format").to_string(),
            });
        }

        key_buf.copy_from_slice(contents);

        let private = PrivateKey::from_raw_bytes(key_buf)?;
        let public = private.id().copy();

        self.keys.insert(public, private);

        Ok(())
    }

    fn decode_chain_recursive<E>(&self, cert: E::CertificateType) -> Result<Arc<Certificate>, CryptoError>
        where E: CertificateEncoding {
        let (mut cert, signer) = E::decode_partial(cert)?;

        if let Some(s) = signer {
            cert.infos.signer_certificate = Some(self.decode_chain_recursive::<E>(s)?);
        }

        let arc_cert = Arc::new(cert);
        let public = arc_cert.public_key().copy();

        self.certificates.insert(public, Arc::clone(&arc_cert));

        Ok(arc_cert)
    }

    pub async fn init_certificate<E>(&self, contents: &[u8]) -> Result<(), CryptoError>
        where E: CertificateEncoding {
        let raw_cert = E::deserialise(contents.to_vec())?;
        let _result = self.decode_chain_recursive::<E>(raw_cert)?;

        Ok(())
    }
}

#[cfg(test)]
mod crypto_storage_tests {
    use std::time::Duration;

    use tokio::fs::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::test_utils::GrpcCertificateEncoding;


    const CERTFILE: &'static str = "target/testcert.cert";
    const KEYFILE: &'static str = "target/testkey.key";

    #[tokio::test]
    async fn test_init_key() {
        let _r  = remove_file(KEYFILE).await;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(KEYFILE)
            .await.unwrap();

        let key = PrivateKey::generate().unwrap();

        file.write_all(key.secret_bytes()).await.unwrap();
        std::mem::drop(file);

        let mut file = File::open(KEYFILE).await.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let store = CryptoStore::new();
        store.init_key(&contents[..]).await.unwrap();

        println!("contains {:?}", &store.keys);

        assert!(!store.keys.is_empty());
    }

    #[tokio::test]
    async fn test_init_cert_without_signer() {
        let _r  = remove_file(CERTFILE).await;

        let key = PrivateKey::generate().unwrap();

        let cert = CertificateFactory::default()
            .certified(key.id().copy())
            .expiration(Duration::from_secs(1000)).self_sign::<GrpcCertificateEncoding>(&key).unwrap();

        let cert_bytes = GrpcCertificateEncoding::serialise(&cert).unwrap();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(CERTFILE)
            .await.unwrap();

        file.write_all(&cert_bytes[..]).await.unwrap();

        std::mem::drop(file);

        let mut file = File::open(CERTFILE).await.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let store = CryptoStore::new();
        store.init_certificate::<GrpcCertificateEncoding>(&contents[..]).await.unwrap();

        println!("contains {:?}", &store.certificates);

        assert!(!store.certificates.is_empty());

        let mut contains_signer = false;
        for (_, ref entry) in store.certificates {
            contains_signer |= entry.infos.signer_certificate.is_some();
        }

        assert!(!contains_signer);
    }

    #[tokio::test]
    async fn test_init_cert_with_signer() {
        let _r  = remove_file(CERTFILE).await;

        let signer_key = PrivateKey::generate().unwrap();

        let signer_cert = CertificateFactory::default()
            .certified(signer_key.id().copy())
            .expiration(Duration::from_secs(1000))
            .self_sign::<GrpcCertificateEncoding>(&signer_key).map(Arc::new).unwrap();

        let leaf_key = PrivateKey::generate().unwrap();

        let leaf_cert = CertificateFactory::default()
            .certified(leaf_key.id().copy())
            .expiration(Duration::from_secs(1000))
            .sign::<GrpcCertificateEncoding>(&signer_key, Some(&signer_cert)).unwrap();

        let cert_bytes = GrpcCertificateEncoding::serialise(&leaf_cert).unwrap();

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(CERTFILE)
            .await.unwrap();

        file.write_all(&cert_bytes[..]).await.unwrap();

        std::mem::drop(file);

        let mut file = File::open(CERTFILE).await.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let store = CryptoStore::new();
        store.init_certificate::<GrpcCertificateEncoding>(&contents[..]).await.unwrap();

        println!("contains {:?}", &store.certificates);

        assert!(!store.certificates.is_empty());

        let mut contains_signer = false;
        for (_, ref entry) in store.certificates {
            contains_signer |= entry.infos.signer_certificate.is_some();
        }

        assert!(contains_signer);
    }
}
