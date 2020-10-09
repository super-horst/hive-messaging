use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;

use crate::*;

pub struct CryptoStore {
    my_key: PrivateKey,
    my_cert: Arc<Certificate>,
    certificates: DashMap<PublicKey, Arc<Certificate>>,
    keys: DashMap<PublicKey, Arc<PrivateKey>>,
}

impl Identities for CryptoStore {
    fn resolve_id(&self, id: &[u8]) -> Result<PublicKey, CryptoError> {
        PublicKey::from_bytes(id)
    }

    fn my_id(&self) -> &PrivateKey {
        &self.my_key
    }

    fn my_certificate(&self) -> &Arc<Certificate> {
        &self.my_cert
    }

    fn known_private(&self, public: &PublicKey) -> Option<Arc<PrivateKey>> {
        self.keys.get(public).map(|f| Arc::clone(f.value()))
    }
}

/// build-a-cryptostore
pub struct CryptoStoreBuilder {
    my_key: Option<PrivateKey>,
    my_cert: Option<Arc<Certificate>>,
    known_certs: DashMap<PublicKey, Arc<Certificate>>,
    known_keys: DashMap<PublicKey, Arc<PrivateKey>>,
}

impl CryptoStoreBuilder {
    pub fn new() -> CryptoStoreBuilder {
        CryptoStoreBuilder {
            my_key: None,
            my_cert: None,
            known_certs: DashMap::new(),
            known_keys: DashMap::new(),
        }
    }

    pub fn my_key(mut self, key: PrivateKey) -> Self {
        self.my_key = Some(key);

        self
    }

    pub fn my_certificate(mut self, cert: Certificate) -> Self {
        self.my_cert = Some(Arc::new(cert));

        self
    }

    pub fn init_my_key(mut self, key_bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut key_buf = [0u8; 32];
        if key_buf.len() > key_bytes.len() {
            return Err(CryptoError::Message {
                message: format!("received invalid key format").to_string(),
            });
        }

        key_buf.copy_from_slice(key_bytes);

        self.my_key = Some(PrivateKey::from_bytes(&key_buf)?);

        Ok(self)
    }

    pub fn init_other_key(self, key_bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut key_buf = [0u8; 32];
        if key_buf.len() > key_bytes.len() {
            return Err(CryptoError::Message {
                message: format!("received invalid key format").to_string(),
            });
        }

        key_buf.copy_from_slice(key_bytes);

        let key = PrivateKey::from_bytes(&key_buf)?;

        self.known_keys.insert(key.id().copy(), Arc::new(key));

        Ok(self)
    }

    fn decode_chain_recursive<E>(
        &self,
        cert: E::CertificateType,
    ) -> Result<Arc<Certificate>, failure::Error>
    where
        E: CertificateEncoding,
    {
        let (mut cert, signer) = E::decode_partial(cert)?;

        if let Some(s) = signer {
            cert.infos.signer_certificate = Some(self.decode_chain_recursive::<E>(s)?);
        }

        let public = cert.public_key().copy();

        return if self.known_certs.contains_key(&public) {
            let entry = self.known_certs.get(&public).ok_or(CryptoError::Message {
                message: "illegal state".to_string(),
            })?;

            Ok(Arc::clone(entry.value()))
        } else {
            let arc_cert = Arc::new(cert);
            self.known_certs.insert(public, Arc::clone(&arc_cert));
            Ok(arc_cert)
        };
    }

    /// initialise my certificate from bytes
    pub fn init_my_certificate<E>(mut self, cert_bytes: &[u8]) -> Result<Self, CryptoError>
    where
        E: CertificateEncoding,
    {
        let raw_cert =
            E::deserialise(cert_bytes.to_vec()).map_err(|e| CryptoError::Unspecified {
                message: "failed to deserialise raw certificate".to_string(),
                cause: e,
            })?;
        let result =
            self.decode_chain_recursive::<E>(raw_cert)
                .map_err(|e| CryptoError::Unspecified {
                    message: "failed to deserialise raw certificate".to_string(),
                    cause: e,
                })?;

        self.my_cert = Some(result);

        Ok(self)
    }

    /// initialise my certificate from bytes
    pub fn init_other_certificate<E>(self, cert_bytes: &[u8]) -> Result<Self, CryptoError>
    where
        E: CertificateEncoding,
    {
        let raw_cert =
            E::deserialise(cert_bytes.to_vec()).map_err(|e| CryptoError::Unspecified {
                message: "failed to deserialise raw certificate".to_string(),
                cause: e,
            })?;

        let _result =
            self.decode_chain_recursive::<E>(raw_cert)
                .map_err(|e| CryptoError::Unspecified {
                    message: "failed to deserialise raw certificate".to_string(),
                    cause: e,
                })?;

        Ok(self)
    }

    pub fn build(self) -> Result<CryptoStore, CryptoError> {
        let my_key = self.my_key.ok_or(CryptoError::Message {
            message: "no private key given".to_string(),
        })?;

        // calculate expiration timestamp
        let my_cert = self.my_cert.ok_or(CryptoError::Message {
            message: "no certificate given".to_string(),
        })?;

        Ok(CryptoStore {
            my_key,
            my_cert,
            certificates: self.known_certs,
            keys: self.known_keys,
        })
    }
}

//TODO cleanup
#[cfg(feature = "storage")]
pub async fn load_private_key(path: &str) -> PrivateKey {
    use tokio::fs;
    use tokio::prelude::*;

    let f = fs::File::open(path).await;
    if f.is_ok() {
        let mut file = f.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        return PrivateKey::from_bytes(&contents[..]).unwrap();
    } else {
        let server_id = PrivateKey::generate().unwrap();

        let mut f = fs::File::create(path).await.unwrap();
        f.write_all(server_id.secret_bytes()).await.unwrap();

        return server_id;
    }
}

//TODO cleanup
#[cfg(feature = "storage")]
pub async fn load_certificate<T>(server_id: &PrivateKey, path: &str) -> Certificate
where
    T: CertificateEncoding,
{
    use tokio::fs;
    use tokio::prelude::*;

    let f = fs::File::open(path).await;
    if f.is_ok() {
        let mut file = f.unwrap();

        let mut contents = vec![];
        file.read_to_end(&mut contents).await.unwrap();

        let raw_cert = T::deserialise(contents).unwrap();

        let (cert, _) = T::decode_partial(raw_cert).unwrap();

        return cert;
    } else {
        let server_public = server_id.id().copy();

        let cert = CertificateFactory::default()
            .certified(server_public)
            .expiration(Duration::from_secs(1000))
            .self_sign::<T>(server_id)
            .unwrap();

        let mut f = fs::File::create(path).await.unwrap();
        f.write_all(&T::serialise(&cert).unwrap()[..])
            .await
            .unwrap();

        return cert;
    }
}

#[cfg(test)]
mod crypto_storage_tests {
    use super::*;
    use crate::certificates::certificate_tests;
    use crate::test_utils::GrpcCertificateEncoding;

    #[tokio::test]
    async fn test_builder_with_signed_cert() {
        let my_key = PrivateKey::generate().unwrap();

        let cert = certificate_tests::create_signed_cert();
        let cert_bytes = GrpcCertificateEncoding::serialise(&cert).unwrap();

        let csb = CryptoStoreBuilder::new()
            .init_my_key(my_key.secret_bytes())
            .unwrap()
            .init_my_certificate::<GrpcCertificateEncoding>(&cert_bytes[..])
            .unwrap();

        let store = csb.build().unwrap();

        println!("contains keys{:?}", &store.keys);
        println!("contains certs{:?}", &store.certificates);

        assert_eq!(store.my_id().secret_bytes(), my_key.secret_bytes());
        assert!(!store.certificates.is_empty());
        // signed certificate, so at least 2 certs
        assert!(store.certificates.len() > 1);
    }

    #[tokio::test]
    async fn test_builder_with_multiple_signed_cert() {
        let my_key = PrivateKey::generate().unwrap();

        let (cert1, cert2) = certificate_tests::create_two_signed_certs();
        let cert_bytes_1 = GrpcCertificateEncoding::serialise(&cert1).unwrap();
        let cert_bytes_2 = GrpcCertificateEncoding::serialise(&cert2).unwrap();

        let csb = CryptoStoreBuilder::new()
            .init_my_key(my_key.secret_bytes())
            .unwrap()
            .init_my_certificate::<GrpcCertificateEncoding>(&cert_bytes_1[..])
            .unwrap()
            .init_other_certificate::<GrpcCertificateEncoding>(&cert_bytes_2[..])
            .unwrap();

        let store = csb.build().unwrap();

        println!("contains keys{:?}", &store.keys);
        println!("contains certs{:?}", &store.certificates);

        assert_eq!(store.my_id().secret_bytes(), my_key.secret_bytes());
        assert!(!store.certificates.is_empty());
        // 2 leaf_certs & common signer
        assert_eq!(3, store.certificates.len());
    }

    #[tokio::test]
    async fn test_builder_with_self_signed_cert() {
        let my_key = PrivateKey::generate().unwrap();

        let cert = certificate_tests::create_self_signed_cert();
        let cert_bytes = GrpcCertificateEncoding::serialise(&cert).unwrap();

        let csb = CryptoStoreBuilder::new()
            .init_my_key(my_key.secret_bytes())
            .unwrap()
            .init_my_certificate::<GrpcCertificateEncoding>(&cert_bytes[..])
            .unwrap();

        let store = csb.build().unwrap();

        println!("contains keys{:?}", &store.keys);
        println!("contains certs{:?}", &store.certificates);

        assert_eq!(store.my_id().secret_bytes(), my_key.secret_bytes());
        assert!(!store.certificates.is_empty());
    }
}
