#[cfg(test)]
mod service_tests {
    use std::{
        sync::Arc,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use chrono::Utc;

    use mockall::predicate;

    use hive_commons::crypto;
    use hive_commons::model::{common, Encodable};

    use crate::persistence::*;

    use crate::service::AccountService;
    use crate::service::Accounts;

    #[test]
    fn verify_challenge_test() {
        let (client_private, _) = generate_credentials();

        let signed = prepare_signed_challenge(&client_private);

        let recycled_id = AccountService::verify_challenge(signed).unwrap();

        let public = client_private.id();
        assert_eq!(public, recycled_id);
    }

    #[test]
    fn verify_challenge_with_exceeded_timestamp_test() {
        let (client_private, _) = generate_credentials();

        let public = client_private.id();
        let challenge = common::signed_challenge::Challenge {
            identity: Some(public.into_peer()),
            timestamp: 0u64,
        };

        let buf: Vec<u8> = challenge.encode().unwrap();

        let signature = client_private.sign(&buf).unwrap();

        let signed = common::SignedChallenge {
            challenge: buf,
            signature,
        };

        let verify_result = AccountService::verify_challenge(signed);
        assert_eq!(
            Some(tonic::Code::DeadlineExceeded),
            verify_result.err().map(|s| s.code())
        );
    }

    #[test]
    fn verify_challenge_with_invalid_signature_test() {
        let (client_private, _) = generate_credentials();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap();

        let public = client_private.id();
        let challenge = common::signed_challenge::Challenge {
            identity: Some(public.into_peer()),
            timestamp: now,
        };

        let buf: Vec<u8> = challenge.encode().unwrap();

        let signed = common::SignedChallenge {
            challenge: buf,
            signature: vec![0u8, 0u8, 0u8],
        };

        let verify_result = AccountService::verify_challenge(signed);
        assert_eq!(
            Some(tonic::Code::PermissionDenied),
            verify_result.err().map(|s| s.code())
        );
    }

    #[tokio::test]
    async fn certificate_signing_and_update_test() {
        let account = entities::Account {
            id: i32::default(),
            public_key: "dummy_key".to_string(),
            timestamp: Utc::now(),
        };

        let mut mock = MockAccountsRepository::new();
        mock.expect_refresh_certificate()
            .with(predicate::eq(account.clone()), predicate::always())
            .times(1)
            .return_const(Ok(()));

        let (private, cert) = generate_credentials();
        let public_key = private.id().copy();

        let svc = AccountService::new(private, Arc::new(cert), Box::new(mock));

        svc.create_update_certificate(public_key, &account)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn create_account_for_unknown_id_test() {
        let account = entities::Account {
            id: i32::default(),
            public_key: "dummy_key".to_string(),
            timestamp: Utc::now(),
        };

        let mut mock = MockAccountsRepository::new();
        mock.expect_retrieve_account()
            .with(predicate::always())
            .times(1)
            .return_const(Err(RepositoryError::NotFound {
                message: "Err for test".to_string(),
            }));
        mock.expect_create_account()
            .with(predicate::always())
            .times(1)
            .return_const(Ok(account.clone()));
        mock.expect_refresh_certificate()
            .with(predicate::eq(account.clone()), predicate::always())
            .times(1)
            .return_const(Ok(()));

        let (private, cert) = generate_credentials();
        let svc = AccountService::new(private, Arc::new(cert), Box::new(mock));

        let (client_private, _) = generate_credentials();
        let signed = prepare_signed_challenge(&client_private);

        let response = svc.create_account(tonic::Request::new(signed)).await;

        assert!(response.is_ok());
    }

    #[tokio::test]
    async fn create_account_for_known_id_test() {
        let account = entities::Account {
            id: i32::default(),
            public_key: "dummy_key".to_string(),
            timestamp: Utc::now(),
        };

        let mut mock = MockAccountsRepository::new();
        mock.expect_retrieve_account()
            .with(predicate::always())
            .times(1)
            .return_const(Ok(account.clone()));
        mock.expect_create_account().with(predicate::never());
        mock.expect_refresh_certificate()
            .with(predicate::never(), predicate::never());

        let (private, cert) = generate_credentials();
        let svc = AccountService::new(private, Arc::new(cert), Box::new(mock));

        let (client_private, _) = generate_credentials();
        let signed = prepare_signed_challenge(&client_private);

        let response = svc.create_account(tonic::Request::new(signed)).await;

        assert_eq!(
            Some(tonic::Code::AlreadyExists),
            response.err().map(|s| s.code())
        );
    }

    #[tokio::test]
    async fn update_attestation_test() {
        //TODO
    }

    #[tokio::test]
    async fn update_pre_keys_test() {
        //TODO
    }

    #[tokio::test]
    async fn update_pre_keys_with_invalid_signature_test() {
        //TODO
    }

    #[tokio::test]
    async fn get_pre_keys_test() {
        //TODO
    }

    fn generate_credentials() -> (crypto::PrivateKey, crypto::Certificate) {
        let private_key = crypto::PrivateKey::generate().unwrap();

        let public_key = private_key.id().copy();

        let cert = crypto::CertificateFactory::default()
            .certified(public_key)
            .expiration(Duration::from_secs(1000))
            .self_sign(&private_key)
            .unwrap();

        (private_key, cert)
    }

    fn prepare_signed_challenge(client_private: &crypto::PrivateKey) -> common::SignedChallenge {
        // preparing client request
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap();

        let public = client_private.id();
        let challenge = common::signed_challenge::Challenge {
            identity: Some(public.into_peer()),
            timestamp: now,
        };

        let buf: Vec<u8> = challenge.encode().unwrap();

        let signature = client_private.sign(&buf).unwrap();

        common::SignedChallenge {
            challenge: buf,
            signature,
        }
    }
}
