use std::fmt;

mod interfaces;
mod grpc;

pub use interfaces::*;

use hive_crypto::PrivateKey;

pub struct Accounts<T> {
    wrapped: Box<T>,
}

#[async_trait::async_trait]
impl<T> AccountService for Accounts<T>
    where
        T: AccountService + fmt::Debug, {
    async fn update_attestation(&mut self, id: &PrivateKey) -> Result<(), AccountsError> {
        self.wrapped.update_attestation(id).await
    }
}
