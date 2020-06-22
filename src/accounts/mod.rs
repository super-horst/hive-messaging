use crate::prelude::*;

use crate::crypto::PrivateIdentity;

mod interfaces;
mod rpc;
mod grpc;

use interfaces::*;
use rpc::*;

pub struct Accounts<T> {
    wrapped: Box<T>,
}

#[async_trait::async_trait]
impl<T> AccountService for Accounts<T>
    where
        T: AccountService + fmt::Debug, {
    async fn update_attestation(&mut self, id: &dyn PrivateIdentity) -> Result<(), AccountError> {
        self.wrapped.update_attestation(id).await
    }
}

