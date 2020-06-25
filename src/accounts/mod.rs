use crate::prelude::*;

use crate::crypto::PrivateIdentity;

mod interfaces;
mod grpc;

#[cfg(test)]
pub use grpc::GrpcCertificateEncoding;

pub use interfaces::*;

pub struct Accounts<T> {
    wrapped: Box<T>,
}

#[async_trait::async_trait]
impl<T> AccountService for Accounts<T>
    where
        T: AccountService + fmt::Debug, {
    async fn update_attestation(&mut self, id: &dyn PrivateIdentity) -> Result<(), AccountsError> {
        self.wrapped.update_attestation(id).await
    }
}
