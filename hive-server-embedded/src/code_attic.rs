use std::{error, io, fmt};

use std::ops::Fn;

//#################################################################################
//#################################################################################
//#################################################################################
#[derive(Debug)]
pub enum ExecutionContext {
    Mixed(Vec<ExecutionContext>),
    Tracer(String),
    Empty(),
}

impl ExecutionContext {
    pub fn put_tracer<F>(&self, mut consumer: F) -> Result<(), Box<dyn error::Error>>
        where F: FnMut(&String) -> Result<(), Box<dyn error::Error>> {
        return match self {
            ExecutionContext::Empty() => Ok(()),
            ExecutionContext::Tracer(t) => consumer(t),
            ExecutionContext::Mixed(ctxs) => {
                // do a search a single level deep for now
                for ctx in ctxs {
                    if let ExecutionContext::Tracer(inner) = ctx {
                        return consumer(inner);
                    }
                }
                Ok(())
            }
        };
    }
}

//#################################################################################
//#################################################################################
//#################################################################################

const METADATA_TRACE_KEY: &str = "tracer";

pub struct TracingAccountsWrapper<T> {
    wrapped: Box<T>,
}

impl<T> fmt::Debug for TracingAccountsWrapper<T>
    where
        T: AccountsServerTrait + fmt::Debug, {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // forward to inner
        self.wrapped.fmt(f)
    }
}

impl<T> TracingAccountsWrapper<T>
    where
        T: AccountsServerTrait + fmt::Debug, {
    pub fn new(to_be_wrapped: T) -> TracingAccountsWrapper<T> {
        TracingAccountsWrapper { wrapped: Box::new(to_be_wrapped) }
    }

    //TODO IMPROVE!!!
    fn extract_tracer<'b, B>(&self, request: &tonic::Request<B>) -> Span {
        let mut tracing_span;

        if let Some(e) = request.metadata().get(METADATA_TRACE_KEY) {
            let to_str_result = e.to_str();
            if to_str_result.is_ok() {
                tracing_span = span!(Level::ERROR, METADATA_TRACE_KEY, tracer=to_str_result.unwrap());
            } else {
                let mut msg = "Malformed tracer".to_string();
                if let Some(peer) = request.remote_addr() {
                    msg = format!("Malformed tracer from {}", peer);
                }
                tracing_span = span!(Level::ERROR, METADATA_TRACE_KEY, tracer=msg.as_str());
            }
        } else {
            let mut msg = "Missing tracer".to_string();
            if let Some(peer) = request.remote_addr() {
                msg = format!("Missing tracer from {}", peer);
            }

            tracing_span = span!(Level::ERROR, METADATA_TRACE_KEY, tracer=msg.as_str());
        }

        return tracing_span;
    }
}

#[async_trait::async_trait]
impl<T> AccountsServerTrait for TracingAccountsWrapper<T>
    where
        T: AccountsServerTrait + fmt::Debug, {
    async fn update_attestation(
        &self,
        request: tonic::Request<grpc::SignedChallenge>,
    ) -> Result<tonic::Response<grpc::SenderCertificate>, tonic::Status> {
        let span = self.extract_tracer(&request);
        let _guard = span.enter();

        self.wrapped.update_attestation(request).await
    }

    #[instrument]
    async fn check_attestation(
        &self,
        request: tonic::Request<grpc::SenderCertificate>,
    ) -> Result<tonic::Response<grpc::CheckResult>, tonic::Status> {
        let span = self.extract_tracer(&request);
        let _guard = span.enter();

        self.wrapped.check_attestation(request).await
    }

    #[instrument]
    async fn publish_pre_keys(
        &self,
        request: tonic::Request<grpc::PreKeyBundle>,
    ) -> Result<tonic::Response<grpc::PublishKeyResult>, tonic::Status> {
        let span = self.extract_tracer(&request);
        let _guard = span.enter();

        self.wrapped.publish_pre_keys(request).await
    }
}

pub fn build_server() -> impl AccountsServerTrait {
    let server_id = Arc::new(crypto::DalekEd25519PrivateId::generate().unwrap());

    let ids = Arc::new(crypto::SimpleDalekIdentities::new(Arc::clone(&server_id) as Arc<dyn PrivateIdentity>));
    let inner_accs = InMemoryAccounts { ids: Arc::clone(&ids) as Arc<dyn crypto::Identities> };
    return TracingAccountsWrapper::<InMemoryAccounts>::new(inner_accs);
}
