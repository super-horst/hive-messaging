use std::time::Duration;

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::futures_0_3::{spawn_local, JsFuture};
use wasm_timer::Delay;

use yew::Callback;

use log::*;

use hive_commons::crypto::{CertificateFactory, FromBytes, PublicKey, Signer};
use hive_commons::{model, protocol};

use crate::bindings::msg_svc_bindings;
use crate::ctrl::{Contact, ContactManager, ControllerError, IdentityController};
use crate::transport::ConnectionManager;

#[derive(Clone)]
pub struct MessagingController {
    identity: IdentityController,
    contacts: ContactManager,
    transport: ConnectionManager,
    incoming_payload: Callback<model::messages::Payload>,
}

impl MessagingController {
    pub fn new(
        on_error: Callback<String>,
        identity: IdentityController,
        contacts: ContactManager,
        transport: ConnectionManager,
        incoming_payload: Callback<model::messages::Payload>,
    ) -> MessagingController {
        let msg_ctrl = MessagingController { identity, contacts, transport, incoming_payload };

        let cloned = msg_ctrl.clone();
        spawn_local(async move { cloned.message_polling(on_error).await; });

        return msg_ctrl;
    }

    async fn message_polling(&self, on_error: Callback<String>) {
        let my_id = self.identity.public_key().clone();
        loop {
            if let Err(error) = self.poll_and_forward_message(&my_id).await {
                on_error.emit(format!("Failed to poll messages {:?}", error));
                error!("Failed to poll messages {:?}", error);
            }
        }
    }

    async fn poll_and_forward_message(&self, my_id: &PublicKey) -> Result<(), ControllerError> {
        if let Err(cause) = Delay::new(Duration::from_secs(2)).await {
            return Err(ControllerError::IOError { cause });
        };

        let filter = msg_svc_bindings::MessageFilter::new();
        filter.setState(msg_svc_bindings::MessageFilterState::NEW);
        filter.setDst(my_id.into_peer().into());

        let promise = self.transport.messages().getMessages(filter);
        match JsFuture::from(promise).await {
            Ok(value) => {
                let envelope: msg_svc_bindings::Envelope =
                    value.dyn_into().map_err(|e| {
                        ControllerError::Message {
                            message: e.as_string().unwrap_or("Unknown error during message conversion".to_string())
                        }
                    })?;

                self.incoming_message(envelope).await
            }
            Err(cause) => {
                Err(ControllerError::Message {
                    message: cause.as_string().unwrap_or("Unknown error retrieving messages".to_string())
                })
            }
        }
    }

    async fn incoming_message(
        &self,
        envelope: msg_svc_bindings::Envelope,
    ) -> Result<(), ControllerError> {
        let eph_key = PublicKey::from_bytes(&envelope.getEphemeralSessionKey_asU8().to_vec())
            .map_err(|cause| ControllerError::CryptographicError {
                message: "Failed to decode ephemeral session key".to_string(),
                cause,
            })?;
        let session_params = protocol::decrypt_session(
            &self.identity,
            eph_key,
            &envelope.getEncryptedSession_asU8().to_vec(),
        )
            .map_err(|cause| ControllerError::ProtocolExecution {
                message: "Failed to decrypt session".to_string(),
                cause,
            })?;

        // TODO check signer
        let cert = session_params.origin.as_ref().ok_or_else(|| ControllerError::Message {
            message: "Missing certificate in session parameters".to_string(),
        })?;
        let (cert, _signer) = CertificateFactory::decode(cert).map_err(|cause| {
            ControllerError::CryptographicError {
                message: "Failed to decode peer certificate".to_string(),
                cause,
            }
        })?;

        // TODO blocking in async
        let contact = self.contacts.access_contact(cert.public_key())?;

        let payload = contact
            .incoming_message(session_params, &envelope.getEncryptedPayload_asU8().to_vec())
            .await
            .map_err(|cause| ControllerError::ProtocolExecution {
                message: "Failed to decrypt incoming message".to_string(),
                cause,
            })?;

        self.incoming_payload.emit(payload);

        Ok(())
    }

    pub async fn outgoing_message(
        &self,
        contact: &Contact,
        payload: &model::messages::Payload,
    ) -> Result<(), ControllerError> {
        let (mut session_params, encrypted_payload) = contact
            .outgoing_message(&payload)
            .await
            .map_err(|cause| ControllerError::ProtocolExecution {
                message: "Failed to encrypt outgoing message".to_string(),
                cause,
            })?;

        // TODO blocking in async
        session_params.origin =
            self.identity.certificate().map(|cert| model::common::Certificate {
                certificate: cert.encoded_certificate().to_vec(),
                signature: cert.signature().to_vec(),
            });

        let (session_key, encrypted_session) =
            protocol::encrypt_session(&contact.peer_identity(), session_params).map_err(
                |cause| ControllerError::ProtocolExecution {
                    message: "Failed to encrypt session".to_string(),
                    cause,
                },
            )?;

        let envelope = msg_svc_bindings::Envelope::new();
        envelope.setEphemeralSessionKey(js_sys::Uint8Array::from(&session_key.id_bytes()[..]));
        envelope.setEncryptedSession(js_sys::Uint8Array::from(&encrypted_session[..]));
        envelope.setEncryptedPayload(js_sys::Uint8Array::from(&encrypted_payload[..]));

        let promise = self.transport.messages().sendMessage(envelope);
        let _value = JsFuture::from(promise).await.map_err(|cause| {
            ControllerError::Message {
                message: cause.as_string().unwrap_or("Unknown error during message send".to_string())
            }
        })?;

        Ok(())
    }
}
