use std::sync::Arc;

use log::*;

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::futures_0_3::spawn_local;
use yew::{html, Callback, Component, ComponentLink, Html, ShouldRender};

use crate::ctrl::{ContactManager, IdentityController, MessagingController, StorageController, PayloadHandler, CONTACT_PAYLOAD_IDENTIFIER};
use crate::transport::ConnectionManager;
use crate::views::*;


#[wasm_bindgen]
extern "C" {
    fn alert(s: &str);
}

pub enum AppMessage {
    ApplicationError(String),
}

pub struct AppContainer {
    link: ComponentLink<Self>,
    on_error: Callback<String>,
    storage: StorageController,
    connections: ConnectionManager,
    identity: IdentityController,
    messaging: MessagingController,
    contacts: ContactManager,
}

impl Component for AppContainer {
    type Message = AppMessage;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        info!("Initialising app...");

        let on_error: Callback<String> = link.callback(AppMessage::ApplicationError);

        let storage = StorageController::new();
        let connections = ConnectionManager::new();

        let identity =
            match IdentityController::new(on_error.clone(), storage.clone(), connections.clone()) {
                Ok(identity) => identity,
                Err(error) => {
                    error!("{:?}", error);
                    panic!("{:?}", error)
                }
            };

        let contacts =
            match ContactManager::new(storage.clone(), connections.clone(), identity.clone()) {
                Ok(contacts) => contacts,
                Err(error) => {
                    error!("{:?}", error);
                    panic!("{:?}", error)
                }
            };

        let messaging = MessagingController::new(
            on_error.clone(),
            identity.clone(),
            contacts.clone(),
            connections.clone(),
        );

        let incoming_contact_handler = PayloadHandler::new(Arc::new(contacts.clone()));
        let local_messaging = messaging.clone();
        spawn_local(async move {
            local_messaging.register_handler(CONTACT_PAYLOAD_IDENTIFIER, incoming_contact_handler).await;
        });

        AppContainer {
            link,
            on_error,
            storage,
            connections,
            messaging,
            identity,
            contacts,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        return match msg {
            AppMessage::ApplicationError(message) => {
                alert(&message);
                true
            }
        };
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        // don't render
        false
    }

    fn view(&self) -> Html {
        html! {
        <div>
            <messaging::MessagingView
             on_error = self.on_error.clone()
             storage=self.storage.clone()
             contacts=self.contacts.clone()
             messaging=self.messaging.clone()
              />
        </div>
        }
    }
}
