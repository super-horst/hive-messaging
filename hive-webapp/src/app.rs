use log::*;

use wasm_bindgen::prelude::*;
use yew::{html, Callback, Component, ComponentLink, Html, ShouldRender};

use crate::ctrl::{ContactManager, IdentityController, MessagingController, StorageController};
use crate::transport::ConnectionManager;
use crate::views::*;

use hive_commons::model;

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
                    on_error.emit(format!("Failed to access contacts {:?}", error));
                    panic!(error)
                }
            };

        let contacts =
            match ContactManager::new(storage.clone(), connections.clone(), identity.clone()) {
                Ok(contacts) => contacts,
                Err(error) => {
                    on_error.emit(format!("Failed to access contacts {:?}", error));
                    panic!(error)
                }
            };

        AppContainer { link, on_error, storage, connections, identity, contacts }
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
             identity=self.identity.clone()
             contacts=self.contacts.clone()
             connections=self.connections.clone()
              />
        </div>
        }
    }
}
