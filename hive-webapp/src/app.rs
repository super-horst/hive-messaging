use yew::{html, Component, ComponentLink, Html, ShouldRender};

use log::*;

use wasm_bindgen::__rt::std::sync::{Arc, RwLock};

use crate::identity::LocalIdentity;
use crate::storage::StorageController;
use crate::transport::ConnectionManager;
use crate::views::*;

pub struct AppContainer {
    link: ComponentLink<Self>,
    connections: ConnectionManager,
    storage: StorageController,
    identity: LocalIdentity,
}

impl Component for AppContainer {
    type Message = ();
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        info!("Initialising app");

        let connections = ConnectionManager::new();
        let storage = StorageController::new();

        AppContainer {
            link,
            connections: connections.clone(),
            storage: storage.clone(),
            identity: LocalIdentity::initialise(storage, connections),
        }
    }

    fn update(&mut self, _: Self::Message) -> ShouldRender {
        // don't render
        return false;
    }

    fn change(&mut self, _: Self::Properties) -> ShouldRender {
        // don't render
        false
    }

    fn view(&self) -> Html {
        html! {
        <div>
            <messaging::MessagingView
             identity=self.identity.clone()
             storage=self.storage.clone()
             connections=self.connections.clone() />
        </div>
        }
    }
}
