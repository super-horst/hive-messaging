use wasm_bindgen::prelude::*;
use yew::prelude::*;

use std::collections::HashMap;
use std::sync::Arc;

use yew::{html, Component, ComponentLink, Href, Html, InputData, KeyboardEvent, ShouldRender};

use wasm_bindgen::JsCast;
use wasm_bindgen_futures::futures_0_3::spawn_local;
use wasm_bindgen_futures::futures_0_3::JsFuture;

use log::*;

use crypto::FromBytes;
use hive_commons::crypto;
use hive_commons::model::*;

use crate::bindings::accounts_svc_bindings;
use crate::bindings::common_bindings;

use crate::storage::*;
use crate::views::*;

struct Message {}

pub enum StateChange {
    UpdateCertificate(crypto::Certificate),
    UpdatePreKeys(crypto::utils::PrivatePreKeys),
}

pub struct AppContainer {
    link: ComponentLink<Self>,
    storage: StorageController,
    identity: Identity,
}

impl Component for AppContainer {
    type Message = StateChange;
    type Properties = ();

    fn create(_: Self::Properties, link: ComponentLink<Self>) -> Self {
        let mut storage = StorageController::new();

        let mut new_account = false;

        let id = match storage.get_identity() {
            Some(id) => id,
            None => {
                let key = crypto::PrivateKey::generate().unwrap();

                let created = Identity::new(key);
                storage.set_identity(&created);

                new_account = true;

                let private = created.key.clone();
                let certificate_link = link.clone();
                spawn_local(async move {
                    let certificate = Self::create_account(private).await;
                    certificate_link.send_message(StateChange::UpdateCertificate(certificate));
                });

                created
            }
        };

        if id.certificate.is_none() && !new_account{
            let private = id.key.clone();
            let certificate_link = link.clone();
            spawn_local(async move {
                let certificate = Self::create_account(private).await;
                certificate_link.send_message(StateChange::UpdateCertificate(certificate));
            });
        } else if id.pre_keys.is_none() && !new_account {
            let private = id.key.clone();
            let pre_key_link = link.clone();
            spawn_local(async move {
                let pre_keys = Self::publish_pre_key_bundle(private).await;

                pre_key_link.send_message(StateChange::UpdatePreKeys(pre_keys));
            });
        }

        AppContainer {
            link,
            storage,
            identity: id,
        }
    }

    fn update(&mut self, msg: Self::Message) -> ShouldRender {
        return match msg {
            StateChange::UpdateCertificate(c) => {
                self.identity.certificate = Some(c);
                self.storage.set_identity(&self.identity);

                let private = self.identity.key.clone();
                let pre_key_link = self.link.clone();
                spawn_local(async move {
                    let pre_keys = Self::publish_pre_key_bundle(private).await;

                    pre_key_link.send_message(StateChange::UpdatePreKeys(pre_keys));
                });

                true
            }
            StateChange::UpdatePreKeys(pre_keys) => {
                self.identity.pre_keys = Some(pre_keys);
                self.storage.set_identity(&self.identity);

                true
            }
        };
    }

    fn change(&mut self, _props: Self::Properties) -> ShouldRender {
        // don't render
        false
    }

    fn view(&self) -> Html {
        html! {
        <div>
            <MessagingView />
        </div>
        }
    }
}

impl AppContainer {
    async fn create_account(key: Arc<crypto::PrivateKey>) -> crypto::Certificate {
        info!("create_account entry");

        let challenge = crypto::utils::sign_challenge(&key).unwrap();
        let unsig_challenge =
            common::signed_challenge::Challenge::decode(challenge.challenge.clone()).unwrap();

        info!("Challenge timestamp {}", unsig_challenge.timestamp);

        let bound_challenge = common_bindings::SignedChallenge::new();
        bound_challenge.setChallenge(js_sys::Uint8Array::from(&challenge.challenge[..]));
        bound_challenge.setSignature(js_sys::Uint8Array::from(&challenge.signature[..]));

        let client =
            accounts_svc_bindings::AccountsPromiseClient::new(create_service_url());
        let promise = client.createAccount(bound_challenge);
        let value = JsFuture::from(promise).await.unwrap();

        let certificate_binding: common_bindings::Certificate =
            value.dyn_into().expect("response not working...");

        let (certificate, ignore_for_now) =
            crypto::CertificateFactory::decode(certificate_binding.into()).unwrap();

        info!("Certificate serial {}", certificate.infos().serial());

        return certificate;
    }

    async fn publish_pre_key_bundle(key: Arc<crypto::PrivateKey>) -> crypto::utils::PrivatePreKeys {
        info!("publish pre keys entry");

        let (pre_keys, privates) =
            crypto::utils::create_pre_key_bundle(&key).unwrap();

        let client =
            accounts_svc_bindings::AccountsPromiseClient::new(create_service_url());

        let bound_pre_keys: common_bindings::PreKeyBundle = pre_keys.into();
        let promise = client.updatePreKeys(bound_pre_keys);
        let value = JsFuture::from(promise).await.unwrap();

        let _: accounts_svc_bindings::UpdateKeyResult =
            value.dyn_into().expect("response not working...");

        privates
    }
}

fn create_service_url() -> String {
    let location = web_sys::window().unwrap().location();

    // TODO error handling
    format!(
        "{}//{}",
        location.protocol().unwrap(),
        location.host().unwrap()
    )
        .to_string()
}
