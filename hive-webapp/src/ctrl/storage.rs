use std::sync::{Arc, RwLock};

use yew::format::Json;
use yew::services::storage::{Area, StorageService};

use serde::{Deserialize, Serialize};

use crate::ctrl::ControllerError;

#[derive(Clone)]
pub struct StorageController {
    service: Arc<RwLock<StorageService>>,
}

impl StorageController {
    pub fn new() -> Self {
        //TODO error handling
        let service = StorageService::new(Area::Local).expect("storage was disabled by the user");

        StorageController {
            service: Arc::new(RwLock::new(service)),
        }
    }

    pub fn load<T>(&self, key: &str) -> Result<T, ControllerError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let storage = self
            .service
            .read()
            .map_err(|cause| ControllerError::Message {
                message: "Locking failed".to_string(),
            })?;
        let Json(data) = storage.restore(key);
        data.map_err(|cause| ControllerError::NoDataFound {
            message: key.to_string(),
        })
    }

    pub fn store<'a, T>(&self, key: &str, data: &'a T) -> Result<(), ControllerError>
    where
        T: Serialize,
    {
        let mut storage = self
            .service
            .write()
            .map_err(|cause| ControllerError::Message {
                message: "Locking failed".to_string(),
            })?;

        storage.store(key, Json(&data));

        Ok(())

        /*panic::catch_unwind(|| {
            storage.store(key, Json(&data))
        }).map_err(|cause| {
            match cause.downcast::<String>() {
                Ok(panic_msg) => {
                    ControllerError::Message { message: panic_msg.to_string() }
                }
                Err(_) => {
                    ControllerError::Message { message: "Unknown panic during storage access".to_string() }
                }
            }
        })*/
    }
}
