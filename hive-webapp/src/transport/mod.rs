use std::cell::Cell;
use std::sync::{Arc, Mutex};

pub fn create_service_url() -> String {
    let location = web_sys::window().unwrap().location();

    // TODO error handling
    format!(
        "{}//{}",
        location.protocol().unwrap(),
        location.host().unwrap()
    )
    .to_string()
}

pub trait ConnectionProvider {
    type Connection;

    fn new_connection(&self) -> Result<Self::Connection, String>;
}

pub struct ConnectionPool<T> {
    provider: Box<dyn ConnectionProvider<Connection = T>>,
    connection: Option<T>,
}

impl<T> ConnectionPool<T>
where
    T: Send + Sync,
{
    pub fn do_stuff(&self) {}
}
