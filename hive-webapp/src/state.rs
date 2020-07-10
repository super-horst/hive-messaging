use serde::{Deserialize, Serialize};

use crate::contacts::*;

#[derive(Serialize, Deserialize)]
pub struct State {
    contacts: Vec<Contact>,
}
