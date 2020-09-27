use std::env;

use failure::{Error, Fail};

use serde::{Serialize, Deserialize};
use serde_json;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub port: u16,
    pub loglevel: String,
    pub db_config: DbConfig,
}

#[derive(Serialize, Deserialize)]
pub struct DbConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub dbname: String,
    pub ssl_mode: bool,
}

#[derive(Debug, Fail)]
pub enum ConfigurationError {
    #[fail(display = "Error accessing env: {}", message)]
    EnvironmentError {
        message: String,
        #[fail(cause)] cause: env::VarError,
    },
    #[fail(display = "Invalid format: {}", message)]
    FormatError {
        message: String,
        #[fail(cause)] cause: serde_json::Error,
    },
}

pub fn load_config_from_env() -> Result<Config, ConfigurationError> {
    let serialised_config = env::var("CONFIG")
        .map_err(|e| ConfigurationError::EnvironmentError {
            message: "No configuration given".to_string(),
            cause: e,
        })?;

    serde_json::from_str(&serialised_config)
        .map_err(|e| ConfigurationError::FormatError {
            message: "Configuration".to_string(),
            cause: e,
        })
}

#[cfg(test)]
mod config_tests {
    use super::*;

    #[test]
    fn config_template() {
        let db_conf = DbConfig {
            host: "172.17.0.2".to_string(),
            port: 5432,
            dbname: "postgres".to_string(),
            user: "postgres".to_string(),
            password: "docker".to_string(),
            ssl_mode: true,
        };

        let config = Config {
            port: 8080,
            loglevel: "debug".to_string(),
            db_config: db_conf,
        };

        let s = serde_json::to_string(&config).unwrap();
        println!("{}", s);

        let s = serde_json::to_string_pretty(&config).unwrap();
        println!("{}", s);
    }
}
