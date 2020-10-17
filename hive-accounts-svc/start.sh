#!/bin/bash

export CONFIG='{"port":8080,"loglevel":"debug","db_config":{"host":"accounts_db","port":5432,"user":"postgres","password":"accounts_db","dbname":"common","ssl_mode":true},"certificate":"./certs", "key":"./privates"}'
cargo run