#!/bin/bash

export CONFIG='{"port":8080,"loglevel":"debug","db_config":{"host":"messages_db","port":5432,"user":"postgres","password":"messages_db","dbname":"common","ssl_mode":true},"certificate":"ignore", "key":"ignore"}'
cargo run
