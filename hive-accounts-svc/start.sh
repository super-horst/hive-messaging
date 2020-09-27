#!/bin/bash

export CONFIG='{"port":8080,"loglevel":"debug","db_config":{"host":"172.17.0.2","port":5432,"user":"postgres","password":"docker","dbname":"postgres","ssl_mode":true}}'
cargo run