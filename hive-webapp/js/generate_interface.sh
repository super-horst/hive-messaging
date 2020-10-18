#!/bin/bash

protoc -I="$PROTO_DIR" $PROTOS \
    --js_out=import_style=commonjs:"$SRC_DIR"/generated \
    --grpc-web_out=import_style=commonjs,mode=grpcwebtext:"$SRC_DIR"/generated

cd "$SRC_DIR" || exit
npm install
npx webpack client.js