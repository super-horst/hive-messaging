#!/bin/bash

protoc -I=$PROTOS $PROTOS/*.proto \
    --js_out=import_style=commonjs:$SRC_DIR/generated \
    --grpc-web_out=import_style=commonjs,mode=grpcwebtext:$SRC_DIR/generated

cd $SRC_DIR
npm install
npx webpack client.js