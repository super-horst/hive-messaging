#!/usr/bin/env bash

mkdir src/generated

docker build -t protoc_container .

export PROTO_DIR=/proto
export PROTOS=$(echo "$PROTO_DIR"/{messages_svc.proto,common.proto})
export SRC_DIR=/src

docker run --env PROTOS --env PROTO_DIR --env SRC_DIR  \
  --mount type=bind,src=$(pwd)/../../hive-commons/proto,dst=$PROTO_DIR \
  --mount type=bind,src=$(pwd)/src,dst=$SRC_DIR \
  protoc_container:latest ./build_js_app.sh
 # -ti protoc_container:latest bash
