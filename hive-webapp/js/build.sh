#!/usr/bin/env bash

mkdir src

docker build -t protoc_container .

export PROTO_DIR=/proto
export PROTOS=$(echo "$PROTO_DIR"/{messages_svc.proto,common.proto})
export SRC_DIR=/src

docker run --env PROTOS --env PROTO_DIR --env SRC_DIR  \
  --mount type=bind,src=$(pwd)/../../hive-commons/proto,dst=$PROTO_DIR \
  --mount type=bind,src=$(pwd)/src,dst=$SRC_DIR \
  protoc_container:latest \
  protoc -I="$PROTO_DIR" $PROTOS \
    --js_out=import_style=commonjs:"$SRC_DIR" \
    --grpc-web_out=import_style=commonjs,mode=grpcwebtext:"$SRC_DIR"
