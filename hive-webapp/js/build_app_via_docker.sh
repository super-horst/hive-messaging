#!/usr/bin/env bash

mkdir src/generated

docker build -t protoc_container .

export PROTOS=/proto
export SRC_DIR=/src

docker run --env PROTOS --env SRC_DIR  \
  --mount type=bind,src=$(pwd)/../../hive-grpc/proto,dst=$PROTOS \
  --mount type=bind,src=$(pwd)/src,dst=$SRC_DIR \
  protoc_container:latest ./build_js_app.sh
