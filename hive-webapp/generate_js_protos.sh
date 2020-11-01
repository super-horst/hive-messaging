#!/usr/bin/env bash

cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1

docker build -t protoc_container .

export GEN_DIR=/generated
mkdir -p .$GEN_DIR

export PROTO_DIR=/proto
PROTOS=$(echo "$PROTO_DIR"/{messages_svc.proto,accounts_svc.proto,common.proto})
export PROTOS

# shellcheck disable=SC2086
docker run \
  --mount type=bind,src="$(pwd)"/../hive-commons/proto,dst=$PROTO_DIR \
  --mount type=bind,src="$(pwd)$GEN_DIR",dst=$GEN_DIR \
  protoc_container:latest \
  protoc -I="$PROTO_DIR" $PROTOS \
  --js_out=import_style=commonjs:"$GEN_DIR" \
  --grpc-web_out=import_style=commonjs,mode=grpcwebtext:"$GEN_DIR"
