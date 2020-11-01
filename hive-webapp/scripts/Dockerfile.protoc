FROM ubuntu:20.04

RUN DEBIAN_FRONTEND=noninteractive apt update && \
    DEBIAN_FRONTEND=noninteractive apt install -y --no-install-recommends protobuf-compiler git wget

RUN wget --no-check-certificate https://github.com/grpc/grpc-web/releases/download/1.2.1/protoc-gen-grpc-web-1.2.1-linux-x86_64 -O /usr/local/bin/protoc-gen-grpc-web && \
    chmod +x /usr/local/bin/protoc-gen-grpc-web

USER 1000