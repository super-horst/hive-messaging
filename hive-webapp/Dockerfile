FROM rust:1.47.0 as builder

ARG TARGET="/target"
ENV RUST_BACKTRACE=full

RUN cargo install wasm-pack

RUN mkdir $TARGET
WORKDIR /build