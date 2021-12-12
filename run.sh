#!/bin/bash

set -eo pipefail

function dockerize_build() {
  docker run -it -u 1000:1000 --mount type=bind,source="$(pwd)",target=/build "$@"
}

cd "$( dirname "${BASH_SOURCE[0]}" )"

# prepare sources and package for node
docker build -t node_wasm -f docker/Dockerfile.webapp .
./hive-webapp/scripts/generate_js_protos.sh
dockerize_build node_wasm /bin/bash -c "npm install --prefix /build/hive-webapp && npm run build --prefix /build/hive-webapp"

# create key material for server identity
if [ ! -f "hive-commons/certificate.json" ] && [ ! -f "hive-commons/privates.json" ]; then
  dockerize_build rust:1.57 /bin/bash -c "rustup component add rustfmt; cargo test --lib crypto::certificates::certificate_tests::create_key_certificate_files --manifest-path build/hive-commons/Cargo.toml -- --ignored --show-output;"
fi

docker-compose up