# hive-messaging

## what is it?

hive-messaging is a prototype for a web-based messenger utilising _rust_, _webassembly_ and _gRPC_. Messages are encrypted using variant of the signal protocol.

UI is implemented using _yew_ and _wasm-bindgen_, and packaged with _npm_ and _wasm-pack_. Transport from UI to frontent happens via _gRPC-web_, _envoy_ filters out the '-web'-part and propagates _gRPC_ to the microservices.

The backend currently consists of two async _tokio_ services with a dedicated database each. All transport code it auto-generated from the proto-files in _hive-commons_, with exception of the wasm-binds.

## how do I run it

prerequisites:
- docker
- docker-compose

To run, neither _npm_ nor _rust_ need to be available locally, though are invaluable for debugging purposes.

Just execute `./run.sh` in the main directory.