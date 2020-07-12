webapp-release-wasmbind:
	mkdir -p app

	cargo build --release --target wasm32-unknown-unknown \
		&& wasm-bindgen --target web --no-typescript --out-dir app/ --out-name hive-webapp target/wasm32-unknown-unknown/release/hive-webapp.wasm

	cp static/* app

webapp-debug-wasmbind:
	mkdir -p app

	cargo build --target wasm32-unknown-unknown \
		&& wasm-bindgen --target web --no-typescript --out-dir app/ --out-name hive-webapp target/wasm32-unknown-unknown/debug/hive-webapp.wasm

	cp static/* app

## Don't use wasm-bindgen ... not yet stable!

webapp-debug:
	cargo web build --target wasm32-unknown-unknown

	mkdir -p app
	cp static/* app
	cp target/wasm32-unknown-unknown/debug/hive-webapp.js app
	cp target/wasm32-unknown-unknown/debug/hive-webapp.wasm app

webapp-release:
	cargo web build --release --target wasm32-unknown-unknown

	mkdir -p app
	cp static/* app
	cp target/wasm32-unknown-unknown/release/hive-webapp.js app
	cp target/wasm32-unknown-unknown/release/hive-webapp.wasm app

