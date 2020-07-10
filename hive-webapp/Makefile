webapp-release-websys:
	cargo build --release --target wasm32-unknown-unknown \
		&& wasm-bindgen --target web --no-typescript --out-dir target/ --out-name wasm ../target/wasm32-unknown-unknown/release/hive-webapp.wasm
	#mv static/wasm_bg.wasm static/hive-webapp_bg.wasm
	#mv static/wasm.js static/hive-webapp.js

webapp-debug-websys:
	cargo build --target wasm32-unknown-unknown \
		&& wasm-bindgen --target web --no-typescript --out-dir target/ --out-name wasm ../target/wasm32-unknown-unknown/debug/hive-webapp.wasm
	#mv static/wasm_bg.wasm static/hive-webapp_bg.wasm
	#mv static/wasm.js static/hive-webapp.js

## Don't use websys ... not yet stable!

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

