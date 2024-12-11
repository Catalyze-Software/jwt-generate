# Build script jwt_generate canister

# Generate candid
cargo test candid -p jwt_generate

# Build wasm
cargo build -p jwt_generate --release --target wasm32-unknown-unknown

# Gzip wasm
gzip -c target/wasm32-unknown-unknown/release/jwt_generate.wasm > target/wasm32-unknown-unknown/release/jwt_generate.wasm.gz

# Copy wasm
cp target/wasm32-unknown-unknown/release/jwt_generate.wasm.gz wasm/jwt_generate.wasm.gz
