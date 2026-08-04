# Reproducible-build container for the OneCipher daemon.
#
# Builds the `onecipher` binary inside a pinned, deterministic Rust image so
# that the emitted artifact matches what an independent auditor would
# produce. The RUSTFLAGS (`-C strip=symbols`, `-C link-arg=-Wl,--build-id=none`)
# mirror reproducer/build.sh and the Nix flake.
# Uses a pinned Rust nightly image (consistent with rust-toolchain.toml).
FROM rust:nightly-slim AS build

# Pin the reproducible build flags (must match rust-toolchain.toml + flake.nix).
ENV RUSTFLAGS="-C strip=symbols -C link-arg=-Wl,--build-id=none" \
    CARGO_TARGET_DIR="/build/target/reproducible" \
    DEBIAN_FRONTEND="noninteractive"

RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
RUN cargo build --release --locked --bin onecipher

# Minimal runtime image: only the daemon binary.
FROM debian:stable-slim
COPY --from=build /build/target/reproducible/release/onecipher /out/onecipher
ENTRYPOINT ["/out/onecipher"]
