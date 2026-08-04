{
  # Reproducible-build flake for the OneCipher daemon (statically links the
  # Key-Agent). Provides a byte-reproducible `onecipher` package.
  #
  # Usage:
  #   nix build .#onecipher
  #   nix run  .#onecipher -- --help
  description = "OneCipher reproducible daemon build";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        # Pinned stable Rust — must match rust-toolchain.toml.
        rust = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rustfmt" "clippy" ];
        };
      in {
        packages.onecipher = pkgs.rustPlatform.buildRustPackage {
          pname = "onecipher";
          version = "0.1.0";
          src = pkgs.lib.cleanSource ./..;
          cargoLock.lockFile = ../Cargo.lock;

          # Byte-reproducibility flags (mirror reproducer/build.sh).
          RUSTFLAGS = "-C strip=symbols -C link-arg=-Wl,--build-id=none";
          CARGO_TARGET_DIR = "target/reproducible";

          nativeBuildInputs = [ rust pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl pkgs.zeromq ];

          # Build only the daemon binary (contains the Key-Agent).
          cargoBuildFlags = [ "--bin" "onecipher" "--locked" ];
          meta = with pkgs.lib; {
            description = "OneCipher policy-gated signing daemon";
            license = licenses.mit;
          };
        };
        defaultPackage = self.packages.${system}.onecipher;
      });
}
