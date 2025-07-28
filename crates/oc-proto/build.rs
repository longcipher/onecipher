//! Build script — compiles `proto/agent.proto` via `prost-build`.
//!
//! Outputs generated Rust source into `OUT_DIR/onecipher.agent.v1.rs`, which
//! `src/lib.rs` includes via `include!`.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR must be set by cargo at build time");
    prost_build::Config::new()
        .out_dir(out_dir)
        .compile_protos(&["proto/agent.proto"], &["proto"])?;
    println!("cargo:rerun-if-changed=proto/agent.proto");
    Ok(())
}
