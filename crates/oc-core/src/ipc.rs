//! IPC wire-type boundary documentation.
//!
//! Proto types canonically live in `oc_keyagent::proto` (prost, R56-safe).
//! `oc_netagent` depends on `oc_keyagent` only for these pure-codec types —
//! `oc_core` will own them after the next major refactor. This module documents
//! the boundary and reserves the future location.
//!
//! ## Current ownership
//! - `crates/oc-keyagent/src/proto.rs` is the source of truth (prost messages, no I/O, no async
//!   runtime).
//! - `oc_netagent` imports `oc_keyagent::proto::*` and `oc_keyagent::{KeyAgentRequest,
//!   KeyAgentResponse}` for UDS frame codec. The dependency is **pure codec** and R56-safe.
//!
//! ## Future direction
//! After the next major refactor the wire types will move to `oc_core::ipc`
//! (or `oc_core::proto`) so the dependency direction is `oc_keyagent -> oc_core <- oc_netagent`
//! with no reverse edge `oc_netagent -> oc_keyagent` for proto types.
//! `oc_keyagent` would then re-export from `oc_core` for backward compatibility.
//!
//! See `crates/oc-keyagent/src/proto.rs` for the actual definitions.
//! See `oc_keyagent::frame` for the length-prefixed transport.
//!
//! This module intentionally contains no wire types yet — it is a boundary marker
//! so `cargo check` and reviewers can see the intended direction.

// Marker to keep the module non-empty for `cargo shear` (doc-only modules are
// flagged as empty files). Reserved for future wire-type re-export.
#[allow(dead_code)]
pub struct IpcBoundaryMarker(());
