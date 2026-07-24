//! Shared mock ABI encoding helpers for ERC-7715 session key operations.
//!
//! Phase 1 (`evm.rs`) and Phase 2 (`real.rs`) use the same encoding layout
//! but different selectors. These helpers take the selector as a parameter
//! so both modules share one implementation.

/// Left-pad a byte slice to 32 bytes (ABI encoding for `bytes32` args).
/// Truncates to the last 32 bytes if longer.
pub fn pad32(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let len = input.len().min(32);
    out[32 - len..].copy_from_slice(&input[..len]);
    out
}

/// Encode a `grantPermission(bytes32,bytes32,uint64)` calldata.
pub fn encode_grant_permission(
    selector: [u8; 4],
    session_pubkey: &[u8],
    merkle_root: &str,
    expiry_unix: u64,
) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32 + 32 + 32);
    calldata.extend_from_slice(&selector);
    calldata.extend_from_slice(&pad32(session_pubkey));
    let root_bytes = hex::decode(merkle_root.trim_start_matches("0x")).unwrap_or_default();
    calldata.extend_from_slice(&pad32(&root_bytes));
    calldata.extend_from_slice(&[0u8; 24]);
    calldata.extend_from_slice(&expiry_unix.to_be_bytes());
    calldata
}

/// Encode an `isPermissionGranted(bytes32)` view calldata.
pub fn encode_is_permission_granted(selector: [u8; 4], session_key_id: &str) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector);
    calldata.extend_from_slice(&pad32(session_key_id.as_bytes()));
    calldata
}

/// Encode a `revokePermission(bytes32)` calldata.
pub fn encode_revoke_permission(selector: [u8; 4], session_key_id: &str) -> Vec<u8> {
    let mut calldata = Vec::with_capacity(4 + 32);
    calldata.extend_from_slice(&selector);
    calldata.extend_from_slice(&pad32(session_key_id.as_bytes()));
    calldata
}
