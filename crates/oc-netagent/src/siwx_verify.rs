//! EIP-1271 / ERC-6492 Sign-In verification (async, RPC-backed).
//!
//! Pure-crypto checks (EIP-191 recovery, Ed25519) live in `oc-signer` and the
//! message model in `oc-siwx`; this module adds the contract-account layer
//! for EVM chains:
//!
//! * ERC-6492 magic-suffix dispatch (checked first — a magic-suffixed signature must never fall
//!   through to EIP-191);
//! * `eth_chainId` pre-check (a wrong-chain endpoint never sees a contract call);
//! * EIP-1271 `isValidSignature` (`0x1626ba7e`);
//! * deployless ERC-6492 simulation (`eth_call` with `to` omitted, using the vendored ox
//!   `universalSignatureValidatorBytecode` — a canonical public deployment artifact, see
//!   `siwx_bytecode/SOURCE.txt`).
//!
//! Error contract (matches `oc-siwx`): malformed input → `InvalidSignature`,
//! cryptographic mismatch → `VerificationFailed`, transport → `Backend`
//! (reason only — RPC URLs never appear in error strings).

use std::collections::BTreeMap;

use oc_siwx::{SiwxError, SiwxMessage, SyncVerifier};

use crate::{intent::rpc::RpcError, rpc_client::HpxRpcClient};

/// ERC-6492 detection suffix: `0x6492` repeated 16 times.
pub const EIP6492_MAGIC: [u8; 32] = [
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
    0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92, 0x64, 0x92,
];

/// EIP-1271 success magic, `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
///
/// It intentionally equals the function selector below.
pub const EIP1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xBA, 0x7E];

/// `isValidSignature(bytes32,bytes)` selector (== [`EIP1271_MAGIC`]).
pub const EIP1271_SELECTOR: [u8; 4] = [0x16, 0x26, 0xBA, 0x7E];

/// Byte length of the vendored ox validator initcode.
const VALIDATOR_BYTECODE_LEN: usize = 1684;

/// Deployless constructor initcode (hex, see `siwx_bytecode/SOURCE.txt`).
const VALIDATOR_BYTECODE_HEX: &str =
    include_str!("siwx_bytecode/universalSignatureValidatorBytecode.hex");

/// True when `signature` ends with the ERC-6492 magic suffix.
#[must_use]
pub fn has_6492_magic_suffix(signature: &[u8]) -> bool {
    signature.len() >= EIP6492_MAGIC.len() && signature.ends_with(&EIP6492_MAGIC)
}

/// Decode the vendored validator initcode.
fn validator_bytecode() -> Result<Vec<u8>, SiwxError> {
    let hex = VALIDATOR_BYTECODE_HEX.trim();
    if hex.len() != VALIDATOR_BYTECODE_LEN * 2 {
        return Err(SiwxError::Backend { reason: "validator bytecode length mismatch".to_owned() });
    }
    hex::decode(hex)
        .map_err(|_| SiwxError::Backend { reason: "validator bytecode corrupt".to_owned() })
}

/// Parse a `0x`-prefixed 20-byte address (checksum enforced upstream by
/// [`oc_signer::EvmVerifier::validate_address`]; only shape matters here).
fn parse_address_20(address: &str) -> Result<[u8; 20], SiwxError> {
    let hex_part = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .ok_or_else(|| SiwxError::InvalidAddress { reason: "must start with 0x".to_owned() })?;
    if hex_part.len() != 40 {
        return Err(SiwxError::InvalidAddress { reason: "must be 0x + 40 hex chars".to_owned() });
    }
    let bytes = hex::decode(hex_part)
        .map_err(|_| SiwxError::InvalidAddress { reason: "not hex".to_owned() })?;
    bytes
        .try_into()
        .map_err(|_| SiwxError::InvalidAddress { reason: "must be 20 bytes".to_owned() })
}

fn u256_word(value: usize) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&(value as u64).to_be_bytes());
    word
}

fn pad_tail(data: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(data);
    out.extend(std::iter::repeat_n(0u8, data.len().next_multiple_of(32) - data.len()));
}

/// Constructor calldata: `bytecode || abi.encode(signer, hash, signature)`.
fn deployless_calldata(
    bytecode: &[u8],
    signer: &[u8; 20],
    hash: &[u8; 32],
    signature: &[u8],
) -> Vec<u8> {
    let mut data = Vec::with_capacity(bytecode.len() + 128 + signature.len());
    data.extend_from_slice(bytecode);
    // address word (left-padded), hash word, bytes offset (0x60).
    data.extend_from_slice(&[0u8; 12]);
    data.extend_from_slice(signer);
    data.extend_from_slice(hash);
    data.extend_from_slice(&u256_word(0x60));
    // bytes tail: length + padded payload.
    data.extend_from_slice(&u256_word(signature.len()));
    pad_tail(signature, &mut data);
    data
}

/// `isValidSignature` calldata: `selector || abi.encode(hash, signature)`.
fn is_valid_signature_calldata(hash: &[u8; 32], signature: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(100 + signature.len());
    data.extend_from_slice(&EIP1271_SELECTOR);
    data.extend_from_slice(hash);
    data.extend_from_slice(&u256_word(0x40));
    data.extend_from_slice(&u256_word(signature.len()));
    pad_tail(signature, &mut data);
    data
}

/// Interpret a deployless validator `eth_call` result as a bool.
///
/// Nodes pad `return(31, 1)` to 32 bytes. Accept any length whose last byte
/// is `0x00`/`0x01` and whose prefix is all zeros.
pub fn eth_call_bool(data: &[u8]) -> Result<bool, SiwxError> {
    let Some((last, rest)) = data.split_last() else {
        return Err(SiwxError::Backend { reason: "empty eth_call result".to_owned() });
    };
    if rest.iter().any(|&b| b != 0) {
        return Err(SiwxError::VerificationFailed {
            reason: "malformed 6492 eth_call result".to_owned(),
        });
    }
    match last {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(SiwxError::VerificationFailed {
            reason: "malformed 6492 eth_call result".to_owned(),
        }),
    }
}

/// Check an `isValidSignature` return: first 4 bytes must be the EIP-1271
/// magic and any trailing bytes must be zero (accepts both 4-byte and
/// 32-byte padded returns).
fn check_1271_return(data: &[u8]) -> Result<(), SiwxError> {
    if data.len() < 4 || data[..4] != EIP1271_MAGIC || data[4..].iter().any(|&b| b != 0) {
        return Err(SiwxError::VerificationFailed { reason: "EIP-1271 magic mismatch".to_owned() });
    }
    Ok(())
}

/// Require `eth_chainId` to equal the message chain id.
fn assert_rpc_chain_id(message_chain_id: &str, rpc_chain_id: u64) -> Result<(), SiwxError> {
    let expected = oc_signer::parse_evm_chain_id(message_chain_id)?;
    if expected != rpc_chain_id {
        return Err(SiwxError::ChainIdMismatch {
            expected: expected.to_string(),
            actual: rpc_chain_id.to_string(),
        });
    }
    Ok(())
}

/// Map an RPC failure to [`SiwxError`] without leaking endpoint details.
///
/// Timeouts and transport errors mean the chain was unreachable → `Backend`.
/// Server/parse errors mean the chain answered but the call failed →
/// `VerificationFailed`. Neither branch includes URLs or response bodies.
fn rpc_err(what: &'static str, e: RpcError) -> SiwxError {
    match e {
        RpcError::Timeout => SiwxError::Backend { reason: format!("{what} timed out") },
        RpcError::Transport(_) => SiwxError::Backend { reason: format!("{what} failed") },
        RpcError::Server(_) | RpcError::Parse(_) | RpcError::Rpc(_) | RpcError::NotFound => {
            SiwxError::VerificationFailed { reason: format!("{what} failed") }
        }
    }
}

/// EVM Sign-In verifier with optional per-chain contract verification.
///
/// Without RPC endpoints this is pure EIP-191. With endpoints, EIP-191
/// failures fall through to EIP-1271, and magic-suffixed signatures take the
/// ERC-6492 simulation path. Chains missing from the map stay on EIP-191
/// (the 191 error is returned; no wrong-chain RPC is ever dialed).
#[derive(Debug, Clone, Default)]
pub struct RpcVerifier {
    endpoints: BTreeMap<u64, String>,
}

impl RpcVerifier {
    /// Create a verifier that only performs EIP-191 recovery.
    #[must_use]
    pub fn new() -> Self {
        Self { endpoints: BTreeMap::new() }
    }

    /// Create a verifier that selects the RPC URL by EIP-155 chain id.
    #[must_use]
    pub fn with_rpc_map(map: impl IntoIterator<Item = (u64, impl Into<String>)>) -> Self {
        Self { endpoints: map.into_iter().map(|(id, url)| (id, url.into())).collect() }
    }

    /// Create a verifier with a single RPC URL bound to `chain_id`.
    #[must_use]
    pub fn with_rpc_for_chain(chain_id: u64, url: impl Into<String>) -> Self {
        Self::with_rpc_map([(chain_id, url)])
    }

    fn client_for(&self, chain_id: &str) -> Result<Option<HpxRpcClient>, SiwxError> {
        let id = oc_signer::parse_evm_chain_id(chain_id)?;
        let Some(url) = self.endpoints.get(&id) else {
            return Ok(None);
        };
        let client = HpxRpcClient::new(format!("eip155:{id}"), url.clone())
            .map_err(|e| SiwxError::Backend { reason: format!("rpc client: {e}") })?;
        Ok(Some(client))
    }

    /// Verify `signature` over `raw_message`, binding identity to `message`.
    ///
    /// Magic-suffixed signatures take the ERC-6492 path (RPC required);
    /// otherwise EIP-191 runs first and EIP-1271 is the RPC fallback.
    pub async fn verify(
        &self,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        oc_signer::EvmVerifier::validate_address(message.address())?;
        if has_6492_magic_suffix(signature) {
            let Some(client) = self.client_for(message.chain_id())? else {
                return Err(SiwxError::InvalidSignature {
                    reason: "EIP-6492 requires RPC".to_owned(),
                });
            };
            return self.verify_6492(&client, message, raw_message, signature).await;
        }
        match oc_signer::EvmVerifier::new().verify(message, raw_message, signature) {
            Ok(()) => Ok(()),
            Err(e191) => {
                let Some(client) = self.client_for(message.chain_id())? else {
                    return Err(e191);
                };
                self.verify_1271(&client, message, raw_message, signature).await
            }
        }
    }

    async fn verify_1271(
        &self,
        client: &HpxRpcClient,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        let rpc_chain = client.eth_chain_id().await.map_err(|e| rpc_err("eth_chainId", e))?;
        // Wrong-chain contracts must not see isValidSignature.
        assert_rpc_chain_id(message.chain_id(), rpc_chain)?;

        let hash = oc_signer::eip191_hash(raw_message.as_bytes());
        let calldata = is_valid_signature_calldata(&hash, signature);
        let result = client
            .eth_call_bytes(Some(message.address()), &calldata)
            .await
            .map_err(|e| rpc_err("isValidSignature", e))?;
        check_1271_return(&result)
    }

    async fn verify_6492(
        &self,
        client: &HpxRpcClient,
        message: &SiwxMessage,
        raw_message: &str,
        signature: &[u8],
    ) -> Result<(), SiwxError> {
        let rpc_chain = client.eth_chain_id().await.map_err(|e| rpc_err("eth_chainId", e))?;
        assert_rpc_chain_id(message.chain_id(), rpc_chain)?;

        let signer = parse_address_20(message.address())?;
        let hash = oc_signer::eip191_hash(raw_message.as_bytes());
        let bytecode = validator_bytecode()?;
        let calldata = deployless_calldata(&bytecode, &signer, &hash, signature);
        let result =
            client.eth_call_bytes(None, &calldata).await.map_err(|e| rpc_err("eth_call", e))?;
        if eth_call_bool(&result)? {
            Ok(())
        } else {
            Err(SiwxError::VerificationFailed { reason: "EIP-6492 invalid".to_owned() })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magic_is_6492_repeated_sixteen_times() {
        assert_eq!(EIP6492_MAGIC.as_slice(), [0x64, 0x92].repeat(16));
    }

    #[test]
    fn selector_is_is_valid_signature() {
        // bytes4(keccak256("isValidSignature(bytes32,bytes)")) == 0x1626ba7e.
        use sha3::Digest;
        let digest = sha3::Keccak256::digest(b"isValidSignature(bytes32,bytes)");
        assert_eq!(&digest[..4], EIP1271_SELECTOR);
        assert_eq!(EIP1271_SELECTOR, EIP1271_MAGIC);
    }

    #[test]
    fn has_magic_suffix_detects_exact_and_wrapped() {
        assert!(has_6492_magic_suffix(&EIP6492_MAGIC));
        let mut wrapped = vec![0u8; 65];
        wrapped.extend_from_slice(&EIP6492_MAGIC);
        assert!(has_6492_magic_suffix(&wrapped));
        assert!(!has_6492_magic_suffix(&[0u8; 65]));
        assert!(!has_6492_magic_suffix(&[]));
        assert!(!has_6492_magic_suffix(&EIP6492_MAGIC[..31]));
    }

    #[test]
    fn vendored_bytecode_is_deployless_constructor() {
        let bytecode = validator_bytecode().expect("bytecode");
        assert_eq!(bytecode.len(), VALIDATOR_BYTECODE_LEN);
        assert!(
            bytecode.windows(5).any(|w| w == [0x60, 0x01, 0x60, 0x1f, 0xf3]),
            "constructor must return(31,1): PUSH1 1 / PUSH1 31 / RETURN"
        );
        assert!(
            bytecode.windows(4).any(|w| w == [0x61, 0x06, 0x94, 0x38]),
            "constructor size must be PUSH2 0x0694 CODESIZE"
        );
    }

    #[test]
    fn deployless_calldata_is_bytecode_then_abi_encode() {
        let bytecode = validator_bytecode().expect("bytecode");
        let sig = [0u8; 65];
        let data = deployless_calldata(&bytecode, &[0u8; 20], &[0u8; 32], &sig);
        assert!(data.starts_with(&bytecode));
        let args = &data[bytecode.len()..];
        // address word: 12 zero bytes + 20 address bytes.
        assert_eq!(&args[..12], &[0u8; 12]);
        assert_eq!(&args[12..32], &[0u8; 20]);
        // hash word.
        assert_eq!(&args[32..64], &[0u8; 32]);
        // bytes offset 0x60 (third word), then length 65 (fourth word).
        assert_eq!(args[95], 0x60);
        assert_eq!(args[127], 65);
        assert_eq!(&args[128..128 + 65], &sig);
    }

    #[test]
    fn is_valid_signature_calldata_layout() {
        let sig = [0xABu8; 65];
        let data = is_valid_signature_calldata(&[0x11u8; 32], &sig);
        assert_eq!(&data[..4], &EIP1271_SELECTOR);
        assert_eq!(&data[4..36], &[0x11u8; 32]);
        assert_eq!(data[67], 0x40, "bytes offset must be 0x40");
        assert_eq!(data[99], 65, "bytes length");
        assert_eq!(&data[100..165], &sig);
    }

    #[test]
    fn eth_call_bool_accepts_padded_and_short() {
        assert!(eth_call_bool(&[1]).expect("1"));
        assert!(!eth_call_bool(&[0]).expect("0"));
        let mut padded = [0u8; 32];
        padded[31] = 1;
        assert!(eth_call_bool(&padded).expect("padded 1"));
        assert!(!eth_call_bool(&[0u8; 32]).expect("padded 0"));
    }

    #[test]
    fn eth_call_bool_rejects_empty_and_malformed() {
        assert!(matches!(eth_call_bool(&[]), Err(SiwxError::Backend { .. })));
        assert!(matches!(eth_call_bool(&[2]), Err(SiwxError::VerificationFailed { .. })));
        assert!(matches!(eth_call_bool(&[1, 0]), Err(SiwxError::VerificationFailed { .. })));
    }

    #[test]
    fn check_1271_return_accepts_magic_forms() {
        check_1271_return(&EIP1271_MAGIC).expect("bare magic");
        let mut padded = [0u8; 32];
        padded[..4].copy_from_slice(&EIP1271_MAGIC);
        check_1271_return(&padded).expect("padded magic");
        assert!(check_1271_return(&[0u8; 32]).is_err());
        assert!(check_1271_return(&[0x16, 0x26, 0xBA]).is_err());
    }

    #[test]
    fn assert_rpc_chain_id_matches_message() {
        assert_rpc_chain_id("1", 1).expect("match");
        let mismatch = assert_rpc_chain_id("137", 1).expect_err("mismatch");
        assert!(
            matches!(
                mismatch,
                SiwxError::ChainIdMismatch {
                    ref expected,
                    ref actual
                } if expected == "137" && actual == "1"
            ),
            "got {mismatch:?}"
        );
    }

    #[tokio::test]
    async fn magic_suffix_without_rpc_requires_rpc() {
        let message = SiwxMessage::new(
            "example.com",
            "0x0000000000000000000000000000000000000001",
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("message");
        let text = message.to_sign_string("Ethereum");
        let mut sig = vec![0u8; 65];
        sig.extend_from_slice(&EIP6492_MAGIC);
        let err = RpcVerifier::new().verify(&message, &text, &sig).await.expect_err("requires RPC");
        assert!(
            matches!(
                err,
                SiwxError::InvalidSignature { ref reason } if reason == "EIP-6492 requires RPC"
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn eip191_fallback_without_rpc_returns_191_error() {
        let message = SiwxMessage::new(
            "example.com",
            "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("message");
        let text = message.to_sign_string("Ethereum");
        // 65 zero bytes: valid encoding shape, recovers to a random key.
        let err =
            RpcVerifier::new().verify(&message, &text, &[0u8; 65]).await.expect_err("bad sig");
        // No RPC configured: the EIP-191 error surfaces (never dials out).
        assert!(
            matches!(
                err,
                SiwxError::InvalidSignature { .. } | SiwxError::VerificationFailed { .. }
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn unreachable_rpc_is_backend_without_url_leak() {
        let message = SiwxMessage::new(
            "example.com",
            "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
            "https://example.com",
            "1",
            "testnonce12345678",
        )
        .expect("message");
        let text = message.to_sign_string("Ethereum");
        let mut sig = vec![0u8; 65];
        sig.extend_from_slice(&EIP6492_MAGIC);
        let err = RpcVerifier::with_rpc_for_chain(1, "http://127.0.0.1:1")
            .verify(&message, &text, &sig)
            .await
            .expect_err("connect fail");
        assert!(matches!(err, SiwxError::Backend { .. }), "got {err:?}");
        let rendered = err.to_string();
        assert!(!rendered.contains("http"), "URL leak: {rendered}");
        assert!(!rendered.contains("127.0.0.1"), "host leak: {rendered}");
    }
}
