use clap::{Parser, Subcommand};
use oc_core::OcError;
use oc_signer::{CryptoError, SignerError, hd::HdError, mnemonic::MnemonicError};

/// OneCipher CLI (Phase 1 — fully designed and implemented in accordance with the WalletConnect v2
/// protocol and the Open Wallet Standard, R77/AD-02/ponytail step 4).
#[derive(Parser)]
#[command(name = "onecipher", version = env!("OC_VERSION"), about, long_version = concat!(env!("OC_VERSION"), " (", env!("OC_GIT_COMMIT"), ")"), arg_required_else_help = true)]
pub(crate) struct Cli {
    /// Start the daemon (Key-Agent + WC v2 server + control socket) instead
    /// of running a one-shot command. The daemon connects outbound to the WC
    /// v2 relay and accepts pairing injection via a local control UDS.
    #[arg(long)]
    pub(crate) daemon: bool,

    /// Enable experimental commands (Intent, TUI secret creation).
    #[arg(long, global = true)]
    pub(crate) experimental: bool,

    #[command(subcommand)]
    pub(crate) command: Option<Commands>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Manage wallets
    Wallet {
        #[command(subcommand)]
        subcommand: WalletCommands,
    },
    /// Sign messages and transactions
    Sign {
        #[command(subcommand)]
        subcommand: SignCommands,
    },
    /// Generate and derive from mnemonics
    Mnemonic {
        #[command(subcommand)]
        subcommand: MnemonicCommands,
    },
    /// Fund a wallet with USDC via MoonPay
    Fund {
        #[command(subcommand)]
        subcommand: FundCommands,
    },
    /// Pay for x402-enabled API calls
    Pay {
        #[command(subcommand)]
        subcommand: PayCommands,
    },
    /// Manage policies for API key access control
    Policy {
        #[command(subcommand)]
        subcommand: PolicyCommands,
    },
    /// Manage API keys for agent access
    Key {
        #[command(subcommand)]
        subcommand: KeyCommands,
    },
    /// View configuration and RPC endpoints
    Config {
        #[command(subcommand)]
        subcommand: ConfigCommands,
    },
    /// Update onecipher to the latest release
    Update {
        /// Re-download even if already on the latest version
        #[arg(long)]
        force: bool,
    },
    /// Uninstall onecipher from the system
    Uninstall {
        /// Also remove all wallet data and config (~/.onecipher)
        #[arg(long)]
        purge: bool,
    },
    // === OneCipher Phase 1 subcommands (R50, R21-R27, R7, R33, R42) ===
    /// Audit log operations (R50; LOCAL — no RPC, reads audit log file)
    Audit {
        #[command(subcommand)]
        subcommand: AuditCommands,
    },
    /// Session key operations (R21-R27; RPC: CreateSessionKey/RevokeSessionKey/ListSessionKeys)
    SessionKey {
        #[command(subcommand)]
        subcommand: SessionKeyCommands,
    },
    /// OneCipher x402 payment (R7, R33; RPC: PayX402). Named `ocpay` because
    /// the legacy `pay` variant already occupies `Commands::Pay`.
    #[command(name = "ocpay")]
    OcPay {
        #[command(subcommand)]
        subcommand: OcPayCommands,
    },
    /// Show Key-Agent / Network-Agent status (LOCAL — no RPC)
    Status,
    /// Vault operations (LOCAL)
    Vault {
        #[command(subcommand)]
        subcommand: VaultCommands,
    },
    /// Backup operations (R42 — `.ocbk` container, LOCAL)
    Backup {
        #[command(subcommand)]
        subcommand: BackupCommands,
    },
    /// SBOM operations (T41 — CycloneDX SBOM verification, LOCAL)
    Sbom {
        #[command(subcommand)]
        subcommand: SbomCommands,
    },
    /// WalletConnect v2 operations
    Wc {
        #[command(subcommand)]
        subcommand: WcCommands,
    },
    /// Web UI operations
    Webui {
        #[command(subcommand)]
        subcommand: WebUiCommands,
    },
    /// Intent operations (Stage 2 — AI Agent Native)
    Intent {
        #[command(subcommand)]
        subcommand: IntentCommands,
    },
    /// Manage generic secrets (Phase 4 — unified vault)
    Secret {
        #[command(subcommand)]
        subcommand: SecretCommands,
    },
    /// Password management shortcuts (Phase 4 — unified vault)
    Password {
        #[command(subcommand)]
        subcommand: PasswordCommands,
    },
    /// TOTP management (Phase 4 — unified vault)
    Totp {
        #[command(subcommand)]
        subcommand: TotpCommands,
    },
    /// age encryption key management (Phase 4 — unified vault)
    Age {
        #[command(subcommand)]
        subcommand: AgeCommands,
    },
    /// Agent-mode secret operations (Phase 6 — API token mode).
    ///
    /// Reads the API token from ONECIPHER_PASSPHRASE, validates it against
    /// the key file, enforces SecretPermissions, and operates directly on
    /// the local SecretStore (R56: Key-Agent cannot depend on oc-secret).
    AgentSecret {
        #[command(subcommand)]
        subcommand: AgentSecretCommands,
    },
    /// Migrate legacy keystore v3 wallets to age-encrypted secrets
    Migrate {
        /// Dry run: report what would be migrated without writing any files
        #[arg(long)]
        dry_run: bool,
        /// Rollback a previous migration (remove migrated .age entries;
        /// legacy .json files are never deleted)
        #[arg(long)]
        rollback: bool,
    },
    /// Launch interactive TUI for browsing/copying/deleting secrets
    Tui,
    /// Git sync operations for the secrets vault (Stage 5)
    #[cfg(feature = "git")]
    Git {
        #[command(subcommand)]
        subcommand: GitCommands,
    },
}

// ===========================================================================
// OneCipher Phase 1 subcommand enums
// ===========================================================================

#[derive(Subcommand)]
pub(crate) enum AuditCommands {
    /// List audit log entries (R50: `onecipher audit list --since 24h --agent agent-01`)
    List {
        /// Filter entries since this duration (e.g. "24h", "7d", "1h30m")
        #[arg(long)]
        since: Option<String>,
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<String>,
        /// Filter by status (ALLOWED/DENIED)
        #[arg(long)]
        status: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum SessionKeyCommands {
    /// Create a new session key (RPC: CreateSessionKey)
    Create {
        /// Label for the session key
        #[arg(long)]
        label: String,
        /// Hex-encoded Passkey challenge nonce
        #[arg(long)]
        challenge: String,
        /// Hex-encoded Passkey signature
        #[arg(long)]
        signature: String,
        /// Passkey credential ID
        #[arg(long)]
        credential_id: String,
    },
    /// Revoke a session key (RPC: RevokeSessionKey)
    Revoke {
        /// Session key ID to revoke
        session_key_id: String,
        /// Hex-encoded Passkey challenge nonce
        #[arg(long)]
        challenge: String,
        /// Hex-encoded Passkey signature
        #[arg(long)]
        signature: String,
        /// Passkey credential ID
        #[arg(long)]
        credential_id: String,
    },
    /// List all session keys (RPC: ListSessionKeys)
    List,
}

#[derive(Subcommand)]
pub(crate) enum OcPayCommands {
    /// Pay for an x402-enabled API call (RPC: PayX402)
    X402 {
        /// URL to request
        url: String,
        /// Session key ID to pay with
        #[arg(long)]
        session_key: String,
        /// HTTP method (default: GET)
        #[arg(long, default_value = "GET")]
        method: String,
        /// Request body (JSON)
        #[arg(long)]
        body: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum VaultCommands {
    /// Unlock the vault (prompts for passphrase)
    Unlock,
}

#[derive(Subcommand)]
pub(crate) enum BackupCommands {
    /// Export wallet to .ocbk backup container
    Export {
        /// Output file path
        #[arg(long)]
        out: String,
    },
    /// Import wallet from .ocbk backup container
    Import {
        /// Input file path
        #[arg(long)]
        r#in: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum SbomCommands {
    /// Verify a CycloneDX SBOM file (T41)
    Verify {
        /// Path to the CycloneDX SBOM JSON file
        #[arg(long)]
        file: String,
    },
    /// Generate a CycloneDX SBOM for the workspace
    Generate {
        /// Output file path (default: sbom.cdx.json)
        #[arg(long, default_value = "sbom.cdx.json")]
        output: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum WcCommands {
    /// Generate a fresh WalletConnect pairing URI via the daemon (displays QR-ready URI)
    Pair {
        /// Time-to-live in seconds for the pairing (default: 86400 = 24h)
        #[arg(long)]
        ttl: Option<u64>,
    },
    /// Connect to a dApp via WalletConnect pairing URI
    Connect {
        /// WC v2 pairing URI (wc:<topic>@2?relay-protocol=...&symKey=...)
        uri: String,
    },
    /// List saved WalletConnect sessions
    Sessions,
    /// Disconnect a WalletConnect session by topic
    Disconnect {
        /// Session topic to disconnect
        topic: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum WebUiCommands {
    /// Open the Web UI in the default browser
    Open,
}

#[derive(Subcommand)]
pub(crate) enum IntentCommands {
    /// Submit an intent: simulate → confirm → execute (full lifecycle)
    Submit {
        /// Intent JSON spec (e.g. '{"type":"Pay","amount":"10.5 USDC","recipient":"0xABC"}')
        #[arg(long)]
        json: String,
        /// CAIP-2 chain ID (e.g. eip155:8453 for Base)
        #[arg(long)]
        chain: String,
        /// Session key ID to use for signing
        #[arg(long)]
        session_key: String,
        /// Sponsor mode: native (default), sponsored, payin-usdc
        #[arg(long, default_value = "native")]
        sponsor: String,
        /// Skip confirmation prompt (auto-confirm)
        #[arg(long)]
        yes: bool,
        /// Override RPC URL (currently unused; mock RPC is used)
        #[arg(long)]
        rpc_url: Option<String>,
    },
    /// Simulate an intent (dry-run — no execution, no signing)
    Simulate {
        /// Intent JSON spec
        #[arg(long)]
        json: String,
        /// CAIP-2 chain ID
        #[arg(long)]
        chain: String,
        /// Session key ID
        #[arg(long)]
        session_key: String,
        /// Override RPC URL (currently unused; mock RPC is used)
        #[arg(long)]
        rpc_url: Option<String>,
    },
    /// Execute an intent (skips simulation + prompt; for programmatic flows)
    Execute {
        /// Intent JSON spec
        #[arg(long)]
        json: String,
        /// CAIP-2 chain ID
        #[arg(long)]
        chain: String,
        /// Session key ID
        #[arg(long)]
        session_key: String,
        /// Sponsor mode: native (default), sponsored, payin-usdc
        #[arg(long, default_value = "native")]
        sponsor: String,
        /// Override RPC URL (currently unused; mock RPC is used)
        #[arg(long)]
        rpc_url: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum SecretCommands {
    /// List all secrets
    List {
        /// Filter by item type
        #[arg(long)]
        r#type: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Get a secret by name
    Get {
        /// Secret name
        name: String,
        /// Specific field to output (secret, notes, metadata)
        #[arg(long)]
        field: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Add a new secret
    Add {
        /// Secret name (path-like, e.g. "github/personal")
        name: String,
        /// Item type
        #[arg(long)]
        r#type: String,
        /// Metadata key=value pairs (e.g. --meta url=https://...)
        #[arg(long = "meta")]
        meta: Vec<String>,
        /// Read payload from stdin (JSON: {"secret":"...","notes":"..."})
        #[arg(long)]
        stdin: bool,
    },
    /// Update an existing secret
    Update {
        /// Secret name
        name: String,
        /// Specific field to update
        #[arg(long)]
        field: Option<String>,
        /// Read payload from stdin
        #[arg(long)]
        stdin: bool,
    },
    /// Delete a secret
    Delete {
        /// Secret name
        name: String,
    },
    /// Rename a secret
    Rename {
        /// Old name
        old: String,
        /// New name
        new: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PasswordCommands {
    /// Add a password
    Add {
        /// Secret name
        name: String,
        /// Associated URL
        #[arg(long)]
        url: String,
        /// Username
        #[arg(long)]
        username: String,
        /// Generate a random password
        #[arg(long)]
        generate: bool,
        /// Password length (default 32)
        #[arg(long, default_value_t = 32)]
        length: usize,
        /// Include symbols
        #[arg(long)]
        symbols: bool,
    },
    /// Get a password
    Get {
        /// Secret name
        name: String,
        /// Copy to clipboard
        #[arg(long)]
        copy: bool,
    },
    /// Generate a random password
    Generate {
        /// Password length (default 32)
        #[arg(long, default_value_t = 32)]
        length: usize,
        /// Include symbols
        #[arg(long)]
        symbols: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum TotpCommands {
    /// Add a TOTP secret
    Add {
        /// Secret name
        name: String,
        /// otpauth URI
        #[arg(long)]
        otpauth: Option<String>,
        /// Base32 secret (alternative to --otpauth)
        #[arg(long)]
        secret: Option<String>,
        /// Issuer (required with --secret)
        #[arg(long)]
        issuer: Option<String>,
        /// Account (required with --secret)
        #[arg(long)]
        account: Option<String>,
    },
    /// Generate current TOTP code
    Generate {
        /// Secret name
        name: String,
    },
    /// Output otpauth URI for a secret
    Uris {
        /// Secret name
        name: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum AgeCommands {
    /// Initialize age identity
    Init,
    /// Recipient management
    Recipient {
        #[command(subcommand)]
        subcommand: AgeRecipientCommands,
    },
    /// Show age public key
    IdentityShow,
    /// Re-encrypt all secrets with current recipients
    Reencrypt,
}

#[derive(Subcommand)]
pub(crate) enum AgeRecipientCommands {
    /// Add a recipient
    Add {
        /// age bech32 public key
        bech32: String,
    },
    /// List all recipients
    List,
    /// Remove a recipient
    Remove {
        /// age bech32 public key
        bech32: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum AgentSecretCommands {
    /// Read a secret by name (requires read_patterns permission)
    Get {
        /// Secret name (must match a read_patterns glob)
        #[arg(long)]
        name: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// List all secret index entries (requires at least one read pattern)
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Generate a TOTP code from a stored otpauth URI (requires allow_totp)
    Totp {
        /// Secret name holding the otpauth:// URI
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
#[cfg(feature = "git")]
pub(crate) enum GitCommands {
    /// Initialize a git repository in the vault root (optionally set origin remote)
    Init {
        /// Remote URL to set as `origin`
        #[arg(long)]
        remote: Option<String>,
    },
    /// Fetch from `origin` and merge into the current branch
    Pull,
    /// Push the current branch to `origin`
    Push,
    /// Show commit history (optionally for a single secret)
    Log {
        /// Show history for a specific secret name
        #[arg(long)]
        name: Option<String>,
    },
    /// Show working-tree status
    Status,
}

#[derive(Subcommand)]
pub(crate) enum WalletCommands {
    /// Create a new universal wallet (generates mnemonic, derives all chain addresses)
    Create {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Number of words (12 or 24)
        #[arg(long, default_value = "12")]
        words: u32,
        /// Display the generated mnemonic (DANGEROUS — only for backup)
        #[arg(long)]
        show_mnemonic: bool,
    },
    /// Import an existing wallet from a mnemonic or private key
    Import {
        /// Wallet name
        #[arg(long)]
        name: String,
        /// Import a mnemonic phrase (from ONECIPHER_MNEMONIC env or stdin)
        #[arg(long)]
        mnemonic: bool,
        /// Import a raw private key (from ONECIPHER_PRIVATE_KEY env or stdin)
        #[arg(long)]
        private_key: bool,
        /// Source chain for private key import (determines curve: evm/bitcoin/cosmos/tron =
        /// secp256k1, solana/ton = ed25519)
        #[arg(long)]
        chain: Option<String>,
        /// Account index for HD derivation (mnemonic only)
        #[arg(long, default_value = "0")]
        index: u32,
    },
    /// Export wallet secret (mnemonic or private key) to stdout
    Export {
        /// Wallet name or ID
        #[arg(long)]
        wallet: String,
    },
    /// Delete a wallet from the vault
    Delete {
        /// Wallet name or ID
        #[arg(long)]
        wallet: String,
        /// Confirm deletion (required)
        #[arg(long)]
        confirm: bool,
    },
    /// Rename a wallet
    Rename {
        /// Current wallet name or ID
        #[arg(long)]
        wallet: String,
        /// New wallet name
        #[arg(long)]
        new_name: String,
    },
    /// List all saved wallets
    List,
    /// Show vault path and supported chains
    Info,
}

#[derive(Clone, clap::ValueEnum)]
pub(crate) enum SignVia {
    /// Local signing with stored key
    Local,
    /// WalletConnect remote signing
    Wc,
}

#[derive(Subcommand)]
pub(crate) enum SignCommands {
    /// Sign a message with chain-specific formatting (EIP-191, Bitcoin message signing, etc.)
    Message {
        /// Chain name (ethereum, base, arbitrum, solana, ...), CAIP-2 ID (eip155:8453), or EVM
        /// chain ID (8453)
        #[arg(long)]
        chain: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "ONECIPHER_WALLET")]
        wallet: String,
        /// Message to sign
        #[arg(long)]
        message: String,
        /// Message encoding: "utf8" or "hex"
        #[arg(long, default_value = "utf8")]
        encoding: String,
        /// EIP-712 typed data JSON (EVM only)
        #[arg(long)]
        typed_data: Option<String>,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON instead of raw hex
        #[arg(long)]
        json: bool,
    },
    /// Sign a transaction (accepts hex-encoded unsigned transaction bytes)
    Tx {
        /// Chain name (ethereum, base, arbitrum, solana, ...), CAIP-2 ID (eip155:8453), or EVM
        /// chain ID (8453)
        #[arg(long)]
        chain: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "ONECIPHER_WALLET")]
        wallet: String,
        /// Hex-encoded unsigned transaction bytes
        #[arg(long)]
        tx: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON instead of raw hex
        #[arg(long)]
        json: bool,
        /// Signing backend: "local" (default) or "wc" (WalletConnect)
        #[arg(long, default_value = "local")]
        r#via: SignVia,
    },
    /// Sign and broadcast a transaction
    SendTx {
        /// Chain name (ethereum, base, arbitrum, solana, ...), CAIP-2 ID (eip155:8453), or EVM
        /// chain ID (8453)
        #[arg(long)]
        chain: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "ONECIPHER_WALLET")]
        wallet: String,
        /// Hex-encoded unsigned transaction bytes
        #[arg(long)]
        tx: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON instead of raw hex
        #[arg(long)]
        json: bool,
        /// Override configured RPC URL
        #[arg(long)]
        rpc_url: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum MnemonicCommands {
    /// Generate a new BIP-39 mnemonic phrase
    Generate {
        /// Number of words (12 or 24)
        #[arg(long, default_value = "12")]
        words: u32,
    },
    /// Derive an address from a mnemonic (reads from ONECIPHER_MNEMONIC env or stdin)
    Derive {
        /// Chain name (ethereum, base, arbitrum, solana, ...), CAIP-2 ID (eip155:8453), or EVM
        /// chain ID (8453). If omitted, derives all chains.
        #[arg(long)]
        chain: Option<String>,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
    },
}

#[derive(Subcommand)]
pub(crate) enum FundCommands {
    /// Create a MoonPay deposit — generates multi-chain deposit addresses that auto-convert to
    /// USDC
    Deposit {
        /// Wallet name or ID
        #[arg(long, env = "ONECIPHER_WALLET")]
        wallet: String,
        /// Target chain (default: base)
        #[arg(long, default_value = "base")]
        chain: String,
        /// Token to receive (default: USDC)
        #[arg(long, default_value = "USDC")]
        token: String,
    },
    /// Check token balances for a wallet
    Balance {
        /// Wallet name or ID
        #[arg(long, env = "ONECIPHER_WALLET")]
        wallet: String,
        /// Chain to check (default: base)
        #[arg(long, default_value = "base")]
        chain: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum PayCommands {
    /// Make a paid request to an x402-enabled API endpoint
    Request {
        /// The URL to request
        url: String,
        /// Wallet name or ID
        #[arg(long, env = "ONECIPHER_WALLET")]
        wallet: String,
        /// HTTP method
        #[arg(long, default_value = "GET")]
        method: String,
        /// Request body (JSON)
        #[arg(long)]
        body: Option<String>,
        /// Skip passphrase prompt (use empty passphrase)
        #[arg(long)]
        no_passphrase: bool,
    },
    /// Discover x402-enabled services from the Bazaar directory
    Discover {
        /// Search query (filters by URL and description)
        #[arg(long)]
        query: Option<String>,
        /// Max results per page (default 100)
        #[arg(long)]
        limit: Option<u64>,
        /// Offset into results for pagination
        #[arg(long)]
        offset: Option<u64>,
    },
}

#[derive(Subcommand)]
pub(crate) enum PolicyCommands {
    /// Register a policy from a JSON file
    Create {
        /// Path to the policy JSON file
        #[arg(long)]
        file: String,
    },
    /// List all registered policies
    List,
    /// Show details of a policy
    Show {
        /// Policy ID
        #[arg(long)]
        id: String,
    },
    /// Delete a policy
    Delete {
        /// Policy ID
        #[arg(long)]
        id: String,
        /// Confirm deletion (required)
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum KeyCommands {
    /// Create an API key for agent access to wallets
    Create {
        /// Key name (e.g. "claude-agent")
        #[arg(long)]
        name: String,
        /// Wallet name or ID (repeatable)
        #[arg(long = "wallet")]
        wallets: Vec<String>,
        /// Policy ID to attach (repeatable)
        #[arg(long = "policy")]
        policies: Vec<String>,
        /// Optional expiry timestamp (ISO-8601)
        #[arg(long)]
        expires_at: Option<String>,
    },
    /// List all API keys (tokens are never shown)
    List,
    /// Revoke (delete) an API key
    Revoke {
        /// API key ID
        #[arg(long)]
        id: String,
        /// Confirm revocation (required)
        #[arg(long)]
        confirm: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
    /// Show current configuration and RPC endpoints
    Show,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CliError {
    #[error("{0}")]
    Lws(#[from] OcError),
    #[error("{0}")]
    Lib(#[from] oc_wallet::OcWalletError),
    #[error("vault error: {0}")]
    Vault(#[from] oc_vault::OcVaultError),
    #[error("{0}")]
    Mnemonic(#[from] MnemonicError),
    #[error("{0}")]
    Hd(#[from] HdError),
    #[error("{0}")]
    Signer(#[from] SignerError),
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    #[error("{0}")]
    Pay(#[from] oc_pay::http::OcPayHttpError),
    #[cfg(feature = "git")]
    #[error("git error: {0}")]
    Git(#[from] oc_secret::git::GitError),
    #[error("secret store error: {0}")]
    SecretStore(#[from] oc_secret::SecretStoreError),
    #[error("recipient error: {0}")]
    Recipient(#[from] oc_secret::RecipientError),
    #[error("migration error: {0}")]
    Migration(#[from] oc_secret::migrate::MigrationError),
    #[error("{0}")]
    InvalidArgs(String),
    #[error("Network-Agent not available (Key-Agent daemon not reachable via UDS)")]
    NetAgentUnavailable,
    #[error("daemon init failed: {0}")]
    DaemonInit(String),
    #[error("key-agent error: {0}")]
    KeyAgent(String),
}

pub(crate) fn parse_chain(s: &str) -> Result<oc_core::Chain, CliError> {
    oc_core::parse_chain(s).map_err(CliError::InvalidArgs)
}
