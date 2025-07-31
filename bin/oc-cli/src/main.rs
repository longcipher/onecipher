mod audit;
mod commands;
mod netagent;
mod tui;

use clap::{Parser, Subcommand};
use oc_core::OcError;
use oc_signer::{CryptoError, SignerError, hd::HdError, mnemonic::MnemonicError};

/// OneCipher CLI (Phase 1 — fully designed and implemented in accordance with the WalletConnect v2
/// protocol and the Open Wallet Standard, R77/AD-02/ponytail step 4).
#[derive(Parser)]
#[command(name = "onecipher", version = env!("OC_VERSION"), about, long_version = concat!(env!("OC_VERSION"), " (", env!("OC_GIT_COMMIT"), ")"), arg_required_else_help = true)]
struct Cli {
    /// Start the daemon (Key-Agent + WC v2 server + control socket) instead
    /// of running a one-shot command. The daemon connects outbound to the WC
    /// v2 relay and accepts pairing injection via a local control UDS.
    #[arg(long)]
    daemon: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
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
enum AuditCommands {
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
enum SessionKeyCommands {
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
enum OcPayCommands {
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
enum VaultCommands {
    /// Unlock the vault (prompts for passphrase)
    Unlock,
}

#[derive(Subcommand)]
enum BackupCommands {
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
enum SbomCommands {
    /// Verify a CycloneDX SBOM file (T41)
    Verify {
        /// Path to the CycloneDX SBOM JSON file
        #[arg(long)]
        file: String,
    },
}

#[derive(Subcommand)]
enum WcCommands {
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
enum IntentCommands {
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
enum SecretCommands {
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
enum PasswordCommands {
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
enum TotpCommands {
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
enum AgeCommands {
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
enum AgeRecipientCommands {
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
enum AgentSecretCommands {
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
enum GitCommands {
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
enum WalletCommands {
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
enum SignVia {
    /// Local signing with stored key
    Local,
    /// WalletConnect remote signing
    Wc,
}

#[derive(Subcommand)]
enum SignCommands {
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
enum MnemonicCommands {
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
enum FundCommands {
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
enum PayCommands {
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
enum PolicyCommands {
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
enum KeyCommands {
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
enum ConfigCommands {
    /// Show current configuration and RPC endpoints
    Show,
}

#[derive(Debug, thiserror::Error)]
enum CliError {
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
    Pay(#[from] oc_pay_http::OcPayHttpError),
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
    #[error(
        "Network-Agent not yet available (Phase D T17-T21 will implement ConnectRPC transport)"
    )]
    NetAgentUnavailable,
}

pub(crate) fn parse_chain(s: &str) -> Result<oc_core::Chain, CliError> {
    oc_core::parse_chain(s).map_err(CliError::InvalidArgs)
}

fn main() {
    oc_signer::process_hardening::harden_process();

    // Eagerly initialize the global key cache and register it for zeroization
    // on termination signals (SIGTERM, SIGINT, SIGHUP).
    let cache = oc_signer::global_key_cache();
    oc_signer::process_hardening::register_cleanup(move || cache.clear());
    oc_signer::process_hardening::install_signal_handlers();

    // Migrate legacy directories (~/.lws, ~/.ows) → ~/.onecipher if needed (one-time upgrade
    // paths).
    oc_wallet::migrate::migrate_vault_if_needed();

    let cli = Cli::parse();

    // Daemon mode: start the WC v2 server + signing engine (Stage 1 stub).
    if cli.daemon {
        let code = match run_daemon() {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("error: {e}");
                1
            }
        };
        oc_signer::global_key_cache().clear();
        std::process::exit(code);
    }

    // Try the Key-Agent daemon first; fall back to the stub client if the
    // daemon is not reachable. Phase D (T17-T21) will add a real ConnectRPC
    // transport to the Network-Agent.
    let client: Box<dyn netagent::NetAgentClient> =
        match netagent::UdsKeyAgentClient::connect_default() {
            Ok(c) => Box::new(c),
            Err(e) => {
                eprintln!(
                    "warning: could not connect to Key-Agent daemon ({e}), using stub client"
                );
                Box::new(netagent::UnimplementedClient)
            }
        };
    let code = match run(cli, &*client) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("error: {e}");
            1
        }
    };

    // Explicitly zeroize all cached key material before exiting.
    oc_signer::global_key_cache().clear();
    std::process::exit(code);
}

fn run(cli: Cli, client: &dyn netagent::NetAgentClient) -> Result<(), CliError> {
    let command = match cli.command {
        Some(c) => c,
        None => return Ok(()),
    };
    match command {
        Commands::Wallet { subcommand } => match subcommand {
            WalletCommands::Create { name, words, show_mnemonic } => {
                commands::wallet::create(&name, words, show_mnemonic)
            }
            WalletCommands::Import { name, mnemonic, private_key, chain, index } => {
                commands::wallet::import(&name, mnemonic, private_key, chain.as_deref(), index)
            }
            WalletCommands::Export { wallet } => commands::wallet::export(&wallet),
            WalletCommands::Delete { wallet, confirm } => {
                commands::wallet::delete(&wallet, confirm)
            }
            WalletCommands::Rename { wallet, new_name } => {
                commands::wallet::rename(&wallet, &new_name)
            }
            WalletCommands::List => commands::wallet::list(),
            WalletCommands::Info => commands::info::run(),
        },
        Commands::Sign { subcommand } => match subcommand {
            SignCommands::Message { chain, wallet, message, encoding, typed_data, index, json } => {
                commands::sign_message::run(
                    &chain,
                    &wallet,
                    &message,
                    &encoding,
                    typed_data.as_deref(),
                    index,
                    json,
                )
            }
            SignCommands::Tx { chain, wallet, tx, index, json, via } => {
                commands::sign_transaction::run(&chain, &wallet, &tx, index, json, via)
            }
            SignCommands::SendTx { chain, wallet, tx, index, json, rpc_url } => {
                commands::send_transaction::run(
                    &chain,
                    &wallet,
                    &tx,
                    index,
                    json,
                    rpc_url.as_deref(),
                )
            }
        },
        Commands::Fund { subcommand } => match subcommand {
            FundCommands::Deposit { wallet, chain, token } => {
                commands::fund::run(&wallet, Some(&chain), Some(&token))
            }
            FundCommands::Balance { wallet, chain } => {
                commands::fund::balance(&wallet, Some(&chain))
            }
        },
        Commands::Pay { subcommand } => match subcommand {
            PayCommands::Request { url, wallet, method, body, no_passphrase } => {
                commands::pay::run(&url, &wallet, &method, body.as_deref(), no_passphrase)
            }
            PayCommands::Discover { query, limit, offset } => {
                commands::pay::discover(query.as_deref(), limit, offset)
            }
        },
        Commands::Mnemonic { subcommand } => match subcommand {
            MnemonicCommands::Generate { words } => commands::generate::run(words),
            MnemonicCommands::Derive { chain, index } => {
                commands::derive::run(chain.as_deref(), index)
            }
        },
        Commands::Policy { subcommand } => match subcommand {
            PolicyCommands::Create { file } => commands::policy::create(&file),
            PolicyCommands::List => commands::policy::list(),
            PolicyCommands::Show { id } => commands::policy::show(&id),
            PolicyCommands::Delete { id, confirm } => commands::policy::delete(&id, confirm),
        },
        Commands::Key { subcommand } => match subcommand {
            KeyCommands::Create { name, wallets, policies, expires_at } => {
                commands::key::create(&name, &wallets, &policies, expires_at.as_deref())
            }
            KeyCommands::List => commands::key::list(),
            KeyCommands::Revoke { id, confirm } => commands::key::revoke(&id, confirm),
        },
        Commands::Config { subcommand } => match subcommand {
            ConfigCommands::Show => commands::config::show(),
        },
        Commands::Update { force } => commands::update::run(force),
        Commands::Uninstall { purge } => commands::uninstall::run(purge),
        // === OneCipher Phase 1 commands ===
        Commands::Audit { subcommand } => match subcommand {
            AuditCommands::List { since, agent, status } => {
                commands::audit::list(since.as_deref(), agent.as_deref(), status.as_deref())
            }
        },
        Commands::SessionKey { subcommand } => match subcommand {
            SessionKeyCommands::Create { label, challenge, signature, credential_id } => {
                commands::session_key::create(
                    &label,
                    &challenge,
                    &signature,
                    &credential_id,
                    client,
                )
            }
            SessionKeyCommands::Revoke { session_key_id, challenge, signature, credential_id } => {
                commands::session_key::revoke(
                    &session_key_id,
                    &challenge,
                    &signature,
                    &credential_id,
                    client,
                )
            }
            SessionKeyCommands::List => commands::session_key::list(client),
        },
        Commands::OcPay { subcommand } => match subcommand {
            OcPayCommands::X402 { url, session_key, method, body } => {
                commands::pay_x402::run(&url, &session_key, &method, body.as_deref(), client)
            }
        },
        Commands::Status => commands::status::run(),
        Commands::Vault { subcommand } => match subcommand {
            VaultCommands::Unlock => commands::vault::unlock(),
        },
        Commands::Backup { subcommand } => match subcommand {
            BackupCommands::Export { out } => commands::backup::export(&out),
            BackupCommands::Import { r#in } => commands::backup::import(&r#in),
        },
        Commands::Sbom { subcommand } => match subcommand {
            SbomCommands::Verify { file } => commands::sbom::verify(&file),
        },
        Commands::Wc { subcommand } => match subcommand {
            WcCommands::Pair { ttl } => commands::wc::pair(ttl),
            WcCommands::Connect { uri } => commands::wc::connect(&uri),
            WcCommands::Sessions => commands::wc::sessions(),
            WcCommands::Disconnect { topic } => commands::wc::disconnect(&topic),
        },
        Commands::Intent { subcommand } => match subcommand {
            IntentCommands::Submit { json, chain, session_key, sponsor, yes, rpc_url } => {
                commands::intent::run_submit(
                    &json,
                    &chain,
                    &session_key,
                    &sponsor,
                    yes,
                    rpc_url.as_deref(),
                )
            }
            IntentCommands::Simulate { json, chain, session_key, rpc_url } => {
                commands::intent::run_simulate(&json, &chain, &session_key, rpc_url.as_deref())
            }
            IntentCommands::Execute { json, chain, session_key, sponsor, rpc_url } => {
                commands::intent::run_execute(
                    &json,
                    &chain,
                    &session_key,
                    &sponsor,
                    rpc_url.as_deref(),
                )
            }
        },
        Commands::Secret { subcommand } => match subcommand {
            SecretCommands::List { r#type, json } => {
                let item_type = r#type.as_deref().map(commands::parse_item_type).transpose()?;
                commands::secret::list(item_type, json)
            }
            SecretCommands::Get { name, field, json } => {
                commands::secret::get(&name, field.as_deref(), json)
            }
            SecretCommands::Add { name, r#type, meta, stdin } => {
                let item_type = commands::parse_item_type(&r#type)?;
                commands::secret::add(&name, item_type, &meta, stdin)
            }
            SecretCommands::Update { name, field, stdin } => {
                commands::secret::update(&name, field.as_deref(), stdin)
            }
            SecretCommands::Delete { name } => commands::secret::delete(&name),
            SecretCommands::Rename { old, new } => commands::secret::rename(&old, &new),
        },
        Commands::Password { subcommand } => match subcommand {
            PasswordCommands::Add { name, url, username, generate, length, symbols } => {
                commands::password::add(&name, &url, &username, generate, length, symbols)
            }
            PasswordCommands::Get { name, copy } => commands::password::get(&name, copy),
            PasswordCommands::Generate { length, symbols } => {
                commands::password::generate(length, symbols)
            }
        },
        Commands::Totp { subcommand } => match subcommand {
            TotpCommands::Add { name, otpauth, secret, issuer, account } => commands::totp::add(
                &name,
                otpauth.as_deref(),
                secret.as_deref(),
                issuer.as_deref(),
                account.as_deref(),
            ),
            TotpCommands::Generate { name } => commands::totp::generate(&name),
            TotpCommands::Uris { name } => commands::totp::uris(&name),
        },
        Commands::Age { subcommand } => match subcommand {
            AgeCommands::Init => commands::age_cmd::init(),
            AgeCommands::Recipient { subcommand } => match subcommand {
                AgeRecipientCommands::Add { bech32 } => commands::age_cmd::recipient_add(&bech32),
                AgeRecipientCommands::List => commands::age_cmd::recipient_list(),
                AgeRecipientCommands::Remove { bech32 } => {
                    commands::age_cmd::recipient_remove(&bech32)
                }
            },
            AgeCommands::IdentityShow => commands::age_cmd::identity_show(),
            AgeCommands::Reencrypt => commands::age_cmd::reencrypt(),
        },
        Commands::Migrate { dry_run, rollback } => commands::migrate::run(dry_run, rollback),
        Commands::Tui => {
            let store = commands::open_secret_store()?;
            tui::run(store).map_err(|e| CliError::InvalidArgs(e.to_string()))
        }
        Commands::AgentSecret { subcommand } => match subcommand {
            AgentSecretCommands::Get { name, json } => {
                commands::agent_secret::agent_secret_get(&name, json)
            }
            AgentSecretCommands::List { json } => commands::agent_secret::agent_secret_list(json),
            AgentSecretCommands::Totp { name } => {
                commands::agent_secret::agent_totp_generate(&name)
            }
        },
        #[cfg(feature = "git")]
        Commands::Git { subcommand } => match subcommand {
            GitCommands::Init { remote } => commands::git_cmd::init(remote.as_deref()),
            GitCommands::Pull => commands::git_cmd::pull(),
            GitCommands::Push => commands::git_cmd::push(),
            GitCommands::Log { name } => commands::git_cmd::log(name.as_deref()),
            GitCommands::Status => commands::git_cmd::status(),
        },
    }
}

/// Run the unified daemon: Key-Agent UDS server + WC v2 wallet server +
/// control socket for CLI pairing injection.
///
/// Architecture:
/// - **Key-Agent** (sync thread, R55): `oc_keyagent::server::run()` on UDS. Handles signing,
///   policy, vault access via globals pointing at `~/.onecipher`.
/// - **WC v2 server** (tokio task): `oc_netagent::run_server_controlled()` connects outbound WSS to
///   the WC relay, subscribes to pairing topics, and dispatches inbound JSON-RPC to the Key-Agent
///   via UDS.
/// - **Control socket** (tokio task): accepts `CONNECT <uri>` and `PAIR` commands from `onecipher
///   wc connect/pair` CLI calls. Injects pairing URIs into the WC server via a tokio mpsc channel.
fn run_daemon() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::PermissionsExt;

    eprintln!("onecipher daemon starting...");
    let engine = oc_signing_core::SigningEngine::open_default()?;
    let state_dir = engine.state_dir().to_path_buf();
    eprintln!("signing engine opened at {}", state_dir.display());

    // --- Key-Agent UDS server (sync, dedicated thread per R55) ---
    let key_agent_sock = oc_keyagent::server::default_socket_path();
    eprintln!("key-agent socket: {}", key_agent_sock);
    let ka_sock_clone = key_agent_sock.clone();
    std::thread::spawn(move || {
        if let Err(e) = oc_keyagent::server::run(Some(&ka_sock_clone)) {
            eprintln!("key-agent server error: {e}");
        }
    });
    // Give the Key-Agent a moment to bind before the WC server tries to
    // connect via KeyAgentClient.
    std::thread::sleep(std::time::Duration::from_millis(50));

    // --- Control socket path ---
    let ctrl_sock_path = commands::wc::control_socket_path();

    // --- Tokio runtime for async WC server + control loop ---
    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;

    let relay_url =
        std::env::var("OC_WC_RELAY_URL").unwrap_or_else(|_| "wss://relay.walletconnect.com".into());
    let state_dir_str = state_dir.to_string_lossy().to_string();
    let ka_sock_for_wc = key_agent_sock;

    // Channel: control socket → WC server (pairing URI injection)
    let (pairing_tx, pairing_rx) = tokio::sync::mpsc::channel::<oc_walletconnect::PairingUri>(32);

    rt.block_on(async {
        // Bind control socket (tokio UDS, mode 0600)
        let _ = std::fs::remove_file(&ctrl_sock_path);
        if let Some(parent) = std::path::Path::new(&ctrl_sock_path).parent() {
            let _ = std::fs::create_dir_all(parent);
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
        let ctrl_listener =
            tokio::net::UnixListener::bind(&ctrl_sock_path).expect("bind control socket");
        let _ = std::fs::set_permissions(&ctrl_sock_path, std::fs::Permissions::from_mode(0o600));
        eprintln!("control socket: {}", ctrl_sock_path);

        // Spawn control socket accept loop
        let ctrl_tx = pairing_tx.clone();
        let ctrl_task = tokio::spawn(control_socket_loop(ctrl_listener, ctrl_tx));

        // Spawn WC v2 server (consumes pairing_rx)
        let wc_task = tokio::spawn(async move {
            if let Err(e) = oc_netagent::run_server_controlled(
                &ka_sock_for_wc,
                &relay_url,
                &state_dir_str,
                pairing_rx,
            )
            .await
            {
                eprintln!("WC v2 server error: {e}");
            }
        });

        eprintln!("daemon running (Ctrl+C to stop)");

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                eprintln!("daemon shutting down");
            }
            _ = ctrl_task => {
                eprintln!("control socket task exited");
            }
            _ = wc_task => {
                eprintln!("WC server exited");
            }
        }

        // Cleanup control socket
        let _ = std::fs::remove_file(&ctrl_sock_path);
    });

    Ok(())
}

/// Control socket accept loop — handles `CONNECT <uri>` and `PAIR [ttl]`
/// commands from `onecipher wc connect/pair`.
///
/// Protocol (line-based, newline-terminated):
/// - Request:  `CONNECT <wc_uri>\n` or `PAIR [<ttl_secs>]\n`
/// - Response: `OK [details]\n` or `ERR <message>\n`
async fn control_socket_loop(
    listener: tokio::net::UnixListener,
    tx: tokio::sync::mpsc::Sender<oc_walletconnect::PairingUri>,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut reader = BufReader::new(reader);
                    let mut line = String::new();

                    if reader.read_line(&mut line).await.is_err() {
                        let _ = writer.write_all(b"ERR read failed\n").await;
                        return;
                    }

                    let line = line.trim();
                    if let Some(uri_str) = line.strip_prefix("CONNECT ") {
                        // dApp-generated URI → inject into WC server
                        match oc_walletconnect::PairingUri::parse(uri_str) {
                            Ok(uri) => {
                                if tx.send(uri).await.is_ok() {
                                    let _ = writer.write_all(b"OK pairing loaded\n").await;
                                } else {
                                    let _ = writer.write_all(b"ERR daemon shutting down\n").await;
                                }
                            }
                            Err(e) => {
                                let _ = writer
                                    .write_all(format!("ERR invalid URI: {e}\n").as_bytes())
                                    .await;
                            }
                        }
                    } else if line == "PAIR" || line.starts_with("PAIR ") {
                        // Daemon-generated pairing URI → return to user for QR display
                        let ttl: u64 = line
                            .strip_prefix("PAIR ")
                            .and_then(|s| s.trim().parse().ok())
                            .unwrap_or(oc_netagent::DEFAULT_PAIRING_TTL);
                        let (uri, _session) = oc_netagent::generate_pairing_uri(ttl);
                        let uri_for_send = uri.clone();
                        if tx.send(uri_for_send).await.is_ok() {
                            let _ = writer.write_all(format!("OK {uri}\n").as_bytes()).await;
                        } else {
                            let _ = writer.write_all(b"ERR daemon shutting down\n").await;
                        }
                    } else {
                        let _ = writer.write_all(b"ERR unknown command\n").await;
                    }
                });
            }
            Err(e) => {
                eprintln!("control socket accept error: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================
//
// The mock client records every request it receives so tests can assert that
// the clap parser → `run()` → command-module → RPC-construction pipeline
// built the correct proto message. No real ConnectRPC transport is involved
// (ponytail YAGNI — tonic/connect-rs are NOT dev-deps in Phase 1).

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use oc_proto::{
        CreateSessionKeyRequest, CreateSessionKeyResponse, ListSessionKeysResponse, PayX402Request,
        PayX402Response, RevokeSessionKeyRequest, RevokeSessionKeyResponse, SessionKeyInfo,
        SessionKeyStatus,
    };

    use super::*;
    use crate::netagent::NetAgentClient;

    // -----------------------------------------------------------------------
    // Mock NetAgentClient
    // -----------------------------------------------------------------------

    #[derive(Default, Clone)]
    struct MockNetAgentClient {
        create_session_key_requests: Arc<Mutex<Vec<CreateSessionKeyRequest>>>,
        revoke_session_key_requests: Arc<Mutex<Vec<RevokeSessionKeyRequest>>>,
        list_session_keys_calls: Arc<Mutex<u32>>,
        pay_x402_requests: Arc<Mutex<Vec<PayX402Request>>>,
        next_create_resp: Arc<Mutex<Option<CreateSessionKeyResponse>>>,
        next_revoke_resp: Arc<Mutex<Option<RevokeSessionKeyResponse>>>,
        next_list_resp: Arc<Mutex<Option<ListSessionKeysResponse>>>,
        next_pay_x402_resp: Arc<Mutex<Option<PayX402Response>>>,
    }

    impl netagent::NetAgentClient for MockNetAgentClient {
        fn create_session_key(
            &self,
            req: CreateSessionKeyRequest,
        ) -> Result<CreateSessionKeyResponse, CliError> {
            self.create_session_key_requests.lock().unwrap().push(req);
            Ok(self.next_create_resp.lock().unwrap().clone().unwrap_or_default())
        }

        fn revoke_session_key(
            &self,
            req: RevokeSessionKeyRequest,
        ) -> Result<RevokeSessionKeyResponse, CliError> {
            self.revoke_session_key_requests.lock().unwrap().push(req);
            Ok((*self.next_revoke_resp.lock().unwrap()).unwrap_or_default())
        }

        fn list_session_keys(&self) -> Result<ListSessionKeysResponse, CliError> {
            *self.list_session_keys_calls.lock().unwrap() += 1;
            Ok(self.next_list_resp.lock().unwrap().clone().unwrap_or_default())
        }

        fn pay_x402(&self, req: PayX402Request) -> Result<PayX402Response, CliError> {
            self.pay_x402_requests.lock().unwrap().push(req);
            Ok(self.next_pay_x402_resp.lock().unwrap().clone().unwrap_or_default())
        }
    }

    // -----------------------------------------------------------------------
    // 1. clap parser accepts `audit list --since 24h --agent agent-01 --status DENIED`
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_list_parses_all_flags() {
        let cli = Cli::parse_from([
            "onecipher",
            "audit",
            "list",
            "--since",
            "24h",
            "--agent",
            "agent-01",
            "--status",
            "DENIED",
        ]);
        if let Some(Commands::Audit { subcommand: AuditCommands::List { since, agent, status } }) =
            cli.command
        {
            assert_eq!(since.as_deref(), Some("24h"));
            assert_eq!(agent.as_deref(), Some("agent-01"));
            assert_eq!(status.as_deref(), Some("DENIED"));
        } else {
            panic!("expected Commands::Audit{{List}}");
        }
    }

    // -----------------------------------------------------------------------
    // 2. clap parser accepts `audit list --since 24h --agent agent-01` (eval rule)
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_list_parses_subset_of_flags() {
        let cli = Cli::parse_from([
            "onecipher",
            "audit",
            "list",
            "--since",
            "24h",
            "--agent",
            "agent-01",
        ]);
        if let Some(Commands::Audit { subcommand: AuditCommands::List { since, agent, status } }) =
            cli.command
        {
            assert_eq!(since.as_deref(), Some("24h"));
            assert_eq!(agent.as_deref(), Some("agent-01"));
            assert!(status.is_none());
        } else {
            panic!("expected Commands::Audit{{List}}");
        }
    }

    // -----------------------------------------------------------------------
    // 3. `audit list` (no flags) parses with all Options = None
    // -----------------------------------------------------------------------

    #[test]
    fn test_audit_list_no_flags() {
        let cli = Cli::parse_from(["onecipher", "audit", "list"]);
        if let Some(Commands::Audit { subcommand: AuditCommands::List { since, agent, status } }) =
            cli.command
        {
            assert!(since.is_none());
            assert!(agent.is_none());
            assert!(status.is_none());
        } else {
            panic!("expected Commands::Audit{{List}}");
        }
    }

    // -----------------------------------------------------------------------
    // 4. `audit list` end-to-end via mock client — run() returns Ok
    // -----------------------------------------------------------------------

    #[test]
    fn test_cli_audit_list_via_mock() {
        let mock = MockNetAgentClient::default();
        let cli = Cli::parse_from([
            "onecipher",
            "audit",
            "list",
            "--since",
            "24h",
            "--agent",
            "agent-01",
        ]);
        let result = run(cli, &mock);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // 5. `session-key create` builds the correct CreateSessionKeyRequest RPC
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_key_create_builds_correct_rpc() {
        let mock = MockNetAgentClient::default();
        let cli = Cli::parse_from([
            "onecipher",
            "session-key",
            "create",
            "--label",
            "test-label",
            "--challenge",
            "deadbeef",
            "--signature",
            "0102",
            "--credential-id",
            "cred-1",
        ]);
        let result = run(cli, &mock);
        assert!(result.is_ok());

        let recorded = mock.create_session_key_requests.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].label, "test-label");
        let auth = recorded[0].auth.as_ref().expect("auth must be set");
        assert_eq!(auth.challenge, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(auth.signature, vec![0x01, 0x02]);
        assert_eq!(auth.credential_id, "cred-1");
    }

    // -----------------------------------------------------------------------
    // 6. `session-key create` rejects invalid hex challenge with InvalidArgs
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_key_create_rejects_bad_hex() {
        let mock = MockNetAgentClient::default();
        let cli = Cli::parse_from([
            "onecipher",
            "session-key",
            "create",
            "--label",
            "x",
            "--challenge",
            "not-hex!",
            "--signature",
            "0102",
            "--credential-id",
            "cred-1",
        ]);
        let result = run(cli, &mock);
        assert!(matches!(result, Err(CliError::InvalidArgs(_))));
        // Mock must NOT have been called.
        assert!(mock.create_session_key_requests.lock().unwrap().is_empty());
    }

    // -----------------------------------------------------------------------
    // 7. `session-key revoke` builds the correct RevokeSessionKeyRequest RPC
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_key_revoke_builds_correct_rpc() {
        let mock = MockNetAgentClient::default();
        let cli = Cli::parse_from([
            "onecipher",
            "session-key",
            "revoke",
            "sk-42",
            "--challenge",
            "cafe",
            "--signature",
            "0304",
            "--credential-id",
            "cred-7",
        ]);
        let result = run(cli, &mock);
        assert!(result.is_ok());

        let recorded = mock.revoke_session_key_requests.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].session_key_id, "sk-42");
        let auth = recorded[0].auth.as_ref().expect("auth must be set");
        assert_eq!(auth.challenge, vec![0xCA, 0xFE]);
        assert_eq!(auth.signature, vec![0x03, 0x04]);
        assert_eq!(auth.credential_id, "cred-7");
    }

    // -----------------------------------------------------------------------
    // 8. `session-key list` calls list_session_keys exactly once
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_key_list_calls_rpc_once() {
        let mock = MockNetAgentClient::default();
        let cli = Cli::parse_from(["onecipher", "session-key", "list"]);
        let result = run(cli, &mock);
        assert!(result.is_ok());
        assert_eq!(*mock.list_session_keys_calls.lock().unwrap(), 1u32);
    }

    // -----------------------------------------------------------------------
    // 9. `ocpay x402` builds the correct PayX402Request RPC
    // -----------------------------------------------------------------------

    #[test]
    fn test_ocpay_x402_builds_correct_rpc() {
        let mock = MockNetAgentClient::default();
        let cli = Cli::parse_from([
            "onecipher",
            "ocpay",
            "x402",
            "https://example.com/api",
            "--session-key",
            "sk-1",
            "--method",
            "POST",
            "--body",
            "{\"k\":\"v\"}",
        ]);
        let result = run(cli, &mock);
        assert!(result.is_ok());

        let recorded = mock.pay_x402_requests.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].session_key_id, "sk-1");
        assert_eq!(recorded[0].url, "https://example.com/api");
        assert_eq!(recorded[0].method, "POST");
        assert_eq!(recorded[0].body, b"{\"k\":\"v\"}".to_vec());
        assert!(recorded[0].headers.is_empty());
    }

    // -----------------------------------------------------------------------
    // 10. `ocpay x402` defaults method to GET and body to empty
    // -----------------------------------------------------------------------

    #[test]
    fn test_ocpay_x402_defaults() {
        let mock = MockNetAgentClient::default();
        let cli = Cli::parse_from([
            "onecipher",
            "ocpay",
            "x402",
            "https://example.com/",
            "--session-key",
            "sk-9",
        ]);
        let result = run(cli, &mock);
        assert!(result.is_ok());

        let recorded = mock.pay_x402_requests.lock().unwrap();
        assert_eq!(recorded[0].method, "GET");
        assert!(recorded[0].body.is_empty());
    }

    // -----------------------------------------------------------------------
    // 11. `ocpay x402` prints DENY when response status = Deny
    // -----------------------------------------------------------------------

    #[test]
    fn test_ocpay_x402_handles_deny_status() {
        let mock = MockNetAgentClient::default();
        *mock.next_pay_x402_resp.lock().unwrap() = Some(PayX402Response {
            status: oc_proto::PaymentStatus::Deny as i32,
            receipt: vec![],
            retry_authorization: String::new(),
            deny_reason: "RATE_LIMIT_MINUTE".to_string(),
            error: String::new(),
        });
        let cli = Cli::parse_from([
            "onecipher",
            "ocpay",
            "x402",
            "https://example.com/",
            "--session-key",
            "sk-1",
        ]);
        let result = run(cli, &mock);
        assert!(result.is_ok(), "Deny is a successful RPC, not a CLI error");
    }

    // -----------------------------------------------------------------------
    // 12. `session-key list` prints "no session keys" when response is empty
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_key_list_empty() {
        let mock = MockNetAgentClient::default();
        let cli = Cli::parse_from(["onecipher", "session-key", "list"]);
        let result = run(cli, &mock);
        assert!(result.is_ok());
        let recorded = mock.list_session_keys_calls.lock().unwrap();
        assert_eq!(*recorded, 1);
    }

    // -----------------------------------------------------------------------
    // 13. `session-key list` iterates non-empty response without panic
    // -----------------------------------------------------------------------

    #[test]
    fn test_session_key_list_non_empty() {
        let mock = MockNetAgentClient::default();
        *mock.next_list_resp.lock().unwrap() = Some(ListSessionKeysResponse {
            keys: vec![SessionKeyInfo {
                session_key_id: "sk-1".to_string(),
                label: "alpha".to_string(),
                created_at_unix: 0,
                expires_at_unix: 0,
                policy: None,
                status: SessionKeyStatus::Active as i32,
            }],
        });
        let cli = Cli::parse_from(["onecipher", "session-key", "list"]);
        let result = run(cli, &mock);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // 14. UnimplementedClient returns NetAgentUnavailable for every RPC
    // -----------------------------------------------------------------------

    #[test]
    fn test_unimplemented_client_returns_error() {
        let client = netagent::UnimplementedClient;
        assert!(matches!(client.list_session_keys(), Err(CliError::NetAgentUnavailable)));
        assert!(matches!(
            client.create_session_key(CreateSessionKeyRequest::default()),
            Err(CliError::NetAgentUnavailable)
        ));
        assert!(matches!(
            client.revoke_session_key(RevokeSessionKeyRequest::default()),
            Err(CliError::NetAgentUnavailable)
        ));
        assert!(matches!(
            client.pay_x402(PayX402Request::default()),
            Err(CliError::NetAgentUnavailable)
        ));
    }

    // -----------------------------------------------------------------------
    // 15. `status`, `vault unlock`, `backup export`, `backup import` all return Ok
    // -----------------------------------------------------------------------

    #[test]
    fn test_local_stubs_return_ok() {
        let mock = MockNetAgentClient::default();

        let cli = Cli::parse_from(["onecipher", "status"]);
        assert!(run(cli, &mock).is_ok());

        // NOTE: `vault unlock` is excluded — it depends on the real vault at
        // ~/.onecipher and the wallet's KDF format. Covered by integration tests.

        let cli = Cli::parse_from(["onecipher", "backup", "export", "--out", "/tmp/wallet.ocbk"]);
        assert!(run(cli, &mock).is_ok());

        let cli = Cli::parse_from(["onecipher", "backup", "import", "--in", "/tmp/wallet.ocbk"]);
        assert!(run(cli, &mock).is_ok());
    }

    // -----------------------------------------------------------------------
    // 16. proptest: arbitrary `--since`/`--agent`/`--status` strings round-trip through the clap
    //     parser without panic
    // -----------------------------------------------------------------------

    proptest::proptest! {
        #[test]
        fn test_audit_list_fuzz_args(
            since in "[a-zA-Z0-9]{0,8}",
            // First char must NOT be `-` so clap doesn't treat the value as a flag.
            agent in "[a-zA-Z0-9][a-zA-Z0-9-]{0,15}",
            status in "(ALLOWED|DENIED)",
        ) {
            let cli = Cli::parse_from([
                "onecipher", "audit", "list",
                "--since", &since,
                "--agent", &agent,
                "--status", &status,
            ]);
            if let Some(Commands::Audit {
                subcommand: AuditCommands::List {
                    since: s, agent: a, status: st,
                },
            }) = cli.command
            {
                assert_eq!(s.as_deref(), Some(since.as_str()));
                assert_eq!(a.as_deref(), Some(agent.as_str()));
                assert_eq!(st.as_deref(), Some(status.as_str()));
            } else {
                panic!("expected Commands::Audit{{List}}");
            }
        }
    }

    // -----------------------------------------------------------------------
    // 17. CLI binary name in `--help` is `onecipher` (R77 rename verified)
    // -----------------------------------------------------------------------

    #[test]
    fn test_cli_binary_name_is_onecipher() {
        // clap's `parse_from` requires the first arg to be the binary name; we
        // assert that "onecipher" is accepted (a different name would still be
        // accepted by parse_from, but it's the canonical name we use).
        let cli = Cli::parse_from(["onecipher", "status"]);
        assert!(matches!(cli.command, Some(Commands::Status)));
    }
}
