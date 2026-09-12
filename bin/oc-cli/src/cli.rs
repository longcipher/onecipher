use clap::{Parser, Subcommand};
use oc_core::OcError;
use oc_signer::{SignerError, hd::HdError, mnemonic::MnemonicError};
use oc_vault::crypto::CryptoError;

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

    /// Internal: run as a one-shot per-request enclave child
    /// (`oc_keyagent::enclave::run_enclave_child`). Spawned by the parent via
    /// `current_exe --enclave-child`; never invoked directly by users.
    #[arg(long, hide = true)]
    pub(crate) enclave_child: bool,

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
    /// Generate vanity addresses by brute-force matching
    Vanity {
        /// Address must start with this hex pattern
        #[arg(long)]
        starts_with: Option<String>,
        /// Address must end with this hex pattern
        #[arg(long)]
        ends_with: Option<String>,
        /// Number of matching wallets to generate
        #[arg(long, default_value = "1")]
        count: usize,
        /// Number of parallel threads
        #[arg(long)]
        jobs: Option<usize>,
        /// Save results to JSON file (append mode)
        #[arg(long)]
        save_path: Option<std::path::PathBuf>,
        /// Encrypt and save to vault
        #[arg(long)]
        save_to_vault: bool,
    },
    /// Verify a cryptographic signature
    Verify {
        /// Signer address (hex)
        #[arg(long)]
        address: String,
        /// Message to verify (personal_sign by default)
        #[arg(long, group = "input")]
        message: Option<String>,
        /// EIP-712 typed data JSON string
        #[arg(long, group = "input")]
        typed_data: Option<String>,
        /// Path to EIP-712 typed data JSON file
        #[arg(long, group = "input")]
        typed_data_file: Option<String>,
        /// Raw 32-byte hash (use with --no-hash)
        #[arg(long, group = "input")]
        hash: Option<String>,
        /// Treat --hash as pre-hashed value (no EIP-191 prefix)
        #[arg(long, requires = "hash")]
        no_hash: bool,
        /// Signature to verify (hex)
        #[arg(long)]
        signature: String,
        /// Chain type (default: evm)
        #[arg(long, default_value = "evm")]
        chain: String,
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
        /// Skip the interactive confirmation prompt (required with
        /// ONECIPHER_JSON_ERRORS=1, which refuses to prompt)
        #[arg(long)]
        force: bool,
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
    /// Show Key-Agent / Network-Agent status (LOCAL — no RPC)
    Status,
    /// Manage the onecipher daemon as a systemd user service (LOCAL)
    Service {
        #[command(subcommand)]
        subcommand: ServiceCommands,
    },
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
    /// Run a command with secrets injected as environment variables
    Env {
        /// Secret names to inject (repeatable, or directory prefix for batch)
        #[arg(long = "name")]
        names: Vec<String>,
        /// Direct `KEY=VALUE` pairs to inject (repeatable; full KEY kept as-is
        /// to avoid collisions after case/`.` normalization)
        #[arg(long = "set", short = 'e')]
        set: Vec<String>,
        /// Prompt for a value for KEY on stdin without echoing (repeatable;
        /// value is `Zeroizing` and binary/NUL input is rejected)
        #[arg(long = "prompt", short = 'p')]
        prompt: Vec<String>,
        /// Keep original key case (default: uppercase)
        #[arg(long)]
        keep_case: bool,
        /// Use exec(3) to replace current process
        #[arg(long)]
        exec: bool,
        /// Command to run
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
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
    /// Search inside decrypted secret content
    Grep {
        /// Search pattern (case-insensitive substring, or regex with --regex)
        pattern: String,
        /// Use regex matching
        #[arg(long, short)]
        regex: bool,
        /// Output as JSON
        #[arg(long, short)]
        json: bool,
    },
    /// Search secrets with fuzzy matching
    Find {
        /// Search query
        query: Option<String>,
        /// Use regex matching
        #[arg(long, short)]
        regex: bool,
        /// Output as JSON
        #[arg(long, short)]
        json: bool,
        /// Filter by item type
        #[arg(long)]
        r#type: Option<String>,
    },
    /// Launch interactive TUI for browsing/copying/deleting secrets
    Tui,
    /// Run diagnostics to check system health
    Doctor {
        /// Show passing checks too
        #[arg(long, short)]
        verbose: bool,
        /// Render the report as JSON (single-source with the human view)
        #[arg(long)]
        json: bool,
        /// Rebuild the generations floor from readable secrets; unreadable
        /// entries are reported as `skipped[]` (remove + re-insert them)
        #[arg(long = "repair-generations")]
        repair_generations: bool,
    },
    /// Generate shell completion scripts
    Completion {
        /// Shell to generate completions for (bash, zsh, fish, powershell, elvish)
        shell: String,
    },
    /// Check and repair secret store integrity
    Fsck {
        /// Automatically fix issues
        #[arg(long)]
        fix: bool,
        /// Decrypt and re-encrypt all secrets (for key rotation validation)
        #[arg(long)]
        decrypt: bool,
    },
    /// Show version history of a secret (H3)
    #[cfg(feature = "git")]
    History {
        /// Secret name
        name: String,
        /// Show password in history output
        #[arg(long, short)]
        password: bool,
        /// Maximum number of entries to show
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Output as JSON
        #[arg(long, short)]
        json: bool,
    },
    /// Git sync operations for the secrets vault (Stage 5)
    #[cfg(feature = "git")]
    Git {
        #[command(subcommand)]
        subcommand: GitCommands,
    },
    /// Expose a loopback JSON-RPC 2.0 server (WalletSigner for ledgerflow)
    WalletRpc {
        #[command(subcommand)]
        subcommand: WalletRpcCommands,
    },
    /// Send an ERC-20 token transfer (cast-style: build, sign, broadcast)
    Send {
        /// Chain name (ethereum, base, arbitrum, ...), CAIP-2 ID (eip155:8453), or EVM chain ID
        #[arg(long)]
        chain: String,
        /// Recipient address (0x...)
        #[arg(long)]
        to: String,
        /// ERC-20 token address (0x...)
        #[arg(long)]
        token: String,
        /// Amount in base units (integer string, e.g. "1000000" for 1.0 USDC with 6 decimals)
        #[arg(long)]
        amount: String,
        /// Wallet name or ID (uses stored encrypted mnemonic)
        #[arg(long, env = "ONECIPHER_WALLET")]
        wallet: String,
        /// RPC URL for the target chain
        #[arg(long)]
        rpc_url: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Gas limit override (otherwise estimated on-chain)
        #[arg(long)]
        gas_limit: Option<u64>,
        /// Output structured JSON
        #[arg(long)]
        json: bool,
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
    /// Audit secrets for security issues (weak, duplicate, old passwords)
    Secrets {
        /// Output format: text, json
        #[arg(long, default_value = "text")]
        format: String,
        /// Maximum password age in days
        #[arg(long, default_value_t = 365)]
        max_age: u64,
        /// Skip breach detection (HaveIBeenPwned k-anonymity API)
        #[arg(long)]
        skip_hibp: bool,
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
pub(crate) enum VaultCommands {
    /// Unlock the vault (prompts for passphrase)
    Unlock,
}

#[derive(Subcommand)]
pub(crate) enum ServiceCommands {
    /// Install the daemon as a systemd user service (writes
    /// `~/.config/systemd/user/onecipher.service` and enables it)
    Install,
    /// Stop, disable and remove the systemd user service
    Uninstall,
    /// Show whether the service unit file exists and (best-effort) the
    /// `systemctl --user status` output
    Status,
}

#[derive(Subcommand)]
pub(crate) enum BackupCommands {
    /// Export wallets to an age-encrypted .ocbk backup bundle
    Export {
        /// Output file path
        #[arg(long)]
        out: String,
        /// Age recipient (`age1...`) to encrypt the bundle to.
        /// Repeat for multiple recipients; every listed recipient can
        /// independently decrypt the bundle.
        #[arg(long = "recipient")]
        recipients: Vec<String>,
    },
    /// Import wallets from an age-encrypted .ocbk backup bundle
    Import {
        /// Input file path
        #[arg(long)]
        r#in: String,
        /// Age identity (`AGE-SECRET-KEY-1...`) of one of the export
        /// recipients. When omitted, it is read hidden from the terminal.
        #[arg(long)]
        identity: Option<String>,
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
    /// Configure the WC v2 relay endpoint (persisted to ~/.onecipher/config.json)
    Relay {
        /// Relay WSS URL (e.g. wss://relay.walletconnect.com, wss://127.0.0.1:7443)
        url: String,
        /// WalletConnect Cloud project ID (required for relay.walletconnect.com)
        #[arg(long)]
        project_id: Option<String>,
    },
    /// Probe the relay: subscribe to a fresh topic, publish a ping, and wait
    /// for the echo (diagnostic for testing WC v2 connectivity)
    Probe {
        /// Relay URL (default: configured or OC_WC_RELAY_URL or built-in)
        #[arg(long)]
        url: Option<String>,
        /// Project ID for the relay
        #[arg(long)]
        project_id: Option<String>,
        /// How many seconds to wait for the echo (default 10)
        #[arg(long, default_value_t = 10)]
        timeout: u64,
    },
    /// Send a JSON-RPC request on the bound session as a dApp (testing aid)
    DappSend {
        /// Session topic (from `wc sessions` or the pairing topic)
        topic: String,
        /// JSON-RPC method (e.g. personal_sign, eth_sendTransaction)
        method: String,
        /// JSON params object (e.g. '{"data":"0xdead"}')
        params: String,
        /// SymKey hex for the session (from the pairing URI or wc_dapp.json)
        #[arg(long)]
        sym_key: Option<String>,
        /// Relay URL override
        #[arg(long)]
        url: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum WebUiCommands {
    /// Open the Web UI in the default browser
    Open,
    /// Inspect and resolve pending signing approvals (non-interactive bridge
    /// to the daemon's local HTTP API)
    Approval {
        #[command(subcommand)]
        subcommand: ApprovalCommands,
    },
    /// Query Web UI auth / passkey session state (non-interactive)
    Auth {
        #[command(subcommand)]
        subcommand: AuthCommands,
    },
}

#[derive(Subcommand)]
pub(crate) enum ApprovalCommands {
    /// List all pending signing approvals
    List,
    /// Show a single pending approval by ID
    Show {
        /// Approval ID (UUID)
        id: String,
    },
    /// Approve a pending signing request
    Approve {
        /// Approval ID (UUID)
        id: String,
        /// Skip the interactive confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },
    /// Reject a pending signing request
    Reject {
        /// Approval ID (UUID)
        id: String,
        /// Rejection reason (shown in the audit trail)
        #[arg(long)]
        reason: Option<String>,
        /// Skip the interactive confirmation prompt
        #[arg(long, short)]
        yes: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum AuthCommands {
    /// Show whether a Web UI session / passkey registration exists
    Status,
    /// Expire all Web UI sessions (lock)
    Lock,
    /// Show whether first-time passkey registration is still needed
    Bootstrap,
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
        /// Skip confirmation prompt (auto-confirm)
        #[arg(long)]
        yes: bool,
        /// Override RPC URL (currently unused; mock RPC is used)
        #[arg(long)]
        rpc_url: Option<String>,
        /// Sender address used to fetch the transaction nonce (M-04a);
        /// required for Pay / CrossChainTransfer execution
        #[arg(long)]
        from: Option<String>,
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
        /// Override RPC URL (currently unused; mock RPC is used)
        #[arg(long)]
        rpc_url: Option<String>,
        /// Sender address used to fetch the transaction nonce (M-04a);
        /// required for Pay / CrossChainTransfer execution
        #[arg(long)]
        from: Option<String>,
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
        /// Display secret as QR code in terminal
        #[arg(long)]
        qr: bool,
        /// Copy the secret value to the clipboard (auto-clears after timeout)
        #[arg(long)]
        copy: bool,
        /// Clipboard auto-clear timeout in seconds (default 45, 0 = never clear)
        #[arg(long, default_value_t = 45)]
        timeout: u64,
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
        /// Confirm deletion (required: deletion is irreversible)
        #[arg(long)]
        force: bool,
    },
    /// Rename a secret
    Rename {
        /// Old name
        old: String,
        /// New name
        new: String,
    },
    /// Edit a secret in $EDITOR
    Edit {
        /// Secret name
        name: String,
        /// Editor to use (overrides $EDITOR)
        #[arg(long)]
        editor: Option<String>,
    },
    /// Copy a secret to a new name
    Copy {
        /// Source secret name
        src: String,
        /// Destination secret name
        dst: String,
        /// Overwrite if destination exists
        #[arg(long, short)]
        force: bool,
    },
    /// Move a secret to a new name
    Move {
        /// Source secret name
        src: String,
        /// Destination secret name
        dst: String,
        /// Overwrite if destination exists
        #[arg(long, short)]
        force: bool,
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
        /// Clipboard auto-clear timeout in seconds (default 45, 0 = never clear)
        #[arg(long, default_value_t = 45)]
        timeout: u64,
        /// Output the unified secret envelope as JSON
        #[arg(long)]
        json: bool,
    },
    /// Generate a random password
    Generate {
        /// Password length (default 32)
        #[arg(long, default_value_t = 32)]
        length: usize,
        /// Include symbols
        #[arg(long)]
        symbols: bool,
        /// Generator strategy: cryptic (default), memorable, xkcd
        #[arg(long, default_value = "cryptic")]
        generator: String,
        /// XKCD word separator (xkcd generator only)
        #[arg(long, default_value = "-")]
        xkcd_sep: String,
        /// Number of XKCD words
        #[arg(long, default_value_t = 4)]
        xkcd_words: usize,
        /// Display password as QR code in terminal
        #[arg(long)]
        qr: bool,
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
        /// Bare base32 secret (alternative to --otpauth). Short 80/96-bit
        /// seeds are accepted; defaults to SHA-1, 6 digits, 30s period.
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
        /// Display TOTP code as QR code in terminal
        #[arg(long)]
        qr: bool,
        /// Output `{"name","kind","code"}` as JSON
        #[arg(long)]
        json: bool,
    },
    /// Output otpauth URI for a secret
    Uris {
        /// Secret name
        name: String,
        /// Output the unified secret envelope as JSON
        #[arg(long)]
        json: bool,
    },
    /// Generate HOTP code
    Hotp {
        /// Secret name
        name: String,
        /// Counter value
        #[arg(long)]
        counter: u64,
        /// Increment counter after generation
        #[arg(long)]
        increment: bool,
        /// Output `{"name","kind","counter","code"}` as JSON
        #[arg(long)]
        json: bool,
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
        /// Number of words (12, 15, 18, 21, or 24)
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
        /// Interactive import mode (prompts for mnemonic or private key)
        #[arg(long)]
        interactive: bool,
    },
    /// Export wallet secret (mnemonic or private key) to stdout
    Export {
        /// Wallet name or ID
        #[arg(long)]
        wallet: String,
        /// Export the public key instead of the secret
        #[arg(long)]
        public_key: bool,
        /// Chain for public key derivation (default: evm)
        #[arg(long)]
        chain: Option<String>,
        /// Export compressed public key (secp256k1 only)
        #[arg(long)]
        compressed: bool,
    },
    /// Delete a wallet from the vault
    Delete {
        /// Wallet name or ID
        #[arg(long)]
        wallet: String,
        /// Confirm deletion (required; `--force` is accepted as an alias)
        #[arg(long)]
        confirm: bool,
        /// Alias for `--confirm` (unified destructive-action contract)
        #[arg(long)]
        force: bool,
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
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show vault path and supported chains
    Info,
    /// Change wallet encryption passphrase
    ChangePassword {
        /// Wallet name or ID
        #[arg(long)]
        wallet: String,
        /// Current passphrase (non-interactive; falls back to ONECIPHER_PASSPHRASE)
        #[arg(long)]
        passphrase: Option<String>,
        /// New passphrase (non-interactive; falls back to ONECIPHER_NEW_PASSPHRASE)
        #[arg(long)]
        new_passphrase: Option<String>,
    },
}

#[derive(Subcommand)]
pub(crate) enum WalletRpcCommands {
    /// Start the loopback JSON-RPC 2.0 server (WalletSigner for ledgerflow)
    Serve {
        /// Bind address (default: 127.0.0.1:18080)
        #[arg(long, default_value = "127.0.0.1:18080")]
        listen: String,
        /// Wallet name or ID to sign with (default: "default")
        #[arg(long, default_value = "default")]
        wallet: String,
        /// Account index for HD derivation (default: 0)
        #[arg(long, default_value = "0")]
        index: u32,
    },
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
        /// Message to sign (optional when --typed-data is provided)
        #[arg(long, required_unless_present = "typed_data")]
        message: Option<String>,
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
    /// Sign an EIP-7702 authorization (delegate address + chain ID + nonce)
    Auth {
        /// Chain name or CAIP-2 ID (e.g. "ethereum", "eip155:1")
        #[arg(long)]
        chain: String,
        /// Wallet name or ID
        #[arg(long, env = "ONECIPHER_WALLET")]
        wallet: String,
        /// Delegate address to authorize (hex)
        #[arg(long)]
        address: String,
        /// Authorization nonce
        #[arg(long)]
        nonce: String,
        /// Account index
        #[arg(long, default_value = "0")]
        index: u32,
        /// Output structured JSON
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum MnemonicCommands {
    /// Generate a new BIP-39 mnemonic phrase
    Generate {
        /// Number of words (12, 15, 18, 21, or 24)
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
        /// Custom BIP-32 derivation path (e.g. "m/44'/60'/0'/0/5")
        #[arg(long)]
        path: Option<String>,
        /// Number of consecutive addresses to derive (single chain only)
        #[arg(long)]
        count: Option<u32>,
        /// Also show the private key (DANGEROUS)
        #[arg(long)]
        show_private_key: bool,
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
        /// Confirm deletion (required; `--force` is accepted as an alias)
        #[arg(long)]
        confirm: bool,
        /// Alias for `--confirm` (unified destructive-action contract)
        #[arg(long)]
        force: bool,
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
        /// Confirm revocation (required; `--force` is accepted as an alias)
        #[arg(long)]
        confirm: bool,
        /// Alias for `--confirm` (unified destructive-action contract)
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum ConfigCommands {
    /// Show current configuration and RPC endpoints
    Show,
    /// Set a configuration value
    Set {
        /// Configuration key (e.g. "webui.enabled", "rpc.eip155:1")
        key: String,
        /// Value to set
        value: String,
    },
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

impl CliError {
    /// Stable SCREAMING_SNAKE code for `--json` error envelopes (C10).
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Lws(e) => match e {
                oc_core::OcError::WalletNotFound { .. } => "WALLET_NOT_FOUND",
                oc_core::OcError::ChainNotSupported { .. } => "CHAIN_NOT_SUPPORTED",
                oc_core::OcError::InvalidPassphrase => "INVALID_PASSPHRASE",
                oc_core::OcError::InvalidInput { .. } => "INVALID_INPUT",
                oc_core::OcError::CaipParseError { .. } => "CAIP_PARSE_ERROR",
                oc_core::OcError::PolicyDenied { .. } => "POLICY_DENIED",
                oc_core::OcError::ApiKeyNotFound => "API_KEY_NOT_FOUND",
                oc_core::OcError::ApiKeyExpired { .. } => "API_KEY_EXPIRED",
            },
            Self::Lib(e) => match e {
                oc_wallet::OcWalletError::WalletNotFound(_) => "WALLET_NOT_FOUND",
                oc_wallet::OcWalletError::AmbiguousWallet { .. } => "AMBIGUOUS_WALLET",
                oc_wallet::OcWalletError::WalletNameExists(_) => "WALLET_NAME_EXISTS",
                oc_wallet::OcWalletError::InvalidInput(_) => "INVALID_INPUT",
                oc_wallet::OcWalletError::BroadcastFailed(_) => "BROADCAST_FAILED",
                _ => "WALLET_ERROR",
            },
            Self::Vault(_) => "VAULT_ERROR",
            Self::Mnemonic(_) => "MNEMONIC_ERROR",
            Self::Hd(_) => "HD_ERROR",
            Self::Signer(_) => "SIGNER_ERROR",
            Self::Crypto(_) => "CRYPTO_ERROR",
            Self::Io(_) => "IO_ERROR",
            Self::Json(_) => "JSON_ERROR",
            #[cfg(feature = "git")]
            Self::Git(_) => "GIT_ERROR",
            Self::SecretStore(_) => "SECRET_STORE_ERROR",
            Self::Recipient(_) => "RECIPIENT_ERROR",
            Self::Migration(_) => "MIGRATION_ERROR",
            Self::InvalidArgs(_) => "INVALID_ARGS",
            Self::NetAgentUnavailable => "NET_AGENT_UNAVAILABLE",
            Self::DaemonInit(_) => "DAEMON_INIT_FAILED",
            Self::KeyAgent(_) => "KEY_AGENT_ERROR",
        }
    }

    /// BSD `sysexits(3)` mapping (Phase 1: 64 usage / 65 data / 66 noinput /
    /// 70 software / 73 cantcreat / 77 noperm).
    ///
    /// I/O errors inspect the [`std::io::ErrorKind`] (`NotFound` -> 66,
    /// `PermissionDenied` -> 77, anything else -> 73); every other variant
    /// delegates to [`crate::exit::exit_code_for`] via its stable
    /// [`CliError::code`], so new variants fail closed to 70.
    pub(crate) fn exit_code(&self) -> i32 {
        match self {
            Self::Io(e) => match e.kind() {
                std::io::ErrorKind::NotFound => crate::exit::EX_NOINPUT,
                std::io::ErrorKind::PermissionDenied => crate::exit::EX_NOPERM,
                _ => crate::exit::EX_CANTCREAT,
            },
            _ => crate::exit::exit_code_for(self.code()),
        }
    }

    /// JSON error envelope: `{ code, message }` with the stable code.
    pub(crate) fn to_envelope(&self) -> serde_json::Value {
        serde_json::json!({"code": self.code(), "message": self.to_string()})
    }
}

#[cfg(test)]
mod error_envelope_tests {
    use super::*;

    #[test]
    fn envelope_has_code_and_message() {
        let e = CliError::InvalidArgs("bad flag".into());
        let v = e.to_envelope();
        assert_eq!(v["code"], "INVALID_ARGS");
        assert!(v["message"].as_str().unwrap().contains("bad flag"));
        assert_eq!(e.exit_code(), crate::exit::EX_USAGE);
    }

    #[test]
    fn wallet_not_found_maps_to_code() {
        let e = CliError::Lib(oc_wallet::OcWalletError::WalletNotFound("w".into()));
        assert_eq!(e.code(), "WALLET_NOT_FOUND");
    }

    #[test]
    fn policy_denied_maps_to_code() {
        let e = CliError::Lws(oc_core::OcError::PolicyDenied {
            policy_id: "p".into(),
            reason: "r".into(),
        });
        assert_eq!(e.code(), "POLICY_DENIED");
    }

    #[test]
    fn exit_codes_follow_sysexits() {
        // 64 usage, 77 permission, 66 missing input.
        assert_eq!(CliError::InvalidArgs("x".into()).exit_code(), 64);
        let denied = CliError::Lws(oc_core::OcError::PolicyDenied {
            policy_id: "p".into(),
            reason: "r".into(),
        });
        assert_eq!(denied.exit_code(), 77);
        let missing = CliError::Lib(oc_wallet::OcWalletError::WalletNotFound("w".into()));
        assert_eq!(missing.exit_code(), 66);
        let io_missing = CliError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "nope"));
        assert_eq!(io_missing.exit_code(), 66);
        let io_denied =
            CliError::Io(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"));
        assert_eq!(io_denied.exit_code(), 77);
    }
}
