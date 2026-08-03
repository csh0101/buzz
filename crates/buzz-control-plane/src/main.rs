#![deny(unsafe_code)]

//! Self-hosted control plane prototype for the Buzz relay Operator API.
//!
//! The OSS relay ships the *server side* of community provisioning
//! (`/operator/communities*`, NIP-98 authenticated against
//! `RELAY_OPERATOR_PUBKEYS`). A deployment that wants to onboard communities
//! needs a caller for that surface — this crate is the minimal reference
//! implementation described in `docs/nostr-in-buzz.zh-CN.md`.
//!
//! Every request is authorized with a NIP-98 (kind:27235) event whose `u` tag
//! binds `{RELAY_OPERATOR_API_ORIGIN}{path}{?query}` and whose `payload` tag
//! binds the SHA-256 of the request body. The operator secret key stays here,
//! on the control-plane side — it is never distributed to clients.

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::{Parser, Subcommand};
use nostr::hashes::sha256::Hash as Sha256Hash;
use nostr::hashes::Hash as _;
use nostr::nips::nip98::{HttpData, HttpMethod};
use nostr::{EventBuilder, Keys, ToBech32, Url};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

mod audit;
mod guard;
mod hosted;
mod key_source;
mod serve;
mod sso;

#[derive(Parser)]
#[command(
    name = "buzz-control-plane",
    about = "Control plane for the Buzz relay operator API (NIP-98 signed)"
)]
struct Cli {
    /// Canonical operator API origin. Must byte-match the relay's
    /// RELAY_OPERATOR_API_ORIGIN — the NIP-98 `u` tag is verified against it,
    /// not against the inbound Host header.
    #[arg(
        long,
        env = "BUZZ_OPERATOR_ORIGIN",
        default_value = "http://localhost:3000",
        global = true
    )]
    origin: String,

    /// Operator secret key (nsec or 64-char hex). Its pubkey must be listed
    /// in the relay's RELAY_OPERATOR_PUBKEYS. Required for every command
    /// except `keygen`.
    #[arg(long, env = "BUZZ_OPERATOR_KEY", global = true)]
    key: Option<String>,

    /// Load the operator key from a secret backend instead of plaintext:
    /// `env:VAR`, `file:/path` (0600), or `cmd:<command...>` printing the
    /// key on stdout — e.g. macOS Keychain
    /// (`cmd:security find-generic-password -s buzz-operator -w`), Vault, or
    /// AWS Secrets Manager CLIs. Takes precedence over --key.
    #[arg(
        long,
        env = "BUZZ_OPERATOR_KEY_SOURCE",
        global = true,
        hide_env_values = true
    )]
    key_source: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum UserCommand {
    /// Fetch a Casdoor access token for yourself (password grant; browsers
    /// use GET /auth/casdoor/login instead).
    Token {
        #[arg(long, default_value = "http://localhost:8000")]
        casdoor_endpoint: String,
        #[arg(long)]
        client_id: String,
        #[arg(long)]
        client_secret: String,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password: String,
    },
    /// One-time: bind your npub to your SSO identity.
    Bind {
        /// Your private key (nsec/hex). Defaults to BUZZ_PRIVATE_KEY — the
        /// same identity the desktop app uses.
        #[arg(long, env = "BUZZ_PRIVATE_KEY", hide_env_values = true)]
        user_key: String,
        #[arg(long)]
        casdoor_token: String,
        #[arg(long, default_value = "http://localhost:8900")]
        service: String,
    },
    /// Create a community as yourself (server enforces the SSO gate,
    /// quota, replay and rate limits).
    Create {
        #[arg(long, env = "BUZZ_PRIVATE_KEY", hide_env_values = true)]
        user_key: String,
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "http://localhost:8900")]
        service: String,
    },
}

#[derive(Subcommand)]
enum Command {
    /// Generate a fresh operator keypair. Put the hex pubkey into the relay's
    /// RELAY_OPERATOR_PUBKEYS; keep the nsec on the control plane only.
    Keygen,
    /// Check whether a community host is available.
    Availability {
        /// Candidate community host, e.g. `acme.example.com`.
        #[arg(long)]
        host: String,
    },
    /// Provision a community (optionally bootstrapping its initial owner).
    Provision {
        /// Community host to create, e.g. `acme.example.com`.
        #[arg(long)]
        host: String,
        /// Initial owner as a 64-char hex pubkey (the end user's Nostr key,
        /// not the operator key).
        #[arg(long)]
        owner_pubkey: Option<String>,
        /// Reject instead of converging when the host already exists.
        #[arg(long, default_value_t = false)]
        create_only: bool,
    },
    /// List communities owned by a given end-user pubkey.
    List {
        /// Owner as a 64-char hex pubkey.
        #[arg(long)]
        owner_pubkey: String,
    },
    /// End-user commands against a running self-serve service. These sign
    /// with YOUR key (not the operator key): SSO login, one-time npub↔SSO
    /// binding, and self-serve community creation.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Archive a community (owner assertion required).
    Archive {
        #[arg(long)]
        host: String,
        #[arg(long)]
        owner_pubkey: String,
    },
    /// Unarchive a community (owner assertion required).
    Unarchive {
        #[arg(long)]
        host: String,
        #[arg(long)]
        owner_pubkey: String,
    },
    /// Transfer community ownership (last-writer-wins guarded by the
    /// expected current owner).
    Transfer {
        #[arg(long)]
        community_id: String,
        #[arg(long)]
        new_owner_pubkey: String,
        #[arg(long)]
        expected_owner_pubkey: String,
    },
    /// Run the self-serve provisioning service: end users sign with their own
    /// Nostr key, this service re-signs with the operator key and pins them as
    /// community owner.
    Serve {
        /// Listen address for the self-serve API.
        #[arg(long, default_value = "127.0.0.1:8900")]
        listen: String,
        /// This service's own public origin — end-user NIP-98 `u` tags are
        /// verified against it.
        #[arg(long, default_value = "http://localhost:8900")]
        public_origin: String,
        /// Suffix appended to user-chosen names, e.g. `.chat.company.com`.
        /// Must be covered by the deployment's wildcard DNS + certificate.
        #[arg(long, default_value = ".example")]
        host_suffix: String,
        /// Directory for the audit log and SSO bindings (JSONL files).
        #[arg(long, default_value = "./buzz-control-plane-data")]
        data_dir: String,
        /// Require callers to have bound a company SSO identity before they
        /// may provision communities.
        #[arg(long)]
        require_sso: bool,
        /// Casdoor base URL, e.g. http://localhost:8000. Enables the SSO
        /// endpoints (/auth/casdoor/*, /bindings).
        #[arg(long)]
        casdoor_endpoint: Option<String>,
        /// Casdoor application client id.
        #[arg(long, requires = "casdoor_endpoint")]
        casdoor_client_id: Option<String>,
        /// Casdoor application client secret.
        #[arg(long, requires = "casdoor_endpoint")]
        casdoor_client_secret: Option<String>,
        /// Max community creations per user per hour.
        #[arg(long, default_value_t = 10)]
        rate_create_max: u32,
    },
}

/// Sign and send one NIP-98-authorized request against the operator API.
///
/// The exact URL string is used both as the NIP-98 `u` tag and as the
/// request target so the relay's server-side reconstruction
/// (`{origin}{path}?{raw_query}`) matches byte-for-byte.
/// NIP-98 event IDs have second-resolution `created_at` and no nonce, so two
/// identical GETs (same URL, same key) within one second collide in the
/// relay's replay guard. Append a unique throwaway query param to every GET so
/// each event ID is distinct. The relay reconstructs the URL from the raw
/// query, so verification still matches, and unknown params are ignored.
fn with_request_nonce(url: &str, method: &HttpMethod) -> Result<String> {
    if *method != HttpMethod::GET {
        return Ok(url.to_string());
    }
    let mut parsed = Url::parse(url).context("invalid operator URL")?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before epoch")?
        .as_nanos();
    parsed
        .query_pairs_mut()
        .append_pair("_r", &nanos.to_string());
    Ok(parsed.into())
}

async fn nostr_http(
    client: &reqwest::Client,
    keys: &Keys,
    method: HttpMethod,
    url: &str,
    body: Option<&[u8]>,
) -> Result<(reqwest::StatusCode, String)> {
    let url = &with_request_nonce(url, &method)?;
    let mut data = HttpData::new(Url::parse(url).context("invalid operator URL")?, method);
    if let Some(bytes) = body {
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        data = data.payload(Sha256Hash::from_byte_array(digest));
    }
    let event = EventBuilder::http_auth(data)
        .sign_with_keys(keys)
        .context("failed to sign NIP-98 event")?;
    let event_json = serde_json::to_string(&event).context("failed to serialize NIP-98 event")?;

    let request = match method {
        HttpMethod::GET => client.get(url),
        HttpMethod::POST => client.post(url),
        HttpMethod::PUT => client.put(url),
        HttpMethod::PATCH => client.patch(url),
    }
    .header(
        "Authorization",
        format!("Nostr {}", BASE64.encode(event_json)),
    );
    let request = match body {
        Some(bytes) => request
            .header("Content-Type", "application/json")
            .body(bytes.to_vec()),
        None => request,
    };

    let response = request
        .send()
        .await
        .context("operator API request failed")?;
    let status = response.status();
    let text = response
        .text()
        .await
        .context("failed to read response body")?;
    Ok((status, text))
}

fn require_key(cli: &Cli) -> Result<Keys> {
    if let Some(source) = &cli.key_source {
        return key_source::KeySource::parse(source)
            .and_then(|s| s.load_keys())
            .context("failed to load operator key from --key-source");
    }
    let raw = cli
        .key
        .as_deref()
        .context("operator key missing: set --key-source, BUZZ_OPERATOR_KEY, or pass --key")?;
    Keys::parse(raw).context("invalid operator key (expected nsec or 64-char hex)")
}

fn print_result(status: reqwest::StatusCode, body: &str) -> Result<()> {
    let pretty = serde_json::from_str::<serde_json::Value>(body)
        .and_then(|v| serde_json::to_string_pretty(&v))
        .unwrap_or_else(|_| body.to_string());
    println!("HTTP {status}\n{pretty}");
    if status.is_success() {
        Ok(())
    } else {
        bail!("operator API returned {status}")
    }
}

/// Run an end-user command against the self-serve service.
async fn run_user_command(command: &UserCommand) -> Result<()> {
    let client = reqwest::Client::new();
    match command {
        UserCommand::Token {
            casdoor_endpoint,
            client_id,
            client_secret,
            username,
            password,
        } => {
            let response = client
                .post(format!(
                    "{}/api/login/oauth/access_token",
                    casdoor_endpoint.trim_end_matches('/')
                ))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .body(format!(
                    "grant_type=password&client_id={client_id}&client_secret={client_secret}&username={username}&password={password}"
                ))
                .send()
                .await?
                .text()
                .await?;
            let value: Value = serde_json::from_str(&response)
                .with_context(|| format!("casdoor token error: {response}"))?;
            let token = value
                .get("access_token")
                .and_then(Value::as_str)
                .context("casdoor did not return an access_token")?;
            println!("{token}");
            Ok(())
        }
        UserCommand::Bind {
            user_key,
            casdoor_token,
            service,
        } => {
            let keys = Keys::parse(user_key.trim()).context("invalid --user-key")?;
            let url = format!("{}/bindings", service.trim_end_matches('/'));
            let payload = serde_json::to_vec(&json!({ "casdoor_token": casdoor_token }))?;
            let (status, body) =
                nostr_http(&client, &keys, HttpMethod::POST, &url, Some(&payload)).await?;
            print_result(status, &body)
        }
        UserCommand::Create {
            user_key,
            name,
            service,
        } => {
            let keys = Keys::parse(user_key.trim()).context("invalid --user-key")?;
            let url = format!("{}/communities", service.trim_end_matches('/'));
            let payload = serde_json::to_vec(&json!({ "name": name }))?;
            let (status, body) =
                nostr_http(&client, &keys, HttpMethod::POST, &url, Some(&payload)).await?;
            print_result(status, &body)
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if let Command::User { command } = &cli.command {
        return run_user_command(command).await;
    }

    if matches!(cli.command, Command::Keygen) {
        let keys = Keys::generate();
        println!("operator pubkey (hex, put in RELAY_OPERATOR_PUBKEYS):");
        println!("  {}", keys.public_key().to_hex());
        println!("operator secret (nsec, keep on the control plane only):");
        println!(
            "  {}",
            keys.secret_key()
                .to_bech32()
                .context("bech32 encode failed")?
        );
        return Ok(());
    }

    let keys = require_key(&cli)?;
    let origin = cli.origin.trim_end_matches('/');
    let client = reqwest::Client::new();

    if let Command::Serve {
        listen,
        public_origin,
        host_suffix,
        data_dir,
        require_sso,
        casdoor_endpoint,
        casdoor_client_id,
        casdoor_client_secret,
        rate_create_max,
    } = &cli.command
    {
        let casdoor = match (casdoor_endpoint, casdoor_client_id, casdoor_client_secret) {
            (Some(endpoint), Some(client_id), Some(client_secret)) => Some(sso::CasdoorConfig {
                endpoint: endpoint.trim_end_matches('/').to_string(),
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
                redirect_uri: format!(
                    "{}/auth/casdoor/callback",
                    public_origin.trim_end_matches('/')
                ),
            }),
            (None, None, None) => None,
            _ => anyhow::bail!(
                "SSO needs all of --casdoor-endpoint/--casdoor-client-id/--casdoor-client-secret"
            ),
        };
        return serve::serve(
            keys,
            origin,
            serve::ServeConfig {
                listen: listen.clone(),
                public_origin: public_origin.clone(),
                host_suffix: host_suffix.clone(),
                data_dir: data_dir.clone(),
                require_sso: *require_sso,
                casdoor,
                rate_create_max: *rate_create_max,
            },
        )
        .await;
    }

    let (status, body) = match &cli.command {
        Command::Keygen | Command::Serve { .. } | Command::User { .. } => {
            unreachable!("handled above")
        }
        Command::Availability { host } => {
            let encoded: String = url::form_urlencoded::byte_serialize(host.as_bytes()).collect();
            let url = format!("{origin}/operator/communities/availability?host={encoded}");
            nostr_http(&client, &keys, HttpMethod::GET, &url, None).await?
        }
        Command::Provision {
            host,
            owner_pubkey,
            create_only,
        } => {
            let payload = serde_json::json!({
                "host": host,
                "initial_owner_pubkey": owner_pubkey,
                "create_only": create_only,
            });
            let bytes = serde_json::to_vec(&payload).context("serialize provision body")?;
            let url = format!("{origin}/operator/communities");
            nostr_http(&client, &keys, HttpMethod::POST, &url, Some(&bytes)).await?
        }
        Command::List { owner_pubkey } => {
            let url = format!("{origin}/operator/communities?owner_pubkey={owner_pubkey}");
            nostr_http(&client, &keys, HttpMethod::GET, &url, None).await?
        }
        Command::Archive { host, owner_pubkey } => {
            let payload = serde_json::json!({ "host": host, "owner_pubkey": owner_pubkey });
            let bytes = serde_json::to_vec(&payload).context("serialize archive body")?;
            let url = format!("{origin}/operator/communities/archive");
            nostr_http(&client, &keys, HttpMethod::POST, &url, Some(&bytes)).await?
        }
        Command::Unarchive { host, owner_pubkey } => {
            let payload = serde_json::json!({ "host": host, "owner_pubkey": owner_pubkey });
            let bytes = serde_json::to_vec(&payload).context("serialize unarchive body")?;
            let url = format!("{origin}/operator/communities/unarchive");
            nostr_http(&client, &keys, HttpMethod::POST, &url, Some(&bytes)).await?
        }
        Command::Transfer {
            community_id,
            new_owner_pubkey,
            expected_owner_pubkey,
        } => {
            let payload = serde_json::json!({
                "community_id": community_id,
                "new_owner_pubkey": new_owner_pubkey,
                "expected_owner_pubkey": expected_owner_pubkey,
            });
            let bytes = serde_json::to_vec(&payload).context("serialize transfer body")?;
            let url = format!("{origin}/operator/communities/transfer");
            nostr_http(&client, &keys, HttpMethod::POST, &url, Some(&bytes)).await?
        }
    };

    print_result(status, &body)
}
