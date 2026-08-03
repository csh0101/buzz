#![deny(unsafe_code)]

//! End-user view of the self-serve provisioning flow.
//!
//! Plays a *regular user* (no operator key): generates a fresh Nostr
//! identity, signs a NIP-98 request against the self-serve service with that
//! key, and creates a community — becoming its owner in one call.
//!
//! Prereq: `buzz-control-plane serve` running locally.
//! Run:   cargo run -p buzz-control-plane --example self_serve_demo

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nostr::hashes::sha256::Hash as Sha256Hash;
use nostr::hashes::Hash as _;
use nostr::nips::nip98::{HttpData, HttpMethod};
use nostr::{EventBuilder, Keys, Url};
use sha2::{Digest, Sha256};

const SERVICE: &str = "http://localhost:8900";

async fn signed_post(
    client: &reqwest::Client,
    keys: &Keys,
    url: &str,
    body: &[u8],
) -> Result<(reqwest::StatusCode, String)> {
    let digest: [u8; 32] = Sha256::digest(body).into();
    let data = HttpData::new(Url::parse(url)?, HttpMethod::POST)
        .payload(Sha256Hash::from_byte_array(digest));
    let event = EventBuilder::http_auth(data).sign_with_keys(keys)?;
    let auth = format!("Nostr {}", BASE64.encode(serde_json::to_string(&event)?));
    let response = client
        .post(url)
        .header("Authorization", auth)
        .header("Content-Type", "application/json")
        .body(body.to_vec())
        .send()
        .await?;
    Ok((response.status(), response.text().await?))
}

#[tokio::main]
async fn main() -> Result<()> {
    // A fresh "employee" — no account registration, the key IS the identity.
    let user = Keys::generate();
    println!("employee pubkey: {}", user.public_key().to_hex());

    let client = reqwest::Client::new();
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "design".to_string());

    // 1. Self-serve create.
    let body = serde_json::to_vec(&serde_json::json!({ "name": name }))?;
    let url = format!("{SERVICE}/communities");
    let (status, text) = signed_post(&client, &user, &url, &body).await?;
    println!("create {name}: HTTP {status} {text}");
    if !status.is_success() {
        anyhow::bail!("create failed");
    }

    // 2. A second employee tries to take the same name -> must fail.
    let squatter = Keys::generate();
    let (status, text) = signed_post(&client, &squatter, &url, &body).await?;
    println!(
        "squatter retries {name}: HTTP {status} {text}  {}",
        if status == reqwest::StatusCode::CONFLICT {
            "(name protected ✓)"
        } else {
            "(UNEXPECTED ✗)"
        }
    );

    // 3. Unsigned request -> must fail.
    let response = client
        .post(&url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("unsigned request failed")?;
    println!(
        "unsigned request: HTTP {} {}",
        response.status(),
        response.text().await?
    );

    Ok(())
}
