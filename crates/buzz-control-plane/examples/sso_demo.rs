#![deny(unsafe_code)]

//! Full production-hardening demo: Casdoor SSO binding, SSO-gated
//! provisioning, replay rejection, rate limiting, and audit trail.
//!
//! Prereqs:
//! - `buzz-control-plane serve` with --require-sso + casdoor flags
//! - env: CASDOOR_CLIENT_ID, CASDOOR_CLIENT_SECRET
//! Run: cargo run -p buzz-control-plane --example sso_demo

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use nostr::hashes::sha256::Hash as Sha256Hash;
use nostr::hashes::Hash as _;
use nostr::nips::nip98::{HttpData, HttpMethod};
use nostr::{EventBuilder, Keys, Url};
use serde_json::json;
use sha2::{Digest, Sha256};

const SERVICE: &str = "http://localhost:8900";
const CASDOOR: &str = "http://localhost:8000";

fn signed_header(keys: &Keys, url: &str, body: &[u8]) -> Result<String> {
    let digest: [u8; 32] = Sha256::digest(body).into();
    let data = HttpData::new(Url::parse(url)?, HttpMethod::POST)
        .payload(Sha256Hash::from_byte_array(digest));
    let event = EventBuilder::http_auth(data).sign_with_keys(keys)?;
    Ok(format!(
        "Nostr {}",
        BASE64.encode(serde_json::to_string(&event)?)
    ))
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    auth: Option<&str>,
    body: &[u8],
) -> Result<(reqwest::StatusCode, String)> {
    let mut request = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body.to_vec());
    if let Some(header) = auth {
        request = request.header("Authorization", header);
    }
    let response = request.send().await?;
    Ok((response.status(), response.text().await?))
}

#[tokio::main]
async fn main() -> Result<()> {
    let client_id = std::env::var("CASDOOR_CLIENT_ID").context("CASDOOR_CLIENT_ID missing")?;
    let client_secret =
        std::env::var("CASDOOR_CLIENT_SECRET").context("CASDOOR_CLIENT_SECRET missing")?;
    let client = reqwest::Client::new();

    // 1. Alice logs into the company SSO (password grant; browsers use the
    //    authorization-code flow via GET /auth/casdoor/login).
    let token_response = client
        .post(format!("{CASDOOR}/api/login/oauth/access_token"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(format!(
            "grant_type=password&client_id={client_id}&client_secret={client_secret}&username=alice&password=alice123"
        ))
        .send()
        .await?
        .text()
        .await?;
    let casdoor_token: String = serde_json::from_str::<serde_json::Value>(&token_response)?
        .get("access_token")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .context("casdoor did not return an access_token")?;
    println!("1. casdoor login: got JWT for alice");

    // 2. Alice binds her npub to her SSO identity.
    let alice = Keys::generate();
    let bind_body = serde_json::to_vec(&json!({ "casdoor_token": casdoor_token }))?;
    let url = format!("{SERVICE}/bindings");
    let auth = signed_header(&alice, &url, &bind_body)?;
    let (status, text) = post(&client, &url, Some(&auth), &bind_body).await?;
    println!("2. bind alice npub<->sso: HTTP {status} {text}");
    if !status.is_success() {
        anyhow::bail!("binding failed");
    }

    // 3. Alice creates a community — SSO gate passes.
    let create_url = format!("{SERVICE}/communities");
    let body1 = serde_json::to_vec(&json!({ "name": "alice-team" }))?;
    let auth1 = signed_header(&alice, &create_url, &body1)?;
    let (status, text) = post(&client, &create_url, Some(&auth1), &body1).await?;
    println!("3. alice creates alice-team: HTTP {status} {text}");
    if !status.is_success() {
        anyhow::bail!("create failed");
    }

    // 4. An unbound employee is rejected by the SSO gate.
    let mallory = Keys::generate();
    let body = serde_json::to_vec(&json!({ "name": "mallory-team" }))?;
    let auth = signed_header(&mallory, &create_url, &body)?;
    let (status, text) = post(&client, &create_url, Some(&auth), &body).await?;
    println!(
        "4. unbound user create: HTTP {status} {text} {}",
        if status == reqwest::StatusCode::FORBIDDEN {
            "(SSO gate ✓)"
        } else {
            "(UNEXPECTED ✗)"
        }
    );

    // 5. Replaying alice's exact signed request from step 3 is rejected.
    let (status, text) = post(&client, &create_url, Some(&auth1), &body1).await?;
    println!(
        "5. replay alice's request: HTTP {status} {text} {}",
        if status == reqwest::StatusCode::UNAUTHORIZED {
            "(replay cache ✓)"
        } else {
            "(UNEXPECTED ✗)"
        }
    );

    // 6. Rate limit: alice may create 2/hour (service started with
    //    --rate-create-max 2). The second succeeds, the third is rejected.
    let body2 = serde_json::to_vec(&json!({ "name": "alice-two" }))?;
    let auth2 = signed_header(&alice, &create_url, &body2)?;
    let (s2, _) = post(&client, &create_url, Some(&auth2), &body2).await?;
    let body3 = serde_json::to_vec(&json!({ "name": "alice-three" }))?;
    let auth3 = signed_header(&alice, &create_url, &body3)?;
    let (s3, text3) = post(&client, &create_url, Some(&auth3), &body3).await?;
    println!(
        "6. rate limit: 2nd create HTTP {s2}, 3rd create HTTP {s3} {text3} {}",
        if s2.is_success() && s3 == reqwest::StatusCode::TOO_MANY_REQUESTS {
            "(rate limiter ✓)"
        } else {
            "(UNEXPECTED ✗)"
        }
    );

    println!("7. audit trail: cat ~/.buzz-control-plane/audit.jsonl | jq");
    Ok(())
}
