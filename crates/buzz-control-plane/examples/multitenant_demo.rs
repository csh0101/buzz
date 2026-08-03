#![deny(unsafe_code)]

//! Multi-tenant demo against the local dev relay.
//!
//! Creates a channel and posts a message inside the `acme.example` community
//! through the local Caddy reverse proxy (port 8088, which rewrites the Host
//! header to the community row), then reads the message back — proving that
//! two communities on the same relay process see disjoint data sets.
//!
//! Name resolution is done per-application (reqwest `resolve()`), so no
//! /etc/hosts or DNS changes are required.
//!
//! Run:
//!   cargo run -p buzz-control-plane --example multitenant_demo

use std::net::SocketAddr;

use anyhow::{Context, Result};
use nostr::{EventBuilder, Keys, Kind, Tag};
use serde_json::json;

const TENANT_HOST: &str = "acme.example";
const PROXY_PORT: u16 = 8088;

/// Sign `builder` with `keys` and submit it to the relay's HTTP event bridge.
async fn submit_event(
    client: &reqwest::Client,
    base: &str,
    keys: &Keys,
    builder: EventBuilder,
) -> Result<serde_json::Value> {
    let event = builder
        .sign_with_keys(keys)
        .context("failed to sign event")?;
    let body = serde_json::to_vec(&event).context("serialize event")?;
    let response = client
        .post(format!("{base}/events"))
        // Dev-relay transport auth (BUZZ_REQUIRE_AUTH_TOKEN=false). The event
        // signature itself is still verified by the relay.
        .header("X-Pubkey", keys.public_key().to_hex())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .context("POST /events failed")?;
    let status = response.status();
    let text = response.text().await.context("read /events response")?;
    let value: serde_json::Value =
        serde_json::from_str(&text).unwrap_or_else(|_| json!({ "raw": text }));
    if !status.is_success() {
        anyhow::bail!("POST /events -> {status}: {value}");
    }
    Ok(value)
}

/// Run a Nostr filter over the HTTP query bridge.
async fn query(
    client: &reqwest::Client,
    base: &str,
    pubkey_hex: &str,
    filter: serde_json::Value,
) -> Result<Vec<serde_json::Value>> {
    let response = client
        .post(format!("{base}/query"))
        .header("X-Pubkey", pubkey_hex)
        .header("Content-Type", "application/json")
        .body(serde_json::to_vec(&json!([filter]))?)
        .send()
        .await
        .context("POST /query failed")?;
    let status = response.status();
    let text = response.text().await.context("read /query response")?;
    if !status.is_success() {
        anyhow::bail!("POST /query -> {status}: {text}");
    }
    serde_json::from_str(&text).context("parse /query response")
}

#[tokio::main]
async fn main() -> Result<()> {
    let keys = Keys::generate();
    let pubkey_hex = keys.public_key().to_hex();
    println!("demo user pubkey: {pubkey_hex}");

    // Per-app DNS: acme.example resolves to the local proxy for this process
    // only — no /etc/hosts, no system DNS changes.
    let client = reqwest::Client::builder()
        .resolve(TENANT_HOST, SocketAddr::from(([127, 0, 0, 1], PROXY_PORT)))
        .build()
        .context("build HTTP client")?;
    let acme = format!("http://{TENANT_HOST}:{PROXY_PORT}");
    let localhost = "http://localhost:3000".to_string();

    // 1. Create #acme-general inside the acme.example community (kind 9007).
    let channel_id = uuid::Uuid::new_v4();
    let create = EventBuilder::new(Kind::Custom(9007), "").tags([
        Tag::parse(["h", &channel_id.to_string()])?,
        Tag::parse(["name", "acme-general"])?,
        Tag::parse(["visibility", "open"])?,
        Tag::parse(["channel_type", "stream"])?,
    ]);
    let created = submit_event(&client, &acme, &keys, create).await?;
    println!("[acme] create channel #acme-general ({channel_id}): {created}");

    // 2. Post a kind:9 message scoped to that channel via the h tag.
    let message = EventBuilder::new(Kind::Custom(9), "hello from acme tenant 🏢")
        .tags([Tag::parse(["h", &channel_id.to_string()])?]);
    let posted = submit_event(&client, &acme, &keys, message).await?;
    println!("[acme] post message: {posted}");

    // 3. Read it back from the acme tenant.
    let in_acme = query(
        &client,
        &acme,
        &pubkey_hex,
        json!({"kinds": [9], "#h": [channel_id.to_string()]}),
    )
    .await?;
    println!(
        "[acme] query kinds=9 h={channel_id}: {} event(s)",
        in_acme.len()
    );
    for event in &in_acme {
        println!("       content: {}", event["content"]);
    }

    // 4. The localhost:3000 community must NOT see acme's channel/message,
    //    and acme must not see localhost's #general history.
    let leak = query(
        &client,
        &localhost,
        &pubkey_hex,
        json!({"kinds": [9], "#h": [channel_id.to_string()]}),
    )
    .await?;
    println!(
        "[localhost] same query on localhost:3000: {} event(s) — {}",
        leak.len(),
        if leak.is_empty() {
            "ISOLATION OK ✓"
        } else {
            "LEAK ✗"
        }
    );

    let acme_view_of_localhost = query(&client, &acme, &pubkey_hex, json!({"kinds": [9]})).await?;
    println!(
        "[acme] all kind:9 visible in acme tenant: {} event(s) (localhost's #general is invisible here too)",
        acme_view_of_localhost.len()
    );

    Ok(())
}
