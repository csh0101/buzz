#![deny(unsafe_code)]

//! End-to-end test of the Builderlab-compatible hosted API, playing the
//! desktop client's exact flow: browser login via Casdoor -> session
//! exchange -> identity challenge/verify (signed kind:24243 event) ->
//! availability -> create -> list.
//!
//! Prereqs: control-plane `serve` with casdoor flags; env BUZZ_PRIVATE_KEY
//! (the desktop identity), CASDOOR_CLIENT_ID/SECRET.
//! Run: cargo run -p buzz-control-plane --example hosted_flow_demo

use anyhow::{Context, Result};
use nostr::{EventBuilder, Keys, Kind, Tag};
use serde_json::{json, Value};

fn api_base() -> String {
    std::env::var("HOSTED_API_BASE")
        .unwrap_or_else(|_| "http://localhost:8900/api/goose/v1".to_string())
}

async fn post_authed(
    client: &reqwest::Client,
    url: &str,
    credential: &str,
    body: &Value,
) -> Result<Value> {
    let response = client
        .post(url)
        .header("X-BB-Session-Credential", credential)
        .header("Origin", "https://app.builderlab.xyz")
        .json(body)
        .send()
        .await?;
    Ok(response.json().await?)
}

#[tokio::main]
async fn main() -> Result<()> {
    let api = api_base();
    let user_key = std::env::var("BUZZ_PRIVATE_KEY")?;
    let keys = Keys::parse(user_key.trim())?;
    println!("desktop identity: {}", keys.public_key().to_hex());

    // Redirects are followed manually — we need the intermediate Locations.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;

    // 1-4. The browser leg (control-plane /auth/login -> Casdoor form ->
    // callback -> loopback URL with an exchange code) is an SPA flow, so it
    // is driven with a real browser (see hosted-login script / the desktop
    // itself). Pass the captured code via EXCHANGE_CODE.
    let exchange_code = std::env::var("EXCHANGE_CODE")
        .context("EXCHANGE_CODE missing (capture it from the browser login leg)")?;
    println!("1-4. browser login leg: exchange code captured via browser");

    // 5. Exchange the code for a session credential (desktop does this).
    let response = client
        .post(format!("{api}/auth/login/exchange"))
        .json(&json!({ "code": exchange_code }))
        .send()
        .await?;
    let exchanged: Value = response.json().await?;
    let credential = exchanged
        .get("session_credential")
        .and_then(Value::as_str)
        .context("no session_credential")?
        .to_string();

    // 6. /auth/me — the desktop's session check.
    let me: Value = client
        .get(format!("{api}/auth/me"))
        .header("X-BB-Session-Credential", &credential)
        .send()
        .await?
        .json()
        .await?;
    println!("5-6. session exchanged; /auth/me: {me}");

    // 7. Identity: current (expect missing_mapping) -> challenge.
    let current = post_authed(
        &client,
        &format!("{api}/buzz/nostr-identities/current"),
        &credential,
        &json!({}),
    )
    .await?;
    println!(
        "7. identity/current before bind: {}",
        current.get("error").unwrap_or(&current)
    );
    let challenge = post_authed(
        &client,
        &format!("{api}/buzz/nostr-identities/challenge"),
        &credential,
        &json!({ "origin": "https://app.builderlab.xyz" }),
    )
    .await?;
    let challenge_id = challenge
        .get("challenge_id")
        .and_then(Value::as_str)
        .context("no challenge")?
        .to_string();
    let nonce = challenge
        .get("nonce")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();

    // 8. Sign the kind:24243 binding event exactly like the desktop does.
    let tags: Vec<Tag> = [
        ("challenge_id", challenge_id.as_str()),
        ("nonce", nonce.as_str()),
        (
            "verification_code",
            challenge
                .get("verification_code")
                .and_then(Value::as_str)
                .unwrap(),
        ),
        ("audience", "buzz:nostr-identity"),
        ("action", "bind_nostr_identity"),
        ("protocol", "buzz-nostr-identity"),
        ("version", "1"),
        (
            "origin",
            challenge.get("origin").and_then(Value::as_str).unwrap(),
        ),
        (
            "expires_at",
            challenge.get("expires_at").and_then(Value::as_str).unwrap(),
        ),
    ]
    .iter()
    .map(|(k, v)| Tag::custom(nostr::TagKind::custom(*k), [*v]))
    .collect();
    let event = EventBuilder::new(Kind::Custom(24243), "")
        .tags(tags)
        .sign_with_keys(&keys)?;
    let verify = post_authed(
        &client,
        &format!("{api}/buzz/nostr-identities/verify"),
        &credential,
        &json!({
            "challenge_id": challenge_id,
            "nonce": nonce,
            "signed_payload": nostr::JsonUtil::as_json(&event),
        }),
    )
    .await?;
    println!("8. identity verify: {verify}");
    anyhow::ensure!(verify.get("identity").is_some(), "verify failed");

    // 9-11. Availability -> create -> list.
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "alice-hq".to_string());
    let availability = post_authed(
        &client,
        &format!("{api}/buzz/communities/availability"),
        &credential,
        &json!({ "name": name }),
    )
    .await?;
    println!("9. availability {name}: {availability}");
    let created = post_authed(
        &client,
        &format!("{api}/buzz/communities"),
        &credential,
        &json!({ "name": name }),
    )
    .await?;
    println!("10. create: {created}");
    let list = post_authed(
        &client,
        &format!("{api}/buzz/communities/list"),
        &credential,
        &json!({}),
    )
    .await?;
    println!("11. list: {list}");
    anyhow::ensure!(created.get("community").is_some(), "create failed");
    println!("\nALL HOSTED-FLOW STEPS PASSED");
    Ok(())
}
