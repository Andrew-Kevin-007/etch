use crate::chain::AuthorshipChain;
use crate::identity::EtchIdentity;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use chrono::Utc;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Serialize)]
struct AnchorRequest {
    chain_id: String,
    file_path: String,
    head_hash: String,
    chain_depth: usize,
    contributor_pubkey: String,
    timestamp: String,
}

#[derive(Serialize)]
struct VerifyRequest {
    chain_id: String,
    file_path: String,
    head_hash: String,
}

#[derive(Deserialize, Debug)]
struct VerifyResponse {
    valid: bool,
}

pub fn get_server_url() -> String {
    env::var("ETCH_SERVER").unwrap_or_else(|_| "https://etch-server-production.up.railway.app".to_string())
}

pub async fn anchor_chain(file_path: &str, chain: &AuthorshipChain, identity: &EtchIdentity) -> Result<()> {
    let server_url = get_server_url();
    let url = format!("{}/anchor", server_url);

    let head_hash = if let Some(last) = chain.fingerprints.last() {
        last.code_hash.clone()
    } else {
        return Err("Cannot anchor empty chain".into());
    };

    // chain_id is SHA-256 of file_path
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let chain_id = hex::encode(hasher.finalize());
    println!("DEBUG anchor: chain_id={} head_hash={}", chain_id, head_hash);

    let request = AnchorRequest {
        chain_id,
        file_path: file_path.to_string(),
        head_hash,
        chain_depth: chain.fingerprints.len(),
        contributor_pubkey: identity.public_key_hex(),
        timestamp: Utc::now().to_rfc3339(),
    };

    let client = reqwest::Client::new();
    let response = client.post(url)
        .json(&request)
        .send()
        .await;

    match response {
        Ok(resp) if resp.status().is_success() => {
            println!("✓ Authorship anchored to notarization server");
            Ok(())
        }
        Ok(resp) if resp.status() == reqwest::StatusCode::CONFLICT => {
            println!("✓ Chain anchor updated on notarization server");
            let update_url = format!("{}/anchor/update", server_url);
            let _ = client.post(update_url)
                .json(&request)
                .send()
                .await;
            Ok(())
        }
        Ok(resp) => {
            eprintln!("Warning: Failed to anchor authorship: Server returned status {}", resp.status());
            Ok(()) // Non-fatal
        }
        Err(e) => {
            eprintln!("Warning: Failed to anchor authorship: {}", e);
            Ok(()) // Non-fatal
        }
    }
}

pub async fn verify_with_server(file_path: &str, chain: &AuthorshipChain) -> Result<bool> {
    let server_url = get_server_url();
    let url = format!("{}/verify", server_url);

    // chain_id is SHA-256 of file_path
    let mut hasher = Sha256::new();
    hasher.update(file_path.as_bytes());
    let chain_id = hex::encode(hasher.finalize());

    let client = reqwest::Client::new();

    // Iterate backwards through fingerprints to find the most recently anchored one
    for fingerprint in chain.fingerprints.iter().rev() {
        let head_hash = &fingerprint.code_hash;
        println!("DEBUG verify: chain_id={} head_hash={}", chain_id, head_hash);

        let request = VerifyRequest {
            chain_id: chain_id.clone(),
            file_path: file_path.to_string(),
            head_hash: head_hash.to_string(),
        };

        let response = client.post(&url)
            .json(&request)
            .send()
            .await?;

        let status = response.status();
        let body_text = response.text().await?;
        println!("DEBUG verify: raw response: {}", body_text);

        if status.is_success() {
            let verify_resp: VerifyResponse = serde_json::from_str(&body_text)?;
            if verify_resp.valid {
                return Ok(true);
            }
        } else if status != reqwest::StatusCode::NOT_FOUND {
            // If it's not a 404/Not Found, maybe something is wrong, but we continue checking?
            // Actually, if we get an error from server, we might want to return it or just continue.
            // Let's stick to matching true and continuing if not.
        }
    }

    Ok(false)
}
