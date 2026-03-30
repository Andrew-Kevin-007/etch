use crate::identity::EtchIdentity;
use chrono::Utc;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Fingerprint {
    pub contributor_pubkey: String,
    pub timestamp: String,
    pub code_hash: String,
    pub prev_hash: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize)]
struct SigningPayload<'a> {
    protocol_tag: &'a str,
    hash_algorithm: &'a str,
    code_hash: &'a str,
    contributor_pubkey: &'a str,
    prev_hash: &'a str,
    timestamp: &'a str,
}

/// Sign a file and return its Fingerprint
pub fn sign_file(path: &str, identity: &EtchIdentity, prev_hash: String) -> io::Result<Fingerprint> {
    let content = fs::read(path)?;
    
    // Hash file contents
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let code_hash_bytes = hasher.finalize();
    let code_hash = hex::encode(code_hash_bytes);
    
    // Get current ISO 8601 timestamp
    let timestamp = Utc::now().to_rfc3339();
    
    // Structured payload for canonical signing
    let payload = SigningPayload {
        protocol_tag: "etch-v1",
        hash_algorithm: "sha2-256",
        code_hash: &code_hash,
        contributor_pubkey: &identity.public_key_hex(),
        prev_hash: &prev_hash,
        timestamp: &timestamp,
    };
    
    // Canonical serialization (serde_json to_vec produces stable JSON for these simple types)
    let canonical_payload = serde_json::to_vec(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    // Sign the data
    let signature_bytes = identity.signing_key.sign(&canonical_payload);
    let signature = hex::encode(signature_bytes.to_bytes());
    
    Ok(Fingerprint {
        contributor_pubkey: identity.public_key_hex(),
        timestamp,
        code_hash,
        prev_hash,
        signature,
    })
}

/// Calculate the SHA-256 hash of a fingerprint's canonical JSON
pub fn hash_fingerprint(fingerprint: &Fingerprint) -> io::Result<String> {
    let canonical = serde_json::to_vec(fingerprint)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}
