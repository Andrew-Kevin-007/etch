use crate::identity::EtchIdentity;
use chrono::Utc;
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Fingerprint {
    pub contributor_pubkey: String,
    pub timestamp: String,
    pub code_hash: String,
    pub prev_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
    pub signature: String,
}

/// Sign a file and return its Fingerprint
pub fn sign_file(
    path: &str,
    identity: &EtchIdentity,
    prev_hash: String,
    metadata: Option<HashMap<String, String>>,
) -> io::Result<Fingerprint> {
    let content = fs::read(path)?;
    
    // Hash file contents
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let code_hash_bytes = hasher.finalize();
    let code_hash = hex::encode(code_hash_bytes);
    
    // Get current ISO 8601 timestamp
    let timestamp = Utc::now().to_rfc3339();
    
    // Structured payload for canonical signing
    let mut payload = HashMap::new();
    payload.insert("protocol_tag".to_string(), "etch-v1".to_string());
    payload.insert("hash_algorithm".to_string(), "sha2-256".to_string());
    payload.insert("code_hash".to_string(), code_hash.clone());
    payload.insert("contributor_pubkey".to_string(), identity.public_key_hex());
    payload.insert("prev_hash".to_string(), prev_hash.clone());
    payload.insert("timestamp".to_string(), timestamp.clone());
    
    if let Some(meta) = &metadata {
        for (k, v) in meta {
            payload.insert(k.clone(), v.clone());
        }
    }
    
    // Canonical serialization: use BTreeMap to ensure sorted keys for stable JSON
    let sorted_payload: std::collections::BTreeMap<_, _> = payload.into_iter().collect();
    let canonical_payload = serde_json::to_vec(&sorted_payload)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    
    
    // Sign the data
    let signature_bytes = identity.signing_key.sign(&canonical_payload);
    let signature = hex::encode(signature_bytes.to_bytes());
    
    Ok(Fingerprint {
        contributor_pubkey: identity.public_key_hex(),
        timestamp,
        code_hash,
        prev_hash,
        metadata,
        signature,
    })
}

/// Calculate the SHA-256 hash of a fingerprint's canonical JSON
pub fn hash_fingerprint(fingerprint: &Fingerprint) -> io::Result<String> {
    // Canonical serialization: ensure metadata fields are sorted
    let mut payload = std::collections::BTreeMap::new();
    payload.insert("contributor_pubkey".to_string(), serde_json::to_value(&fingerprint.contributor_pubkey).unwrap());
    payload.insert("timestamp".to_string(), serde_json::to_value(&fingerprint.timestamp).unwrap());
    payload.insert("code_hash".to_string(), serde_json::to_value(&fingerprint.code_hash).unwrap());
    payload.insert("prev_hash".to_string(), serde_json::to_value(&fingerprint.prev_hash).unwrap());
    
    if let Some(meta) = &fingerprint.metadata {
        let sorted_meta: std::collections::BTreeMap<_, _> = meta.iter().collect();
        payload.insert("metadata".to_string(), serde_json::to_value(&sorted_meta).unwrap());
    }

    let canonical = serde_json::to_vec(&payload)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut hasher = Sha256::new();
    hasher.update(canonical);
    Ok(hex::encode(hasher.finalize()))
}
