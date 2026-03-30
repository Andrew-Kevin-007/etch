use crate::fingerprint::{Fingerprint, hash_fingerprint};
use crate::chain::AuthorshipChain;
use chrono::{DateTime, Utc, Duration};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io;
use ed25519_dalek::{VerifyingKey, Signature, Verifier};

#[derive(Serialize, Deserialize, Debug)]
pub struct CheckResult {
    pub check_id: String,
    pub status: bool,
    pub entry_index: Option<usize>,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub reason_code: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct VerificationReport {
    pub verdict: bool,
    pub verified_through_index: Option<usize>,
    pub results: Vec<CheckResult>,
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

pub fn verify_file(path: &str) -> io::Result<VerificationReport> {
    let mut report = VerificationReport {
        verdict: true,
        verified_through_index: None,
        results: Vec::new(),
    };

    // Load chain
    let chain = match AuthorshipChain::load_for_file(path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            report.verdict = false;
            report.results.push(CheckResult {
                check_id: "chain_load".to_string(),
                status: false,
                entry_index: None,
                expected: None,
                actual: None,
                reason_code: Some("chain_not_found".to_string()),
            });
            return Ok(report);
        }
        Err(e) => return Err(e),
    };

    if chain.fingerprints.is_empty() {
        report.verdict = false;
        report.results.push(CheckResult {
            check_id: "chain_empty".to_string(),
            status: false,
            entry_index: None,
            expected: None,
            actual: None,
            reason_code: Some("no_fingerprints".to_string()),
        });
        return Ok(report);
    }

    let mut expected_prev_hash = "genesis".to_string();
    let mut last_timestamp: Option<DateTime<Utc>> = None;
    let now = Utc::now();
    let max_skew = Duration::minutes(5);

    for (i, f) in chain.fingerprints.iter().enumerate() {
        // 1. Schema Validation
        if let Err(reason) = validate_schema(f) {
            report.verdict = false;
            report.results.push(CheckResult {
                check_id: "schema_validation".to_string(),
                status: false,
                entry_index: Some(i),
                expected: None,
                actual: None,
                reason_code: Some(reason),
            });
            break;
        }

        // 4. Chain Integrity (Part 1: prev_hash)
        if f.prev_hash != expected_prev_hash {
            report.verdict = false;
            report.results.push(CheckResult {
                check_id: "chain_integrity".to_string(),
                status: false,
                entry_index: Some(i),
                expected: Some(expected_prev_hash),
                actual: Some(f.prev_hash.clone()),
                reason_code: Some("prev_hash_mismatch".to_string()),
            });
            break;
        }

        // 2. Canonical Payload Reconstruction & 3. Signature Validity
        let payload = SigningPayload {
            protocol_tag: "etch-v1",
            hash_algorithm: "sha2-256",
            code_hash: &f.code_hash,
            contributor_pubkey: &f.contributor_pubkey,
            prev_hash: &f.prev_hash,
            timestamp: &f.timestamp,
        };

        let canonical_payload = match serde_json::to_vec(&payload) {
            Ok(p) => p,
            Err(_) => {
                report.verdict = false;
                report.results.push(CheckResult {
                    check_id: "canonicalization".to_string(),
                    status: false,
                    entry_index: Some(i),
                    expected: None,
                    actual: None,
                    reason_code: Some("canonicalization_mismatch".to_string()),
                });
                break;
            }
        };

        if let Err(reason) = verify_signature(f, &canonical_payload) {
            report.verdict = false;
            report.results.push(CheckResult {
                check_id: "signature_verification".to_string(),
                status: false,
                entry_index: Some(i),
                expected: None,
                actual: None,
                reason_code: Some(reason),
            });
            break;
        }

        // 6. Temporal Policy
        let ts = match DateTime::parse_from_rfc3339(&f.timestamp) {
            Ok(dt) => dt.with_timezone(&Utc),
            Err(_) => {
                report.verdict = false;
                report.results.push(CheckResult {
                    check_id: "timestamp_parse".to_string(),
                    status: false,
                    entry_index: Some(i),
                    expected: None,
                    actual: Some(f.timestamp.clone()),
                    reason_code: Some("schema_invalid".to_string()),
                });
                break;
            }
        };

        if let Some(last_ts) = last_timestamp {
            if ts < last_ts {
                report.verdict = false;
                report.results.push(CheckResult {
                    check_id: "temporal_policy".to_string(),
                    status: false,
                    entry_index: Some(i),
                    expected: Some(format!(">= {}", last_ts.to_rfc3339())),
                    actual: Some(f.timestamp.clone()),
                    reason_code: Some("sequence_invalid".to_string()),
                });
                break;
            }
        }

        if ts > now + max_skew {
            report.verdict = false;
            report.results.push(CheckResult {
                check_id: "temporal_policy".to_string(),
                status: false,
                entry_index: Some(i),
                expected: Some(format!("<= {} (with 5m skew)", now.to_rfc3339())),
                actual: Some(f.timestamp.clone()),
                reason_code: Some("timestamp_policy_violation".to_string()),
            });
            break;
        }

        last_timestamp = Some(ts);
        expected_prev_hash = hash_fingerprint(f)?;
        report.verified_through_index = Some(i);
    }

    // 5. Artifact Binding (Check against last entry if chain is otherwise valid)
    if report.verdict {
        let last_entry = chain.fingerprints.last().unwrap();
        match fs::read(path) {
            Ok(content) => {
                let mut hasher = Sha256::new();
                hasher.update(&content);
                let actual_hash = hex::encode(hasher.finalize());
                if actual_hash != last_entry.code_hash {
                    report.verdict = false;
                    report.results.push(CheckResult {
                        check_id: "artifact_binding".to_string(),
                        status: false,
                        entry_index: Some(chain.fingerprints.len() - 1),
                        expected: Some(last_entry.code_hash.clone()),
                        actual: Some(actual_hash),
                        reason_code: Some("file_hash_mismatch".to_string()),
                    });
                } else {
                    report.results.push(CheckResult {
                        check_id: "artifact_binding".to_string(),
                        status: true,
                        entry_index: Some(chain.fingerprints.len() - 1),
                        expected: Some(last_entry.code_hash.clone()),
                        actual: Some(actual_hash),
                        reason_code: None,
                    });
                }
            }
            Err(e) => {
                report.verdict = false;
                report.results.push(CheckResult {
                    check_id: "artifact_access".to_string(),
                    status: false,
                    entry_index: None,
                    expected: None,
                    actual: None,
                    reason_code: Some(format!("io_error: {}", e)),
                });
            }
        }
    }

    Ok(report)
}

fn validate_schema(f: &Fingerprint) -> Result<(), String> {
    // Pubkey: 32 bytes hex = 64 chars
    if hex::decode(&f.contributor_pubkey).map_err(|_| "schema_invalid".to_string())?.len() != 32 {
        return Err("schema_invalid".to_string());
    }
    // Signature: 64 bytes hex = 128 chars
    if hex::decode(&f.signature).map_err(|_| "schema_invalid".to_string())?.len() != 64 {
        return Err("signature_invalid".to_string());
    }
    // Code Hash: 32 bytes hex = 64 chars
    if hex::decode(&f.code_hash).map_err(|_| "schema_invalid".to_string())?.len() != 32 {
        return Err("schema_invalid".to_string());
    }
    // Timestamp check
    if DateTime::parse_from_rfc3339(&f.timestamp).is_err() {
        return Err("schema_invalid".to_string());
    }
    Ok(())
}

fn verify_signature(f: &Fingerprint, payload: &[u8]) -> Result<(), String> {
    let pubkey_bytes = hex::decode(&f.contributor_pubkey).map_err(|_| "schema_invalid".to_string())?;
    let sig_bytes = hex::decode(&f.signature).map_err(|_| "schema_invalid".to_string())?;

    let verifying_key = VerifyingKey::from_bytes(
        &pubkey_bytes.try_into().map_err(|_| "schema_invalid".to_string())?
    ).map_err(|_| "signature_invalid".to_string())?;

    let signature = Signature::from_bytes(
        &sig_bytes.try_into().map_err(|_| "signature_invalid".to_string())?
    );

    verifying_key.verify(payload, &signature).map_err(|_| "signature_invalid".to_string())?;

    Ok(())
}
