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
            // We MUST not break here if we want to check other things, but usually chain break is fatal.
            // However, the task asks for a report. If we break, we don't check subsequent entries.
            // For now, let's keep the break as it is a critical failure.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EtchIdentity;
    use crate::fingerprint::{sign_file, hash_fingerprint};
    use crate::chain::AuthorshipChain;
    use ed25519_dalek::Signer;
    use std::fs;
    use chrono::{Utc, Duration};

    fn setup_test_identity() -> EtchIdentity {
        EtchIdentity::generate()
    }

    fn create_test_file(path: &str, content: &str) {
        fs::write(path, content).unwrap();
    }

    #[test]
    fn test_signature_verify_valid() {
        let id = setup_test_identity();
        let path = "test_sig_valid.txt";
        create_test_file(path, "hello");
        let f = sign_file(path, &id, "genesis".to_string()).unwrap();
        
        let mut chain = AuthorshipChain::new();
        chain.append(f).unwrap();
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(report.verdict);
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_signature_verify_wrong_key() {
        let id1 = setup_test_identity();
        let id2 = setup_test_identity();
        let path = "test_sig_wrong_key.txt";
        create_test_file(path, "hello");
        let mut f = sign_file(path, &id1, "genesis".to_string()).unwrap();
        
        // Tamper with pubkey
        f.contributor_pubkey = id2.public_key_hex();

        let mut chain = AuthorshipChain::new();
        chain.append(f).unwrap();
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(!report.verdict);
        assert_eq!(report.results.iter().find(|r| r.check_id == "signature_verification").unwrap().reason_code, Some("signature_invalid".to_string()));
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_signature_verify_tampered_bytes() {
        let id = setup_test_identity();
        let path = "test_sig_tamper.txt";
        create_test_file(path, "hello");
        let mut f = sign_file(path, &id, "genesis".to_string()).unwrap();
        
        // Tamper with signature bytes
        let mut sig_bytes = hex::decode(&f.signature).unwrap();
        sig_bytes[0] ^= 0xFF;
        f.signature = hex::encode(sig_bytes);

        let mut chain = AuthorshipChain::new();
        chain.append(f).unwrap();
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(!report.verdict);
        assert_eq!(report.results.iter().find(|r| r.check_id == "signature_verification").unwrap().reason_code, Some("signature_invalid".to_string()));
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_signature_verify_malformed_signature() {
        let id = setup_test_identity();
        let path = "test_sig_malformed.txt";
        create_test_file(path, "hello");
        let mut f = sign_file(path, &id, "genesis".to_string()).unwrap();
        
        // Malformed hex length
        f.signature = "abc123".to_string();

        let mut chain = AuthorshipChain::new();
        chain.fingerprints.push(f);
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(!report.verdict);
        assert_eq!(report.results.iter().find(|r| r.check_id == "schema_validation").unwrap().reason_code, Some("signature_invalid".to_string()));
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_signature_verify_replay_attack() {
        let id = setup_test_identity();
        let path1 = "test_replay1.txt";
        let path2 = "test_replay2.txt";
        create_test_file(path1, "hello");
        create_test_file(path2, "world");
        
        let f1 = sign_file(path1, &id, "genesis".to_string()).unwrap();
        
        // Replay f1 onto path2
        let mut chain2 = AuthorshipChain::new();
        chain2.fingerprints.push(f1);
        chain2.save_for_file(path2).unwrap();

        let report = verify_file(path2).unwrap();
        assert!(!report.verdict);
        // Should fail artifact binding because code_hash matches path1 not path2
        assert_eq!(report.results.iter().find(|r| r.check_id == "artifact_binding").unwrap().reason_code, Some("file_hash_mismatch".to_string()));
        
        fs::remove_file(path1).ok();
        fs::remove_file(path2).ok();
        fs::remove_file(format!("{}.etch", path1)).ok();
        fs::remove_file(format!("{}.etch", path2)).ok();
    }

    #[test]
    fn test_chain_integrity_valid_n_entry() {
        let id = setup_test_identity();
        let path = "test_chain_n.txt";
        create_test_file(path, "hello");
        
        let mut chain = AuthorshipChain::new();
        let f1 = sign_file(path, &id, "genesis".to_string()).unwrap();
        let h1 = hash_fingerprint(&f1).unwrap();
        chain.append(f1).unwrap();
        
        let f2 = sign_file(path, &id, h1).unwrap();
        chain.append(f2).unwrap();
        
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(report.verdict);
        assert_eq!(report.verified_through_index, Some(1));
        
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_chain_integrity_broken_prev_hash() {
        let id = setup_test_identity();
        let path = "test_chain_broken.txt";
        create_test_file(path, "hello");
        
        let mut chain = AuthorshipChain::new();
        let f1 = sign_file(path, &id, "genesis".to_string()).unwrap();
        let h1 = hash_fingerprint(&f1).unwrap();
        chain.append(f1).unwrap();
        
        let mut f2 = sign_file(path, &id, h1).unwrap();
        f2.prev_hash = "wrong".to_string();
        chain.fingerprints.push(f2);
        
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(!report.verdict);
        assert_eq!(report.results.iter().find(|r| r.check_id == "chain_integrity").unwrap().reason_code, Some("prev_hash_mismatch".to_string()));
        
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_chain_integrity_reordered() {
        let id = setup_test_identity();
        let path = "test_chain_reorder.txt";
        create_test_file(path, "hello");
        
        let mut chain = AuthorshipChain::new();
        let f1 = sign_file(path, &id, "genesis".to_string()).unwrap();
        let h1 = hash_fingerprint(&f1).unwrap();
        let f2 = sign_file(path, &id, h1).unwrap();
        
        chain.fingerprints.push(f2);
        chain.fingerprints.push(f1);
        
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(!report.verdict);
        // First entry should have "genesis" as prev_hash, but it has h1
        assert_eq!(report.results.iter().find(|r| r.check_id == "chain_integrity").unwrap().reason_code, Some("prev_hash_mismatch".to_string()));
        
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_tamper_detection_modified_code_hash() {
        let id = setup_test_identity();
        let path = "test_tamper_hash.txt";
        create_test_file(path, "hello");
        let mut f = sign_file(path, &id, "genesis".to_string()).unwrap();
        
        f.code_hash = hex::encode([0u8; 32]); // wrong hash

        let mut chain = AuthorshipChain::new();
        chain.fingerprints.push(f);
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(!report.verdict);
        // Fails signature first because code_hash is signed
        assert_eq!(report.results.iter().find(|r| r.check_id == "signature_verification").unwrap().reason_code, Some("signature_invalid".to_string()));
        
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_tamper_detection_modified_file_content() {
        let id = setup_test_identity();
        let path = "test_tamper_content.txt";
        create_test_file(path, "hello");
        let f = sign_file(path, &id, "genesis".to_string()).unwrap();
        
        let mut chain = AuthorshipChain::new();
        chain.append(f).unwrap();
        chain.save_for_file(path).unwrap();

        // Modify file content after signing
        fs::write(path, "tampered").unwrap();

        let report = verify_file(path).unwrap();
        assert!(!report.verdict);
        assert_eq!(report.results.iter().find(|r| r.check_id == "artifact_binding").unwrap().reason_code, Some("file_hash_mismatch".to_string()));
        
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_temporal_policy_violation_monotonicity() {
        let id = setup_test_identity();
        let path = "test_time_mono.txt";
        create_test_file(path, "hello");
        
        let mut f1 = sign_file(path, &id, "genesis".to_string()).unwrap();
        // Set f1 to 2 minute in future
        f1.timestamp = (Utc::now() + Duration::minutes(2)).to_rfc3339();
        
        // RE-SIGN f1 because timestamp changed
        let payload1 = SigningPayload {
            protocol_tag: "etch-v1",
            hash_algorithm: "sha2-256",
            code_hash: &f1.code_hash,
            contributor_pubkey: &f1.contributor_pubkey,
            prev_hash: &f1.prev_hash,
            timestamp: &f1.timestamp,
        };
        let canonical1 = serde_json::to_vec(&payload1).unwrap();
        f1.signature = hex::encode(id.signing_key.sign(&canonical1).to_bytes());

        let h1 = hash_fingerprint(&f1).unwrap();
        
        let mut f2 = sign_file(path, &id, h1).unwrap();
        // f2 is now, which is earlier than f1
        f2.timestamp = Utc::now().to_rfc3339();
        
        // RE-SIGN f2 because timestamp changed
        let payload2 = SigningPayload {
            protocol_tag: "etch-v1",
            hash_algorithm: "sha2-256",
            code_hash: &f2.code_hash,
            contributor_pubkey: &f2.contributor_pubkey,
            prev_hash: &f2.prev_hash,
            timestamp: &f2.timestamp,
        };
        let canonical2 = serde_json::to_vec(&payload2).unwrap();
        f2.signature = hex::encode(id.signing_key.sign(&canonical2).to_bytes());
        
        let mut chain = AuthorshipChain::new();
        chain.fingerprints.push(f1);
        chain.fingerprints.push(f2);
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(!report.verdict);
        assert!(report.results.iter().any(|r| r.check_id == "temporal_policy" && r.reason_code == Some("sequence_invalid".to_string())));
        
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }

    #[test]
    fn test_temporal_policy_violation_future_skew() {
        let id = setup_test_identity();
        let path = "test_time_future.txt";
        create_test_file(path, "hello");
        
        let mut f = sign_file(path, &id, "genesis".to_string()).unwrap();
        f.timestamp = (Utc::now() + Duration::minutes(10)).to_rfc3339(); // 10 mins in future
        
        // RE-SIGN because timestamp changed
        let payload = SigningPayload {
            protocol_tag: "etch-v1",
            hash_algorithm: "sha2-256",
            code_hash: &f.code_hash,
            contributor_pubkey: &f.contributor_pubkey,
            prev_hash: &f.prev_hash,
            timestamp: &f.timestamp,
        };
        let canonical = serde_json::to_vec(&payload).unwrap();
        f.signature = hex::encode(id.signing_key.sign(&canonical).to_bytes());

        let mut chain = AuthorshipChain::new();
        chain.fingerprints.push(f);
        chain.save_for_file(path).unwrap();

        let report = verify_file(path).unwrap();
        assert!(!report.verdict);
        assert!(report.results.iter().any(|r| r.check_id == "temporal_policy" && r.reason_code == Some("timestamp_policy_violation".to_string())));
        
        fs::remove_file(path).ok();
        fs::remove_file(format!("{}.etch", path)).ok();
    }
}
