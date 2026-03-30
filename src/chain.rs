use crate::fingerprint::{self, Fingerprint};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AuthorshipChain {
    pub fingerprints: Vec<Fingerprint>,
}

impl AuthorshipChain {
    /// Create a new empty authorship chain
    pub fn new() -> Self {
        Self {
            fingerprints: Vec::new(),
        }
    }

    /// Load the chain from a .etch file associated with the given file path
    /// Enforces append-only by validating each entry's prev_hash.
    pub fn load_for_file(file_path: &str) -> io::Result<Self> {
        let chain_path = Self::get_chain_path(file_path);
        if !chain_path.exists() {
            return Ok(Self::new());
        }
        let json = fs::read_to_string(chain_path)?;
        let chain: AuthorshipChain = serde_json::from_str(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        chain.validate()?;
        Ok(chain)
    }

    /// Validates the authorship chain's cryptographic integrity.
    pub fn validate(&self) -> io::Result<()> {
        let mut expected_prev_hash = "genesis".to_string();
        for (i, fingerprint) in self.fingerprints.iter().enumerate() {
            if fingerprint.prev_hash != expected_prev_hash {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "Chain integrity violation at entry {}: expected prev_hash '{}', found '{}'",
                        i, expected_prev_hash, fingerprint.prev_hash
                    ),
                ));
            }
            expected_prev_hash = fingerprint::hash_fingerprint(fingerprint)?;
        }
        Ok(())
    }

    /// Save the chain to its .etch file
    pub fn save_for_file(&self, file_path: &str) -> io::Result<()> {
        let chain_path = Self::get_chain_path(file_path);
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        fs::write(chain_path, json)?;
        Ok(())
    }

    /// Append a new fingerprint to the chain, ensuring correct prev_hash.
    pub fn append(&mut self, fingerprint: Fingerprint) -> io::Result<()> {
        let expected_prev_hash = if let Some(last) = self.fingerprints.last() {
            fingerprint::hash_fingerprint(last)?
        } else {
            "genesis".to_string()
        };

        if fingerprint.prev_hash != expected_prev_hash {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Fingerprint's prev_hash does not match the end of the chain",
            ));
        }

        self.fingerprints.push(fingerprint);
        Ok(())
    }

    /// Generate the .etch chain file path for a given file path
    fn get_chain_path(file_path: &str) -> PathBuf {
        let mut path = PathBuf::from(file_path);
        let mut filename = path.file_name().unwrap_or_default().to_os_string();
        filename.push(".etch");
        path.set_file_name(filename);
        path
    }
}
