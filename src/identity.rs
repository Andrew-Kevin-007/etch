use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::process::Command;

// WARNING: This is prototype-level storage.
// The signing key is saved as cleartext hex in a JSON file.
// For production use, an OS keystore (like Keychain on macOS, Windows Credential Manager, or Secret Service API on Linux)
// or passphrase-derived encryption (e.g., Argon2 + AES-GCM) should be used to protect the private key.
#[derive(Serialize, Deserialize)]
pub struct EtchIdentity {
    #[serde(with = "hex_serde")]
    pub signing_key: SigningKey,
}

impl EtchIdentity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        Self { signing_key }
    }

    /// Path to the identity file (~/.etch/identity.json)
    fn get_path() -> io::Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "Could not find home directory")
        })?;
        Ok(home.join(".etch").join("identity.json"))
    }

    /// Save the identity to the default location with permission hardening
    pub fn save(&self) -> io::Result<()> {
        let path = Self::get_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        if cfg!(windows) {
            let username = std::env::var("USERNAME").map_err(|_| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "Failed to resolve USERNAME environment variable for permission hardening",
                )
            })?;

            // Write to a temporary file first to avoid exposing sensitive data with default permissions
            let mut temp_path = path.clone();
            temp_path.set_extension("tmp");
            fs::write(&temp_path, &json)?;

            // Permission hardening (restrict to owner read/write) on the temp file
            // We use canonical path or absolute path to avoid issues with icacls finding the file
            let absolute_temp_path = fs::canonicalize(&temp_path).map_err(|e| {
                let _ = fs::remove_file(&temp_path);
                e
            })?;

            let output = Command::new("icacls")
                .arg(&absolute_temp_path)
                .arg("/inheritance:r") // remove inheritance
                .arg("/grant:r")
                .arg(format!("{}:(R,W)", username))
                .output()
                .map_err(|e| {
                    let _ = fs::remove_file(&temp_path);
                    io::Error::new(io::ErrorKind::Other, format!("Failed to spawn icacls: {}", e))
                })?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let _ = fs::remove_file(&temp_path);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("icacls failed with exit code {}: {}", output.status, stderr),
                ));
            }

            // Atomically move the hardened temp file to the final path
            fs::rename(&temp_path, &path).map_err(|e| {
                let _ = fs::remove_file(&temp_path);
                e
            })?;
        } else if cfg!(unix) {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Create with owner-only permissions from the start
                let mut options = fs::OpenOptions::new();
                options.create(true).write(true).truncate(true).mode(0o600);
                let mut file = options.open(&path)?;
                use std::io::Write;
                file.write_all(json.as_bytes())?;
            }
        } else {
            // Fallback for other platforms (less secure, but better than nothing)
            fs::write(&path, json)?;
        }

        Ok(())
    }

    /// Load the identity from the default location
    pub fn load() -> io::Result<Self> {
        let path = Self::get_path()?;
        let json = fs::read_to_string(path)?;
        let identity = serde_json::from_str(&json)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(identity)
    }

    /// Returns the public key as a hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }
}

mod hex_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(key: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(key.to_bytes()))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("invalid key length"))?;
        Ok(SigningKey::from_bytes(&array))
    }
}
