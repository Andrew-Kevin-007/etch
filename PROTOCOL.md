# Etch Protocol Specification (etch-v1)

This document defines the cryptographic structure and verification logic for `etch`, a system for ensuring file integrity and authorship provenance.

## Fingerprint Format

A `Fingerprint` represents a single point-in-time claim of authorship or content state by a specific identity.

| Field | Type | Description |
|-------|------|-------------|
| `contributor_pubkey` | Hex String | 32-byte Ed25519 public key of the signer. |
| `timestamp` | ISO 8601 String | UTC timestamp in RFC 3339 format. |
| `code_hash` | Hex String | SHA-256 hash of the target file contents. |
| `prev_hash` | Hex String | SHA-256 hash of the previous fingerprint's canonical JSON, or `"genesis"`. |
| `signature` | Hex String | 64-byte Ed25519 signature over the `SigningPayload`. |

## Authorship Chain

The `.etch` file contains an `AuthorshipChain`, which is an ordered list of fingerprints.

- **Append-only Guarantee**: Each fingerprint (except the first) contains a `prev_hash` linking to the SHA-256 commitment of the previous entry.
- **Integrity**: Any modification, reordering, or truncation of the chain is detectable by verifying the hash-linkages and signatures.

## Signing Algorithm

### Signing Payload

To ensure canonical representation and protect against ambiguity, `etch` signs a structured JSON payload:

```json
{
  "protocol_tag": "etch-v1",
  "hash_algorithm": "sha2-256",
  "code_hash": "...",
  "contributor_pubkey": "...",
  "prev_hash": "...",
  "timestamp": "..."
}
```

### Process

1. Compute SHA-256 of the target file.
2. Construct the `SigningPayload` with current UTC timestamp and the previous fingerprint's hash.
3. Serialize the payload to canonical JSON bytes.
4. Sign the bytes using Ed25519.
5. Store the result in the authorship chain.

## Threat Model

### Addressed Threats

- **Unauthorized Modification**: If a third party modifies the file, the `code_hash` in the chain will no longer match the file's current hash.
- **Identity Spoofing**: Signatures ensure that only the holder of the private key corresponding to `contributor_pubkey` could have created the fingerprint.
- **Chain Tampering**: Hash-linking prevents attackers from removing or reordering historical authorship records without breaking the chain's integrity.
- **Timestamp Manipulation**: The verification pipeline enforces monotonic timestamps and rejects future-dated fingerprints (beyond a 5-minute skew).

### Out of Scope

- **Private Key Compromise**: If an attacker steals the private key, they can produce valid fingerprints. Users should protect their keys with OS-level keystores or encryption.
- **File Deletion**: `etch` ensures the integrity of *existing* files and chains but cannot prevent their deletion.

## AI & Automation Note

AI systems and automated scripts cannot produce valid `etch` fingerprints without access to a private key. This allows human-in-the-loop verification where "signed by a known developer" serves as a proxy for "reviewed and approved by a human".
