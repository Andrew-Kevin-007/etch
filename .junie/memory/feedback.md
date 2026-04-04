[2026-03-30 13:16] - Updated by Junie
{
    "TYPE": "correction",
    "CATEGORY": "private key storage",
    "EXPECTATION": "Harden identity file handling: restrict permissions on creation and document that cleartext key storage is prototype-only; production should use OS keystore or passphrase-derived encryption.",
    "NEW INSTRUCTION": "WHEN writing secret material to disk THEN set owner-only permissions and add security warning"
}

[2026-04-04 10:57] - Updated by Junie
{
    "TYPE": "correction",
    "CATEGORY": "server verification format",
    "EXPECTATION": "Use SHA-256(file_path) as chain_id and the latest fingerprint's code_hash as head_hash in server verification, and ensure main verify computes and passes these correctly.",
    "NEW INSTRUCTION": "WHEN calling verify_with_server THEN hash file_path for chain_id and use latest code_hash"
}

