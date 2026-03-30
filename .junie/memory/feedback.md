[2026-03-30 13:16] - Updated by Junie
{
    "TYPE": "correction",
    "CATEGORY": "private key storage",
    "EXPECTATION": "Harden identity file handling: restrict permissions on creation and document that cleartext key storage is prototype-only; production should use OS keystore or passphrase-derived encryption.",
    "NEW INSTRUCTION": "WHEN writing secret material to disk THEN set owner-only permissions and add security warning"
}

