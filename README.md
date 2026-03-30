# Etch: A CLI Tool for Data Integrity and Provenance

`etch` allows you to sign files and maintain an immutable authorship chain. It is designed to verify that files haven't been tampered with and to track who created or modified them over time.

## Installation

You can install `etch` directly from the source using Cargo:

```bash
cargo install --path .
```

## Quick Start

### 1. Initialize your identity

Generate a new Ed25519 keypair and save it to `~/.etch/identity.json`:

```bash
etch init
```

### 2. Sign a file

Create a fingerprint for a file and append it to its authorship chain:

```bash
etch sign --path your_file.txt
```

This creates or updates `your_file.txt.etch`.

### 3. Verify the file

Check the file's integrity and its authorship history:

```bash
etch verify --path your_file.txt
```

Example Output:
```text
Verification Report for: your_file.txt
Verdict: PASS
Verified through entry index: 0

Check Details:
- schema_validation [Entry 0]: OK
- chain_integrity [Entry 0]: OK
- signature_verification [Entry 0]: OK
- temporal_policy [Entry 0]: OK
- artifact_binding [Entry 0]: OK
```

### 4. Verify with JSON output

For automation, use the `--json` flag:

```bash
etch verify --path your_file.txt --json
```

---

## Why etch

Modern software development is increasingly mediated by AI tools.
While AI can generate, refactor, and optimize code, it cannot take responsibility,
hold intent, or claim authorship.

etch is built on a simple principle:

> **AI can carry code.  
> Only humans can sign it.**

etch introduces a cryptographic fingerprint system that allows code to retain a
verifiable lineage of human contributors as it evolves across projects, systems,
and time.

---

## Core Ideas

- **Human-only authorship**  
  Only real users with cryptographic identities can append authorship fingerprints.

- **Append-only lineage**  
  Authorship fingerprints form an immutable chain.  
  New contributors are added; existing ones are never removed.

- **AI as a carrier**  
  AI systems may transform code, but they cannot claim authorship or add fingerprints.

- **Verifiable by design**  
  Authorship lineage can be independently verified using standard cryptographic assumptions.

---

## What etch is NOT

- **Not a Version Control System**: `etch` does not store file history or provide diffing tools. It only tracks authorship of a file's state at the time of signing.
- **Not a Backup Tool**: `etch` does not store copies of your files.
- **Not a Replacement for Code Review**: `etch` provides cryptographic proof of *who* signed a file, but not *what* that file contains or its quality.
- **Not a Sandbox**: `etch` does not prevent malicious files from being signed; it only ensures their provenance is tracked.
- **Not a license or copyright replacement.**
- **Not a watermark or comment-based attribution.**
- **Not a blockchain or cryptocurrency system.**

---

## Status

This project is currently **research-in-progress**.

---

## Vision

As code becomes easier to generate, **intent, responsibility, and authorship**
become more valuable than syntax.

etch exists to make sure code remembers the humans behind it.
