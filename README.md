# etch

**human authorship, etched in code**

etch is a research-driven protocol that preserves and verifies human authorship in software.
In an era where AI can generate and transform code at scale, etch ensures that human
creators remain cryptographically visible, accountable, and credited.

Code may change.
Authorship should not disappear.

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

- **Protocol-gated credit**  
  Not all code changes qualify for authorship.  
  Contributions must satisfy defined structural or semantic standards to earn a fingerprint.

- **Verifiable by design**  
  Authorship lineage can be independently verified using standard cryptographic assumptions.

---

## What etch is not

- Not a license
- Not a copyright replacement
- Not a watermark or comment-based attribution
- Not a blockchain or cryptocurrency system

etch focuses on **authorship provenance**, not ownership or monetization.

---

## High-level Model

1. A human creates or meaningfully modifies code.
2. The code is evaluated against etch contribution standards.
3. If eligible, the contributor cryptographically signs the code state.
4. The signature is appended to an immutable authorship chain.
5. Future modifications preserve the chain.
6. AI-driven changes do not alter authorship lineage.
7. When another human contributes meaningfully, a new signature is appended.

Over time, the code accumulates a verifiable human lineage.

---

## Status

This project is currently **research-in-progress**.

The repository focuses on:
- protocol definition
- theoretical foundations
- threat models
- future prototype directions

Implementation details will evolve iteratively.

---

## Vision

As code becomes easier to generate, **intent, responsibility, and authorship**
become more valuable than syntax.

etch exists to make sure code remembers the humans behind it.

---

## License

To be defined.
