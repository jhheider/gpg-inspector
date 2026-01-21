# RFC 9580 Compliance

This document tracks gpg-inspector-lib's compliance with [RFC 9580 (OpenPGP)](https://datatracker.ietf.org/doc/html/rfc9580), the successor to RFC 4880. RFC 9580 introduces Version 6 packets, new algorithms (X448, Ed448), AEAD encryption, and Argon2 key derivation.

**Library Version:** 0.4.0
**Last Updated:** 2026-01-20

## Design Philosophy

gpg-inspector is a **parsing and inspection library**, not a cryptographic implementation. It extracts and displays packet structure without performing cryptographic operations (decryption, signature verification, key derivation). This is intentional—the goal is to inspect and debug OpenPGP data, not to process it.

---

## Compliance Summary

| Category | Compliant | Partial | Not Applicable | Total |
|----------|-----------|---------|----------------|-------|
| V6 Packet Types | 6 | 0 | 0 | 6 |
| New Algorithms | 4 | 0 | 0 | 4 |
| AEAD Modes | 3 | 0 | 0 | 3 |
| S2K Types | 1 | 0 | 0 | 1 |
| New Subpackets | 5 | 0 | 0 | 5 |

---

## Version 6 Packet Types

RFC 9580 introduces Version 6 formats for several packet types. V5 was a draft that never shipped — RFC 9580 skips from V4 to V6.

| Packet Type | Tag | Status | Notes |
|-------------|-----|--------|-------|
| V6 Public Key | 6 | ✅ Complete | 4-byte key material length field, X448/Ed448 support |
| V6 Secret Key | 5 | ✅ Complete | Delegates to V6 public key parsing |
| V6 Public Subkey | 14 | ✅ Complete | Same as V6 Public Key |
| V6 Secret Subkey | 7 | ✅ Complete | Delegates to V6 public key parsing |
| V6 Signature | 2 | ✅ Complete | Salt field, 4-byte subpacket lengths |
| V6 PKESK | 1 | ✅ Complete | Key version field, variable key identification |
| V6 SKESK | 3 | ✅ Complete | AEAD parameters (already implemented) |
| V6 One-Pass Signature | 4 | ✅ Complete | Salt, 32-byte fingerprint (already implemented) |
| SEIPD v2 | 18 | ✅ Complete | 32-byte salt field |

---

## V6 Public Key (Section 5.5.2)

V6 public keys have the following structure:

| Field | Size | Status |
|-------|------|--------|
| Version | 1 octet | ✅ Parsed |
| Creation Time | 4 octets | ✅ Parsed |
| Algorithm | 1 octet | ✅ Parsed |
| Key Material Length | 4 octets | ✅ Parsed (NEW in V6) |
| Algorithm-specific fields | Variable | ✅ Parsed |

---

## V6 Signature (Section 5.2)

V6 signatures have significant changes from V4:

| Field | Size | Status | Notes |
|-------|------|--------|-------|
| Version | 1 octet | ✅ Parsed | |
| Signature Type | 1 octet | ✅ Parsed | |
| Public Key Algorithm | 1 octet | ✅ Parsed | |
| Hash Algorithm | 1 octet | ✅ Parsed | |
| Salt | 16-32 octets | ✅ Parsed | Length depends on hash algorithm |
| Hashed Subpacket Length | 4 octets | ✅ Parsed | (was 2 octets in V4) |
| Hashed Subpackets | Variable | ✅ Parsed | |
| Unhashed Subpacket Length | 4 octets | ✅ Parsed | (was 2 octets in V4) |
| Unhashed Subpackets | Variable | ✅ Parsed | |
| Hash Prefix | 2 octets | ✅ Parsed | |
| Signature Data | Variable | ✅ Parsed | |

### Salt Length by Hash Algorithm

| Hash Algorithm | Salt Length | Status |
|----------------|-------------|--------|
| SHA-256 (8) | 16 bytes | ✅ Supported |
| SHA3-256 (12) | 16 bytes | ✅ Supported |
| SHA-384 (9) | 24 bytes | ✅ Supported |
| SHA-512 (10) | 32 bytes | ✅ Supported |
| SHA3-512 (14) | 32 bytes | ✅ Supported |

---

## V6 PKESK (Section 5.1)

V6 PKESK packets have a new key version field:

| Field | Size | Status | Notes |
|-------|------|--------|-------|
| Version | 1 octet | ✅ Parsed | |
| Key Version | 1 octet | ✅ Parsed | NEW in V6 |
| Key Identification | Variable | ✅ Parsed | Based on key version |
| Algorithm | 1 octet | ✅ Parsed | |
| Encrypted Session Key | Variable | ✅ Parsed | |

### Key Identification Variants

| Key Version | Key Identification | Status |
|-------------|-------------------|--------|
| 0 | None (anonymous) | ✅ Supported |
| 4 | 8-byte Key ID | ✅ Supported |
| 6 | 32-byte Fingerprint | ✅ Supported |

---

## SEIPD v2 (Section 5.13.2)

SEIPD v2 uses AEAD encryption with a mandatory salt:

| Field | Size | Status |
|-------|------|--------|
| Version | 1 octet | ✅ Parsed |
| Cipher Algorithm | 1 octet | ✅ Parsed |
| AEAD Algorithm | 1 octet | ✅ Parsed |
| Chunk Size | 1 octet | ✅ Parsed |
| Salt | 32 octets | ✅ Parsed |
| Encrypted Data | Variable | ✅ Parsed |

---

## New Algorithms (Section 9)

### Public-Key Algorithms

| ID | Algorithm | Key Size | Signature Size | Status |
|----|-----------|----------|----------------|--------|
| 25 | X25519 | 32 bytes | N/A (encryption) | ✅ Complete |
| 26 | X448 | 56 bytes | N/A (encryption) | ✅ Complete |
| 27 | Ed25519 | 32 bytes | 64 bytes | ✅ Complete |
| 28 | Ed448 | 57 bytes | 114 bytes | ✅ Complete |

### AEAD Algorithms

| ID | Algorithm | Status |
|----|-----------|--------|
| 1 | EAX | ✅ Recognized |
| 2 | OCB | ✅ Recognized |
| 3 | GCM | ✅ Recognized |

### Hash Algorithms (New)

| ID | Algorithm | Status |
|----|-----------|--------|
| 12 | SHA3-256 | ✅ Recognized |
| 14 | SHA3-512 | ✅ Recognized |

---

## Argon2 S2K (Section 3.7.1.4)

| Field | Size | Status |
|-------|------|--------|
| Type | 1 octet | ✅ Parsed (value: 4) |
| Salt | 16 octets | ✅ Parsed |
| Parallelism (t) | 1 octet | ✅ Parsed |
| Memory (m) | 1 octet | ✅ Parsed |
| Iterations (p) | 1 octet | ✅ Parsed |

---

## New Signature Subpackets

| Type | Subpacket | Section | Status |
|------|-----------|---------|--------|
| 33 | Issuer Fingerprint | 5.2.3.28 | ✅ Complete |
| 34 | Preferred AEAD Algorithms | 5.2.3.8 | ✅ Complete |
| 35 | Intended Recipient Fingerprint | 5.2.3.29 | ✅ Complete |
| 37 | Attested Certifications | 5.2.3.30 | ✅ Complete |
| 38 | Key Block | 5.2.3.31 | ✅ Complete |
| 39 | Preferred AEAD Ciphersuites | 5.2.3.13 | ✅ Complete |

---

## New Packet Types

| Tag | Packet Type | Status | Notes |
|-----|-------------|--------|-------|
| 20 | AEAD Encrypted Data | ✅ Complete | Version, cipher, AEAD, chunk size |
| 21 | Padding | ✅ Complete | Random padding bytes |

---

## Deprecations (Section 15)

RFC 9580 deprecates certain algorithms for new implementations. gpg-inspector still **parses** these for backward compatibility but they should not be used in new messages:

| Algorithm | Status | Notes |
|-----------|--------|-------|
| MD5 (hash 1) | ⚠️ Deprecated | Still parsed for inspection |
| SHA-1 (hash 2) | ⚠️ Deprecated | Still parsed for inspection |
| IDEA (cipher 1) | ⚠️ Deprecated | Still recognized |
| 3DES (cipher 2) | ⚠️ Deprecated | Still recognized |
| CAST5 (cipher 3) | ⚠️ Deprecated | Still recognized |
| V3 Signatures | ⚠️ Deprecated | Still parsed |
| V3 PKESK | ⚠️ Deprecated | Still parsed |

---

## Features NOT Implemented (By Design)

These features require cryptographic operations and are outside the scope of an inspection library:

| Feature | RFC Section | Reason |
|---------|-------------|--------|
| Signature verification | 5.2.4 | Requires hash computation + public key crypto |
| AEAD decryption | 5.13.2 | Requires symmetric key crypto |
| Key derivation (Argon2) | 3.7.1.4 | Requires KDF computation |
| Fingerprint computation | 5.5.4 | Requires SHA-256 hashing |
| V6 PKESK decryption | 5.1 | Requires ECDH key agreement |

---

## Interoperability

gpg-inspector has been designed to parse OpenPGP data from:

- GnuPG 2.4+ (with `--rfc9580` option)
- Sequoia-PGP
- OpenPGP.js
- GopenPGP

---

## Legend

- ✅ **Complete** — Fully implemented per specification
- ⚠️ **Deprecated** — Supported for backward compatibility but deprecated by RFC 9580
- ⬜ **N/A** — Not applicable to parsing library
