# RFC 4880 Compliance

This document tracks gpg-inspector-lib's compliance with [RFC 4880 (OpenPGP Message Format)](https://datatracker.ietf.org/doc/html/rfc4880) and related specifications.

**Library Version:** 0.4.0
**Last Updated:** 2026-01-20

## Design Philosophy

gpg-inspector is a **parsing and inspection library**, not a cryptographic implementation. It extracts and displays packet structure without performing cryptographic operations (decryption, signature verification, key derivation). This is intentional—the goal is to inspect and debug OpenPGP data, not to process it.

---

## Compliance Summary

| Category | Compliant | Partial | Not Applicable | Total |
|----------|-----------|---------|----------------|-------|
| Packet Types | 14 | 0 | 7 | 21 |
| Signature Subpackets | 26 | 0 | 0 | 26 |
| Public-Key Algorithms | 8 | 0 | 0 | 8 |
| Symmetric Algorithms | 13 | 0 | 0 | 13 |
| Hash Algorithms | 11 | 0 | 0 | 11 |
| Compression Algorithms | 4 | 0 | 0 | 4 |
| S2K Specifiers | 4 | 0 | 0 | 4 |

---

## Section 3: Data Element Formats

| Section | Feature | Status | Notes |
|---------|---------|--------|-------|
| 3.1 | Scalar Numbers | ✅ Complete | Big-endian unsigned integers |
| 3.2 | Multiprecision Integers (MPI) | ✅ Complete | Bit count + data parsing |
| 3.3 | Key IDs | ✅ Complete | 8-octet scalars |
| 3.4 | Text (UTF-8) | ✅ Complete | With replacement char for invalid UTF-8 |
| 3.5 | Time Fields | ✅ Complete | Unix timestamps since 1970-01-01 |
| 3.6 | Keyrings | ⬜ N/A | Storage format, not packet format |
| 3.7.1.1 | Simple S2K | ✅ Complete | Type 0 |
| 3.7.1.2 | Salted S2K | ✅ Complete | Type 1, 8-byte salt |
| 3.7.1.3 | Iterated and Salted S2K | ✅ Complete | Type 3, with count formula |
| — | Argon2 S2K (RFC 9580) | ✅ Complete | Type 4, memory-hard KDF |

---

## Section 4: Packet Syntax

| Section | Feature | Status | Notes |
|---------|---------|--------|-------|
| 4.2 | Packet Headers | ✅ Complete | Old and new format |
| 4.2.1 | Old Format Packet Lengths | ✅ Complete | 1, 2, 4-octet and indeterminate |
| 4.2.2.1 | One-Octet Lengths | ✅ Complete | 0-191 |
| 4.2.2.2 | Two-Octet Lengths | ✅ Complete | 192-8383 |
| 4.2.2.3 | Five-Octet Lengths | ✅ Complete | Up to 4GB |
| 4.2.2.4 | Partial Body Lengths | ✅ Complete | Streaming packets |
| 4.3 | Packet Tags | ✅ Complete | All 21 tags recognized |

---

## Section 5: Packet Types

| Tag | Packet Type | Section | Status | Notes |
|-----|-------------|---------|--------|-------|
| 0 | Reserved | — | ⬜ N/A | Must not appear |
| 1 | Public-Key Encrypted Session Key | 5.1 | ✅ Complete | Version, key ID, algorithm, encrypted data |
| 2 | Signature | 5.2 | ✅ Complete | V3, V4, V5 with all subpackets |
| 3 | Symmetric-Key Encrypted Session Key | 5.3 | ✅ Complete | Version, algorithm, S2K, encrypted key |
| 4 | One-Pass Signature | 5.4 | ✅ Complete | Version, type, algorithms, key ID, nested flag |
| 5 | Secret-Key | 5.5.1.3 | ✅ Complete | Public key + encrypted private material |
| 6 | Public-Key | 5.5.1.1 | ✅ Complete | V4/V5, creation time, algorithm, key material |
| 7 | Secret-Subkey | 5.5.1.4 | ✅ Complete | Same as Secret-Key |
| 8 | Compressed Data | 5.6 | ✅ Complete | Algorithm ID extracted |
| 9 | Symmetrically Encrypted Data | 5.7 | ✅ Complete | Legacy packet, raw ciphertext |
| 10 | Marker | 5.8 | ✅ Complete | "PGP" magic bytes verified |
| 11 | Literal Data | 5.9 | ✅ Complete | Format, filename, date, content |
| 12 | Trust | 5.10 | ⬜ N/A | Implementation-specific, not exported |
| 13 | User ID | 5.11 | ✅ Complete | UTF-8 string |
| 14 | Public-Subkey | 5.5.1.2 | ✅ Complete | Same as Public-Key |
| 17 | User Attribute | 5.12 | ✅ Complete | Image subpacket with JPEG detection |
| 18 | Sym. Encrypted Integrity Protected Data | 5.13 | ✅ Complete | V1 (MDC) and V2 (AEAD) |
| 19 | Modification Detection Code | 5.14 | ✅ Complete | 20-byte SHA-1 hash extracted |
| 20 | AEAD Encrypted Data (RFC 9580) | — | ✅ Complete | Version, algorithm, AEAD mode, chunk size |
| 21 | Padding (RFC 9580) | — | ✅ Complete | Random padding bytes |
| 60-63 | Private/Experimental | — | ✅ Complete | Stored as raw bytes |

---

## Section 5.2.3: Signature Subpackets

| Type | Subpacket | Section | Status | Notes |
|------|-----------|---------|--------|-------|
| 2 | Signature Creation Time | 5.2.3.4 | ✅ Complete | Required, 4-octet timestamp |
| 3 | Signature Expiration Time | 5.2.3.10 | ✅ Complete | Seconds after creation |
| 4 | Exportable Certification | 5.2.3.11 | ✅ Complete | Boolean |
| 5 | Trust Signature | 5.2.3.13 | ✅ Complete | Level and amount |
| 6 | Regular Expression | 5.2.3.14 | ✅ Complete | Null-terminated string |
| 7 | Revocable | 5.2.3.12 | ✅ Complete | Boolean |
| 9 | Key Expiration Time | 5.2.3.6 | ✅ Complete | Seconds after key creation |
| 10 | Placeholder | — | ⬜ N/A | Backward compatibility only |
| 11 | Preferred Symmetric Algorithms | 5.2.3.7 | ✅ Complete | Ordered array |
| 12 | Revocation Key | 5.2.3.15 | ✅ Complete | Class, algorithm, fingerprint |
| 16 | Issuer | 5.2.3.5 | ✅ Complete | 8-octet Key ID |
| 20 | Notation Data | 5.2.3.16 | ✅ Complete | Flags, name, value |
| 21 | Preferred Hash Algorithms | 5.2.3.8 | ✅ Complete | Ordered array |
| 22 | Preferred Compression Algorithms | 5.2.3.9 | ✅ Complete | Ordered array |
| 23 | Key Server Preferences | 5.2.3.17 | ✅ Complete | Flags with no-modify bit |
| 24 | Preferred Key Server | 5.2.3.18 | ✅ Complete | URI string |
| 25 | Primary User ID | 5.2.3.19 | ✅ Complete | Boolean |
| 26 | Policy URI | 5.2.3.20 | ✅ Complete | URI string |
| 27 | Key Flags | 5.2.3.21 | ✅ Complete | All 7 flags decoded |
| 28 | Signer's User ID | 5.2.3.22 | ✅ Complete | UTF-8 string |
| 29 | Reason for Revocation | 5.2.3.23 | ✅ Complete | Code + description |
| 30 | Features | 5.2.3.24 | ✅ Complete | MDC, AEAD, V5 keys |
| 31 | Signature Target | 5.2.3.25 | ✅ Complete | Algorithms + hash |
| 32 | Embedded Signature | 5.2.3.26 | ✅ Complete | Full signature packet |
| 33 | Issuer Fingerprint (RFC 9580) | — | ✅ Complete | Version + fingerprint |
| 34 | Preferred AEAD Algorithms (RFC 9580) | — | ✅ Complete | Ordered array |
| 35 | Intended Recipient (RFC 9580) | — | ✅ Complete | Version + fingerprint |
| 37 | Attested Certifications (RFC 9580) | — | ✅ Complete | Hash list |
| 38 | Key Block (RFC 9580) | — | ✅ Complete | Flags + key data |
| 39 | Preferred AEAD Ciphersuites (RFC 9580) | — | ✅ Complete | Cipher + AEAD pairs |
| 100-110 | Private/Experimental | — | ✅ Complete | Raw bytes preserved |

---

## Section 6: Radix-64 (ASCII Armor)

| Section | Feature | Status | Notes |
|---------|---------|--------|-------|
| 6.1 | CRC-24 Checksum | ✅ Complete | Generator 0x864CFB, init 0xB704CE |
| 6.2 | Armor Header Lines | ✅ Complete | All standard types recognized |
| 6.2 | Armor Headers (Version, Comment, etc.) | ✅ Complete | Parsed and available |
| 6.3 | Base64 Encoding | ✅ Complete | Standard alphabet |
| 6.4 | Base64 Decoding | ✅ Complete | Whitespace tolerant |

### Recognized Armor Types

- `BEGIN PGP MESSAGE`
- `BEGIN PGP PUBLIC KEY BLOCK`
- `BEGIN PGP PRIVATE KEY BLOCK`
- `BEGIN PGP SIGNATURE`
- `BEGIN PGP SIGNED MESSAGE` (cleartext signatures)
- `BEGIN PGP MESSAGE, PART X/Y` (multi-part)

---

## Section 7: Cleartext Signature Framework

| Feature | Status | Notes |
|---------|--------|-------|
| Cleartext header detection | ✅ Complete | `-----BEGIN PGP SIGNED MESSAGE-----` |
| Hash armor header | ✅ Complete | Extracted from headers |
| Dash-escaped text | ⬜ N/A | Display only, no canonicalization |
| Signature verification | ⬜ N/A | Parsing only, no crypto |

---

## Section 9: Algorithm Constants

### 9.1 Public-Key Algorithms

| ID | Algorithm | Status | Notes |
|----|-----------|--------|-------|
| 1 | RSA (Encrypt or Sign) | ✅ Complete | n, e extracted |
| 2 | RSA Encrypt-Only | ✅ Complete | Deprecated |
| 3 | RSA Sign-Only | ✅ Complete | Deprecated |
| 16 | Elgamal (Encrypt-Only) | ✅ Complete | p, g, y extracted |
| 17 | DSA | ✅ Complete | p, q, g, y extracted |
| 18 | ECDH (RFC 6637) | ✅ Complete | OID, point, KDF params |
| 19 | ECDSA (RFC 6637) | ✅ Complete | OID, point |
| 22 | EdDSA (Legacy) | ✅ Complete | OID, public key |
| 25 | X25519 (RFC 9580) | ✅ Complete | 32-byte public key |
| 27 | Ed25519 (RFC 9580) | ✅ Complete | 32-byte public key |
| 100-110 | Private/Experimental | ✅ Complete | Raw bytes |

### 9.2 Symmetric-Key Algorithms

| ID | Algorithm | Status |
|----|-----------|--------|
| 0 | Plaintext | ✅ Recognized |
| 1 | IDEA | ✅ Recognized |
| 2 | TripleDES | ✅ Recognized |
| 3 | CAST5 | ✅ Recognized |
| 4 | Blowfish | ✅ Recognized |
| 7 | AES-128 | ✅ Recognized |
| 8 | AES-192 | ✅ Recognized |
| 9 | AES-256 | ✅ Recognized |
| 10 | Twofish | ✅ Recognized |
| 11 | Camellia-128 | ✅ Recognized |
| 12 | Camellia-192 | ✅ Recognized |
| 13 | Camellia-256 | ✅ Recognized |

### 9.3 Compression Algorithms

| ID | Algorithm | Status |
|----|-----------|--------|
| 0 | Uncompressed | ✅ Recognized |
| 1 | ZIP (RFC 1951) | ✅ Recognized |
| 2 | ZLIB (RFC 1950) | ✅ Recognized |
| 3 | BZip2 | ✅ Recognized |

### 9.4 Hash Algorithms

| ID | Algorithm | Status |
|----|-----------|--------|
| 1 | MD5 | ✅ Recognized |
| 2 | SHA-1 | ✅ Recognized |
| 3 | RIPEMD-160 | ✅ Recognized |
| 8 | SHA-256 | ✅ Recognized |
| 9 | SHA-384 | ✅ Recognized |
| 10 | SHA-512 | ✅ Recognized |
| 11 | SHA-224 | ✅ Recognized |
| 12 | SHA3-256 (RFC 9580) | ✅ Recognized |
| 14 | SHA3-512 (RFC 9580) | ✅ Recognized |

### AEAD Algorithms (RFC 9580)

| ID | Algorithm | Status |
|----|-----------|--------|
| 1 | EAX | ✅ Recognized |
| 2 | OCB | ✅ Recognized |
| 3 | GCM | ✅ Recognized |

---

## Features NOT Implemented (By Design)

These features require cryptographic operations and are outside the scope of an inspection library:

| Feature | RFC Section | Reason |
|---------|-------------|--------|
| Signature verification | 5.2.4 | Requires hash computation + public key crypto |
| Decryption | 5.7, 5.13 | Requires symmetric/public key crypto |
| Key derivation (S2K execution) | 3.7 | Requires hash computation |
| Fingerprint computation | 12.2 | Requires SHA-1/SHA-256 hashing |
| MDC verification | 5.14 | Requires SHA-1 computation |

---

## RFC 9580 (OpenPGP v5) Extensions

gpg-inspector also supports these RFC 9580 extensions:

| Feature | Status |
|---------|--------|
| Version 5 keys | ✅ Complete |
| Version 5 signatures | ✅ Complete |
| SEIPD v2 (AEAD) | ✅ Complete |
| X25519 (algorithm 25) | ✅ Complete |
| Ed25519 (algorithm 27) | ✅ Complete |
| Argon2 S2K (type 4) | ✅ Complete |
| AEAD Encrypted Data (tag 20) | ✅ Complete |
| Padding packet (tag 21) | ✅ Complete |

---

## Legend

- ✅ **Complete** — Fully implemented per specification
- ⚠️ **Partial** — Some functionality missing
- ⬜ **N/A** — Not applicable to parsing library or deprecated
