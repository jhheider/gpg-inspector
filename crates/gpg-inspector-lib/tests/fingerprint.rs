//! Tests for computed key fingerprints and key IDs.

use gpg_inspector_lib::packet::fingerprint::{key_id, to_hex, v4_fingerprint, v6_fingerprint};
use gpg_inspector_lib::{Field, parse, parse_bytes};

const TEST_KEY: &str = include_str!("../../../fixtures/test.key");

/// Verified independently with `gpg --show-keys --with-fingerprint`.
const TEST_KEY_FINGERPRINT: &str = "EB483B26B078A4AA1B6F425EE21B6950A2ECB65C";

/// RFC 9580 Appendix A.3 sample v6 certificate, with fingerprints
/// stated in the RFC text.
const RFC9580_A3_CERT: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----

xioGY4d/4xsAAAAg+U2nu0jWCmHlZ3BqZYfQMxmZu52JGggkLq2EVD34laPCsQYf
GwoAAABCBYJjh3/jAwsJBwUVCg4IDAIWAAKbAwIeCSIhBssYbE8GCaaX5NUt+mxy
KwwfHifBilZwj2Ul7Ce62azJBScJAgcCAAAAAK0oIBA+LX0ifsDm185Ecds2v8lw
gyU2kCcUmKfvBXbAf6rhRYWzuQOwEn7E/aLwIwRaLsdry0+VcallHhSu4RN6HWaE
QsiPlR4zxP/TP7mhfVEe7XWPxtnMUMtf15OyA51YBM4qBmOHf+MZAAAAIIaTJINn
+eUBXbki+PSAld2nhJh/LVmFsS+60WyvXkQ1wpsGGBsKAAAALAWCY4d/4wKbDCIh
BssYbE8GCaaX5NUt+mxyKwwfHifBilZwj2Ul7Ce62azJAAAAAAQBIKbpGG2dWTX8
j+VjFM21J0hqWlEg+bdiojWnKfA5AQpWUWtnNwDEM0g12vYxoWM8Y81W+bHBw805
I8kWVkXU6vFOi+HWvv/ira7ofJu16NnoUkhclkUrk0mXubZvyl4GBg==
-----END PGP PUBLIC KEY BLOCK-----";

const RFC9580_A3_PRIMARY_FP: &str =
    "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9";
const RFC9580_A3_SUBKEY_FP: &str =
    "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885";

fn field_value<'a>(fields: &'a [Field], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|f| f.name.as_ref() == name)
        .map(|f| f.value.as_ref())
}

#[test]
fn test_v4_fingerprint_matches_gpg() {
    let packets = parse(TEST_KEY).unwrap();
    let fields = &packets[0].fields;

    assert_eq!(
        field_value(fields, "Fingerprint (computed)"),
        Some(TEST_KEY_FINGERPRINT)
    );
    // V4 key ID is the low-order 8 bytes of the fingerprint
    assert_eq!(
        field_value(fields, "Key ID (computed)"),
        Some(&TEST_KEY_FINGERPRINT[24..])
    );
}

#[test]
fn test_v4_fingerprint_matches_issuer_subpacket() {
    // The key's self-signature carries an Issuer Fingerprint subpacket;
    // our computed fingerprint must agree with it
    let packets = parse(TEST_KEY).unwrap();
    let computed = field_value(&packets[0].fields, "Fingerprint (computed)")
        .unwrap()
        .to_string();

    let issuer = packets
        .iter()
        .flat_map(|p| &p.fields)
        .find(|f| f.name.contains("Issuer Fingerprint"))
        .expect("no issuer fingerprint subpacket");
    assert!(issuer.value.contains(&computed));
}

#[test]
fn test_v6_fingerprints_match_rfc9580_sample() {
    let packets = parse(RFC9580_A3_CERT).unwrap();

    // Primary key (packet 0) and subkey (packet 2)
    assert_eq!(
        field_value(&packets[0].fields, "Fingerprint (computed)"),
        Some(RFC9580_A3_PRIMARY_FP)
    );
    assert_eq!(
        field_value(&packets[2].fields, "Fingerprint (computed)"),
        Some(RFC9580_A3_SUBKEY_FP)
    );
    // V6 key ID is the high-order 8 bytes of the fingerprint
    assert_eq!(
        field_value(&packets[0].fields, "Key ID (computed)"),
        Some(&RFC9580_A3_PRIMARY_FP[..16])
    );
}

#[test]
fn test_unknown_version_gets_no_computed_fields() {
    // Version 99 parses via the v4 path with an unknown algorithm;
    // no fingerprint can be computed for it
    let mut packet = vec![0xC0 | 6, 8];
    packet.push(99); // version
    packet.extend_from_slice(&[0x5F, 0xF2, 0xD6, 0x90]); // creation time
    packet.push(100); // unknown algorithm
    packet.extend_from_slice(&[0xAA, 0xBB]); // opaque key material

    let packets = parse_bytes(packet).unwrap();
    assert!(field_value(&packets[0].fields, "Fingerprint (computed)").is_none());
    assert!(field_value(&packets[0].fields, "Key ID (computed)").is_none());
}

#[test]
fn test_fingerprint_functions_direct() {
    // Deterministic: SHA-1/SHA-256 of a fixed body
    let body = [4u8, 0, 0, 0, 0, 1];
    let v4 = v4_fingerprint(&body);
    assert_eq!(v4.len(), 20);
    let v6 = v6_fingerprint(&body);
    assert_eq!(v6.len(), 32);

    // key_id slicing rules
    assert_eq!(key_id(4, &v4), to_hex(&v4[12..]));
    assert_eq!(key_id(6, &v6), to_hex(&v6[..8]));

    // Same input, same output
    assert_eq!(v4_fingerprint(&body), v4);
}
