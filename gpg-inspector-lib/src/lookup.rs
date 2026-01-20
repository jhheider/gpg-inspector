pub struct LookupResult<T> {
    pub value: T,
    pub name: String,
}

impl<T: std::fmt::Display> LookupResult<T> {
    pub fn display(&self) -> String {
        format!("{} ({})", self.value, self.name)
    }
}

pub fn lookup_public_key_algorithm(id: u8) -> LookupResult<u8> {
    let name = match id {
        1 => "RSA (Encrypt or Sign)",
        2 => "RSA Encrypt-Only",
        3 => "RSA Sign-Only",
        16 => "Elgamal (Encrypt-Only)",
        17 => "DSA",
        18 => "ECDH",
        19 => "ECDSA",
        20 => "Reserved (formerly Elgamal)",
        21 => "Reserved for Diffie-Hellman",
        22 => "EdDSA",
        23 => "Reserved for AEDH",
        24 => "Reserved for AEDSA",
        25 => "X25519",
        26 => "X448",
        27 => "Ed25519",
        28 => "Ed448",
        100..=110 => "Private/Experimental",
        _ => "Unknown",
    };
    LookupResult {
        value: id,
        name: name.to_string(),
    }
}

pub fn lookup_symmetric_algorithm(id: u8) -> LookupResult<u8> {
    let name = match id {
        0 => "Plaintext",
        1 => "IDEA",
        2 => "TripleDES",
        3 => "CAST5",
        4 => "Blowfish",
        5 => "Reserved",
        6 => "Reserved",
        7 => "AES-128",
        8 => "AES-192",
        9 => "AES-256",
        10 => "Twofish",
        11 => "Camellia-128",
        12 => "Camellia-192",
        13 => "Camellia-256",
        100..=110 => "Private/Experimental",
        _ => "Unknown",
    };
    LookupResult {
        value: id,
        name: name.to_string(),
    }
}

pub fn lookup_hash_algorithm(id: u8) -> LookupResult<u8> {
    let name = match id {
        1 => "MD5",
        2 => "SHA-1",
        3 => "RIPEMD-160",
        4 => "Reserved",
        5 => "Reserved",
        6 => "Reserved",
        7 => "Reserved",
        8 => "SHA-256",
        9 => "SHA-384",
        10 => "SHA-512",
        11 => "SHA-224",
        12 => "SHA3-256",
        13 => "Reserved",
        14 => "SHA3-512",
        100..=110 => "Private/Experimental",
        _ => "Unknown",
    };
    LookupResult {
        value: id,
        name: name.to_string(),
    }
}

pub fn lookup_compression_algorithm(id: u8) -> LookupResult<u8> {
    let name = match id {
        0 => "Uncompressed",
        1 => "ZIP",
        2 => "ZLIB",
        3 => "BZip2",
        100..=110 => "Private/Experimental",
        _ => "Unknown",
    };
    LookupResult {
        value: id,
        name: name.to_string(),
    }
}

pub fn lookup_signature_type(id: u8) -> LookupResult<u8> {
    let name = match id {
        0x00 => "Binary document",
        0x01 => "Canonical text document",
        0x02 => "Standalone",
        0x10 => "Generic certification",
        0x11 => "Persona certification",
        0x12 => "Casual certification",
        0x13 => "Positive certification",
        0x18 => "Subkey Binding",
        0x19 => "Primary Key Binding",
        0x1F => "Direct key",
        0x20 => "Key revocation",
        0x28 => "Subkey revocation",
        0x30 => "Certification revocation",
        0x40 => "Timestamp",
        0x50 => "Third-Party Confirmation",
        _ => "Unknown",
    };
    LookupResult {
        value: id,
        name: name.to_string(),
    }
}

pub fn lookup_subpacket_type(id: u8) -> LookupResult<u8> {
    let name = match id {
        0 => "Reserved",
        1 => "Reserved",
        2 => "Signature Creation Time",
        3 => "Signature Expiration Time",
        4 => "Exportable Certification",
        5 => "Trust Signature",
        6 => "Regular Expression",
        7 => "Revocable",
        8 => "Reserved",
        9 => "Key Expiration Time",
        10 => "Placeholder for backward compatibility",
        11 => "Preferred Symmetric Algorithms",
        12 => "Revocation Key",
        13..=15 => "Reserved",
        16 => "Issuer Key ID",
        17..=19 => "Reserved",
        20 => "Notation Data",
        21 => "Preferred Hash Algorithms",
        22 => "Preferred Compression Algorithms",
        23 => "Key Server Preferences",
        24 => "Preferred Key Server",
        25 => "Primary User ID",
        26 => "Policy URI",
        27 => "Key Flags",
        28 => "Signer's User ID",
        29 => "Reason for Revocation",
        30 => "Features",
        31 => "Signature Target",
        32 => "Embedded Signature",
        33 => "Issuer Fingerprint",
        34 => "Preferred AEAD Algorithms",
        35 => "Intended Recipient Fingerprint",
        37 => "Attested Certifications",
        38 => "Key Block",
        39 => "Preferred AEAD Ciphersuites",
        100..=110 => "Private/Experimental",
        _ => "Unknown/Reserved",
    };
    LookupResult {
        value: id,
        name: name.to_string(),
    }
}

pub fn lookup_curve_oid(oid: &[u8]) -> String {
    match oid {
        [0x2B, 0x81, 0x04, 0x00, 0x22] => "secp384r1 (NIST P-384)".to_string(),
        [0x2B, 0x81, 0x04, 0x00, 0x23] => "secp521r1 (NIST P-521)".to_string(),
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => "secp256r1 (NIST P-256)".to_string(),
        [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07] => "brainpoolP256r1".to_string(),
        [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B] => "brainpoolP384r1".to_string(),
        [0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D] => "brainpoolP512r1".to_string(),
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01] => "Ed25519".to_string(),
        [0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01] => "Curve25519".to_string(),
        _ => {
            let hex: String = oid.iter().map(|b| format!("{:02X}", b)).collect();
            format!("Unknown OID ({})", hex)
        }
    }
}

pub fn lookup_key_flags(flags: u8) -> Vec<&'static str> {
    let mut result = Vec::new();
    if flags & 0x01 != 0 {
        result.push("Certify");
    }
    if flags & 0x02 != 0 {
        result.push("Sign");
    }
    if flags & 0x04 != 0 {
        result.push("Encrypt Communications");
    }
    if flags & 0x08 != 0 {
        result.push("Encrypt Storage");
    }
    if flags & 0x10 != 0 {
        result.push("Split Key");
    }
    if flags & 0x20 != 0 {
        result.push("Authentication");
    }
    if flags & 0x80 != 0 {
        result.push("Shared Key");
    }
    result
}

pub fn lookup_revocation_reason(code: u8) -> &'static str {
    match code {
        0 => "No reason specified",
        1 => "Key is superseded",
        2 => "Key material has been compromised",
        3 => "Key is retired and no longer used",
        32 => "User ID information is no longer valid",
        _ => "Unknown reason",
    }
}

pub fn lookup_s2k_type(id: u8) -> &'static str {
    match id {
        0 => "Simple S2K",
        1 => "Salted S2K",
        2 => "Reserved",
        3 => "Iterated and Salted S2K",
        4 => "Argon2",
        100..=110 => "Private/Experimental",
        _ => "Unknown",
    }
}

pub fn lookup_aead_algorithm(id: u8) -> LookupResult<u8> {
    let name = match id {
        0 => "Reserved",
        1 => "EAX",
        2 => "OCB",
        3 => "GCM",
        100..=110 => "Private/Experimental",
        _ => "Unknown",
    };
    LookupResult {
        value: id,
        name: name.to_string(),
    }
}
