use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketTag {
    Reserved,
    PublicKeyEncryptedSessionKey,
    Signature,
    SymmetricKeyEncryptedSessionKey,
    OnePassSignature,
    SecretKey,
    PublicKey,
    SecretSubkey,
    CompressedData,
    SymmetricallyEncryptedData,
    Marker,
    LiteralData,
    Trust,
    UserId,
    PublicSubkey,
    UserAttribute,
    SymmetricallyEncryptedIntegrityProtectedData,
    ModificationDetectionCode,
    AeadEncryptedData,
    Padding,
    Unknown(u8),
}

impl PacketTag {
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => PacketTag::Reserved,
            1 => PacketTag::PublicKeyEncryptedSessionKey,
            2 => PacketTag::Signature,
            3 => PacketTag::SymmetricKeyEncryptedSessionKey,
            4 => PacketTag::OnePassSignature,
            5 => PacketTag::SecretKey,
            6 => PacketTag::PublicKey,
            7 => PacketTag::SecretSubkey,
            8 => PacketTag::CompressedData,
            9 => PacketTag::SymmetricallyEncryptedData,
            10 => PacketTag::Marker,
            11 => PacketTag::LiteralData,
            12 => PacketTag::Trust,
            13 => PacketTag::UserId,
            14 => PacketTag::PublicSubkey,
            17 => PacketTag::UserAttribute,
            18 => PacketTag::SymmetricallyEncryptedIntegrityProtectedData,
            19 => PacketTag::ModificationDetectionCode,
            20 => PacketTag::AeadEncryptedData,
            21 => PacketTag::Padding,
            n => PacketTag::Unknown(n),
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            PacketTag::Reserved => 0,
            PacketTag::PublicKeyEncryptedSessionKey => 1,
            PacketTag::Signature => 2,
            PacketTag::SymmetricKeyEncryptedSessionKey => 3,
            PacketTag::OnePassSignature => 4,
            PacketTag::SecretKey => 5,
            PacketTag::PublicKey => 6,
            PacketTag::SecretSubkey => 7,
            PacketTag::CompressedData => 8,
            PacketTag::SymmetricallyEncryptedData => 9,
            PacketTag::Marker => 10,
            PacketTag::LiteralData => 11,
            PacketTag::Trust => 12,
            PacketTag::UserId => 13,
            PacketTag::PublicSubkey => 14,
            PacketTag::UserAttribute => 17,
            PacketTag::SymmetricallyEncryptedIntegrityProtectedData => 18,
            PacketTag::ModificationDetectionCode => 19,
            PacketTag::AeadEncryptedData => 20,
            PacketTag::Padding => 21,
            PacketTag::Unknown(n) => *n,
        }
    }
}

impl fmt::Display for PacketTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PacketTag::Reserved => write!(f, "Reserved"),
            PacketTag::PublicKeyEncryptedSessionKey => {
                write!(f, "Public-Key Encrypted Session Key")
            }
            PacketTag::Signature => write!(f, "Signature"),
            PacketTag::SymmetricKeyEncryptedSessionKey => {
                write!(f, "Symmetric-Key Encrypted Session Key")
            }
            PacketTag::OnePassSignature => write!(f, "One-Pass Signature"),
            PacketTag::SecretKey => write!(f, "Secret Key"),
            PacketTag::PublicKey => write!(f, "Public Key"),
            PacketTag::SecretSubkey => write!(f, "Secret Subkey"),
            PacketTag::CompressedData => write!(f, "Compressed Data"),
            PacketTag::SymmetricallyEncryptedData => write!(f, "Symmetrically Encrypted Data"),
            PacketTag::Marker => write!(f, "Marker"),
            PacketTag::LiteralData => write!(f, "Literal Data"),
            PacketTag::Trust => write!(f, "Trust"),
            PacketTag::UserId => write!(f, "User ID"),
            PacketTag::PublicSubkey => write!(f, "Public Subkey"),
            PacketTag::UserAttribute => write!(f, "User Attribute"),
            PacketTag::SymmetricallyEncryptedIntegrityProtectedData => {
                write!(f, "Symmetrically Encrypted Integrity Protected Data")
            }
            PacketTag::ModificationDetectionCode => write!(f, "Modification Detection Code"),
            PacketTag::AeadEncryptedData => write!(f, "AEAD Encrypted Data"),
            PacketTag::Padding => write!(f, "Padding"),
            PacketTag::Unknown(n) => write!(f, "Unknown ({})", n),
        }
    }
}
