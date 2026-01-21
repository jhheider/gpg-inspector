//! PacketTag tests

use gpg_inspector_lib::packet::tags::PacketTag;

#[test]
fn test_packet_tag_from_u8_all_known() {
    assert_eq!(PacketTag::from_u8(0), PacketTag::Reserved);
    assert_eq!(
        PacketTag::from_u8(1),
        PacketTag::PublicKeyEncryptedSessionKey
    );
    assert_eq!(PacketTag::from_u8(2), PacketTag::Signature);
    assert_eq!(
        PacketTag::from_u8(3),
        PacketTag::SymmetricKeyEncryptedSessionKey
    );
    assert_eq!(PacketTag::from_u8(4), PacketTag::OnePassSignature);
    assert_eq!(PacketTag::from_u8(5), PacketTag::SecretKey);
    assert_eq!(PacketTag::from_u8(6), PacketTag::PublicKey);
    assert_eq!(PacketTag::from_u8(7), PacketTag::SecretSubkey);
    assert_eq!(PacketTag::from_u8(8), PacketTag::CompressedData);
    assert_eq!(PacketTag::from_u8(9), PacketTag::SymmetricallyEncryptedData);
    assert_eq!(PacketTag::from_u8(10), PacketTag::Marker);
    assert_eq!(PacketTag::from_u8(11), PacketTag::LiteralData);
    assert_eq!(PacketTag::from_u8(12), PacketTag::Trust);
    assert_eq!(PacketTag::from_u8(13), PacketTag::UserId);
    assert_eq!(PacketTag::from_u8(14), PacketTag::PublicSubkey);
    assert_eq!(PacketTag::from_u8(17), PacketTag::UserAttribute);
    assert_eq!(
        PacketTag::from_u8(18),
        PacketTag::SymmetricallyEncryptedIntegrityProtectedData
    );
    assert_eq!(PacketTag::from_u8(19), PacketTag::ModificationDetectionCode);
    assert_eq!(PacketTag::from_u8(20), PacketTag::AeadEncryptedData);
    assert_eq!(PacketTag::from_u8(21), PacketTag::Padding);
    assert_eq!(PacketTag::from_u8(99), PacketTag::Unknown(99));
}

#[test]
fn test_packet_tag_to_u8_all_known() {
    assert_eq!(PacketTag::Reserved.to_u8(), 0);
    assert_eq!(PacketTag::PublicKeyEncryptedSessionKey.to_u8(), 1);
    assert_eq!(PacketTag::Signature.to_u8(), 2);
    assert_eq!(PacketTag::SymmetricKeyEncryptedSessionKey.to_u8(), 3);
    assert_eq!(PacketTag::OnePassSignature.to_u8(), 4);
    assert_eq!(PacketTag::SecretKey.to_u8(), 5);
    assert_eq!(PacketTag::PublicKey.to_u8(), 6);
    assert_eq!(PacketTag::SecretSubkey.to_u8(), 7);
    assert_eq!(PacketTag::CompressedData.to_u8(), 8);
    assert_eq!(PacketTag::SymmetricallyEncryptedData.to_u8(), 9);
    assert_eq!(PacketTag::Marker.to_u8(), 10);
    assert_eq!(PacketTag::LiteralData.to_u8(), 11);
    assert_eq!(PacketTag::Trust.to_u8(), 12);
    assert_eq!(PacketTag::UserId.to_u8(), 13);
    assert_eq!(PacketTag::PublicSubkey.to_u8(), 14);
    assert_eq!(PacketTag::UserAttribute.to_u8(), 17);
    assert_eq!(
        PacketTag::SymmetricallyEncryptedIntegrityProtectedData.to_u8(),
        18
    );
    assert_eq!(PacketTag::ModificationDetectionCode.to_u8(), 19);
    assert_eq!(PacketTag::AeadEncryptedData.to_u8(), 20);
    assert_eq!(PacketTag::Padding.to_u8(), 21);
    assert_eq!(PacketTag::Unknown(99).to_u8(), 99);
}

#[test]
fn test_packet_tag_display_all() {
    assert_eq!(format!("{}", PacketTag::Reserved), "Reserved");
    assert_eq!(
        format!("{}", PacketTag::PublicKeyEncryptedSessionKey),
        "Public-Key Encrypted Session Key"
    );
    assert_eq!(format!("{}", PacketTag::Signature), "Signature");
    assert_eq!(
        format!("{}", PacketTag::SymmetricKeyEncryptedSessionKey),
        "Symmetric-Key Encrypted Session Key"
    );
    assert_eq!(
        format!("{}", PacketTag::OnePassSignature),
        "One-Pass Signature"
    );
    assert_eq!(format!("{}", PacketTag::SecretKey), "Secret Key");
    assert_eq!(format!("{}", PacketTag::PublicKey), "Public Key");
    assert_eq!(format!("{}", PacketTag::SecretSubkey), "Secret Subkey");
    assert_eq!(format!("{}", PacketTag::CompressedData), "Compressed Data");
    assert_eq!(
        format!("{}", PacketTag::SymmetricallyEncryptedData),
        "Symmetrically Encrypted Data"
    );
    assert_eq!(format!("{}", PacketTag::Marker), "Marker");
    assert_eq!(format!("{}", PacketTag::LiteralData), "Literal Data");
    assert_eq!(format!("{}", PacketTag::Trust), "Trust");
    assert_eq!(format!("{}", PacketTag::UserId), "User ID");
    assert_eq!(format!("{}", PacketTag::PublicSubkey), "Public Subkey");
    assert_eq!(format!("{}", PacketTag::UserAttribute), "User Attribute");
    assert_eq!(
        format!(
            "{}",
            PacketTag::SymmetricallyEncryptedIntegrityProtectedData
        ),
        "Symmetrically Encrypted Integrity Protected Data"
    );
    assert_eq!(
        format!("{}", PacketTag::ModificationDetectionCode),
        "Modification Detection Code"
    );
    assert_eq!(
        format!("{}", PacketTag::AeadEncryptedData),
        "AEAD Encrypted Data"
    );
    assert_eq!(format!("{}", PacketTag::Padding), "Padding");
    assert_eq!(format!("{}", PacketTag::Unknown(99)), "Unknown (99)");
}
