use crate::{HiveMemoError};
use bytes::{BufMut, BytesMut};
use k256::PublicKey as K256PublicKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{
    PublicKey
};
use crate::varint::{decode_varint32, encode_varint32};

#[derive(Debug, Clone)]
pub struct EncryptedMemo {
    pub nonce: u64,
    pub check: u32,
    pub encrypted: Vec<u8>,
    pub from: PublicKey,
    pub to: PublicKey,
}


// This is the order @hiveo/dhive uses in memo encryption/decryption
// If you are going to write a similar thing by taking this code as referance
// please take endiannes into account while developing as you won't be able to notice it
// while checking byte orders by debug prints.

// [from + to + nonce + checksum + varint length of encrypted content  + encrypted]
pub fn serialize_encrypted_memo(memo: &EncryptedMemo) -> Result<Vec<u8>, HiveMemoError> {
    let mut buffer = BytesMut::new();

    // Serialize 'from' public key (33 bytes compressed)
    let binding = memo.from.to_encoded_point(true);
    let from_public_key_bytes = binding.as_bytes();
    buffer.put_slice(&from_public_key_bytes);

    // Serialize 'to' public key (33 bytes compressed)
    let binding = memo.to.to_encoded_point(true);
    let to_public_key_bytes = binding.as_bytes();
    buffer.put_slice(&to_public_key_bytes);

    // Serialize nonce (u64, little-endian)
    buffer.put_u64_le(memo.nonce);

    // Serialize checksum (u32, big-endian)
    buffer.put_u32(memo.check);

    let encrypted_length_varint = encode_varint32(memo.encrypted.len() as u32);
    buffer.extend_from_slice(&encrypted_length_varint);

    // Serialize the encrypted memo content (Vec<u8>)
    buffer.extend_from_slice(&memo.encrypted);

    Ok(buffer.to_vec())
}



pub fn deserialize_encrypted_memo(data: &[u8]) -> Result<EncryptedMemo, HiveMemoError> {
    let mut cursor = 0;

    if data.len() < 78 {
        return Err(HiveMemoError::DeserializationError(
            "Data too short".into(),
        ));
    }

    let from_key_bytes = &data[cursor..cursor + 33];
    let from_public_key = K256PublicKey::from_sec1_bytes(from_key_bytes).map_err(|e| {
        HiveMemoError::DeserializationError(format!("From PublicKey parsing error: {}", e))
    })?;
    cursor += 33;

    let to_key_bytes = &data[cursor..cursor + 33];
    let to_public_key = K256PublicKey::from_sec1_bytes(to_key_bytes).map_err(|e| {
        HiveMemoError::DeserializationError(format!("To PublicKey parsing error: {}", e))
    })?;
    cursor += 33;

    let nonce_bytes = &data[cursor..cursor + 8];
    let nonce = u64::from_le_bytes(nonce_bytes.try_into().map_err(|e| {
        HiveMemoError::DeserializationError(format!("Nonce parsing error: {}", e))
    })?);
    cursor += 8;

    let check_bytes = &data[cursor..cursor + 4];
    let check = u32::from_le_bytes(check_bytes.try_into().map_err(|e| {
        HiveMemoError::DeserializationError(format!("Checksum parsing error: {}", e))
    })?);
    cursor += 4;

    let (encrypted_length, varint_size) = decode_varint32(&data[cursor..])?;
    cursor += varint_size;

    if data.len() < cursor + (encrypted_length as usize) {
        return Err(HiveMemoError::DeserializationError(
            "Encrypted content length exceeds buffer".into(),
        ));
    }

    let encrypted_memo_bytes = &data[cursor..cursor + (encrypted_length as usize)];

    Ok(EncryptedMemo {
        nonce,
        check,
        encrypted: encrypted_memo_bytes.to_vec(),
        from: from_public_key,
        to: to_public_key,
    })
}
