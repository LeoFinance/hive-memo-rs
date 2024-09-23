use crate::{
    keys::{compute_shared_secret},
    serialization::{serialize_encrypted_memo, deserialize_encrypted_memo, EncryptedMemo},
    HiveMemoError,
};
use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use k256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256, Sha512};

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub fn encrypt_memo(
    sender_private_key: &SecretKey,
    receiver_public_key: &PublicKey,
    memo: &str,
) -> Result<String, HiveMemoError> {
    use rand::Rng;

    if !memo.starts_with('#') {
        return Ok(memo.to_string());
    }
    let memo_content = memo.trim_start_matches('#').trim();

    // Generate a random nonce
    let nonce = rand::thread_rng().gen::<u64>();

    // Compute the shared secret bytes (32 bytes: x-coordinate)
    let shared_secret_bytes = compute_shared_secret(receiver_public_key, sender_private_key).expect("Can't compute shared secret");

    // Prepare shared secret preimage (nonce in little-endian + shared_secret_bytes)
    let mut ebuf = Vec::new();
    ebuf.extend_from_slice(&nonce.to_le_bytes());
    ebuf.extend_from_slice(&shared_secret_bytes);

    // Derive the encryption key using SHA-512
    let encryption_key = Sha512::digest(&ebuf);

    // Derive IV and tag from the encryption key
    let iv = &encryption_key[32..48]; // IV (16 bytes)
    let tag = &encryption_key[0..32]; // Tag (32 bytes)

    // Compute the checksum: first 4 bytes of SHA256 of the encryption key
    let checksum_hash = Sha256::digest(&encryption_key);
    let checksum_bytes = &checksum_hash[0..4];
    let checksum = u32::from_be_bytes(checksum_bytes.try_into().map_err(|e| {
        HiveMemoError::EncryptionError(format!("Checksum bytes error: {}", e))
    })?);

    // Memo content as bytes
    let memo_bytes = memo_content.as_bytes();

    // Encrypt memo
    let cipher = Aes256Cbc::new_from_slices(tag, iv).map_err(|e| {
        HiveMemoError::EncryptionError(format!("Cipher creation error: {}", e))
    })?;
    let encrypted_memo = cipher.encrypt_vec(memo_bytes);

    // Prepare encrypted memo structure
    let sender_public_key = sender_private_key.public_key();
    let encrypted_memo_struct = EncryptedMemo {
        nonce,
        check: checksum,
        encrypted: encrypted_memo,
        from: sender_public_key,
        to: receiver_public_key.clone(),
    };

    // Serialize encrypted memo
    let serialized_memo = serialize_encrypted_memo(&encrypted_memo_struct)?;

    // Base58 encode
    let base58_encoded = bs58::encode(&serialized_memo).into_string();
    let result = format!("#{}", base58_encoded);
    Ok(result)
}

pub fn decrypt_memo(
    receiver_private_key: &SecretKey,
    memo: &str,
) -> Result<String, HiveMemoError> {
    // Check if memo starts with '#'
    if !memo.starts_with('#') {
        return Ok(memo.to_string());
    }

    let data = memo.trim_start_matches('#');

    // Base58 decode
    let decoded = bs58::decode(data).into_vec().map_err(|e| {
        HiveMemoError::DecryptionError(format!("Base58 decode error: {}", e))
    })?;
    let encrypted_memo_struct = deserialize_encrypted_memo(&decoded)?;

    // Compute the shared secret bytes using ECDH
    let shared_secret_bytes = compute_shared_secret(&encrypted_memo_struct.from, receiver_private_key).expect("Can't compute shared secret.");

    // Prepare shared secret preimage: nonce (little-endian) + shared_secret_bytes
    let mut shared_secret_preimage = Vec::new();
    shared_secret_preimage.extend_from_slice(&encrypted_memo_struct.nonce.to_le_bytes());
    shared_secret_preimage.extend_from_slice(&shared_secret_bytes);

    // Compute shared secret hash using SHA-512
    let shared_secret_hash = Sha512::digest(&shared_secret_preimage);

    // Derive decryption key and IV
    let decryption_key = &shared_secret_hash[0..32];
    let iv = &shared_secret_hash[32..48];



    // Decrypt the memo using AES-256-CBC
    let cipher = Aes256Cbc::new_from_slices(decryption_key, iv).map_err(|e| {
        HiveMemoError::DecryptionError(format!("Cipher creation error: {}", e))
    })?;
    let decrypted_memo_bytes = cipher.decrypt_vec(&encrypted_memo_struct.encrypted).map_err(|e| {
        HiveMemoError::DecryptionError(format!("Decryption failed: {}", e))
    })?;

    // Convert decrypted bytes to UTF-8 string
    let memo_content = String::from_utf8(decrypted_memo_bytes).map_err(|e| {
        HiveMemoError::DecryptionError(format!("UTF-8 conversion error: {}", e))
    })?;

    Ok(memo_content)
}
