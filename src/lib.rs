pub mod encryption;
pub mod keys;
pub mod serialization;
pub mod varint;

pub use encryption::{encrypt_memo, decrypt_memo};
pub use keys::{wif_to_secret_key, public_key_from_string, public_key_to_hive_format};
pub use serialization::{serialize_encrypted_memo, deserialize_encrypted_memo, EncryptedMemo};
// Optional: Define a custom error type for the crate
pub use thiserror::Error;

#[derive(Error, Debug)]
pub enum HiveMemoError {
    #[error("Invalid WIF format: {0}")]
    InvalidWifFormat(String),

    #[error("Invalid public key format: {0}")]
    InvalidPublicKeyFormat(String),

    #[error("Checksum mismatch")]
    ChecksumMismatch,

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Varint decoding error: {0}")]
    VarintDecodingError(String),

    #[error("Unexpected error: {0}")]
    Unexpected(String),
}
