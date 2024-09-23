use std::error::Error;

use crate::HiveMemoError;
use k256::elliptic_curve::{Group, AffineXCoordinate};
use k256::{
    PublicKey, SecretKey
};
use k256::elliptic_curve::sec1::{ToEncodedPoint};
use ripemd::{Digest as RipemdDigest, Ripemd160};
use sha2::{Sha256, Sha512};

pub fn wif_to_secret_key(wif: &str) -> Result<SecretKey, HiveMemoError> {
    let data = bs58::decode(wif).into_vec().map_err(|e| {
        HiveMemoError::InvalidWifFormat(format!("Base58 decode error: {}", e))
    })?;

    match data.len() {
        37 => {
            // Uncompressed key format (prefix + key + checksum)
            let prefix = data[0];
            let key_bytes = &data[1..33];
            let checksum = &data[33..];

            if prefix != 0x80 {
                return Err(HiveMemoError::InvalidWifFormat(
                    "Incorrect prefix".into(),
                ));
            }

            let checksum_data = &data[0..33];
            let checksum_calculated = &Sha256::digest(&Sha256::digest(checksum_data))[..4];

            if checksum_calculated != checksum {
                return Err(HiveMemoError::ChecksumMismatch);
            }

            let secret_key = SecretKey::from_be_bytes(key_bytes).map_err(|e| {
                HiveMemoError::InvalidWifFormat(format!("SecretKey parsing error: {}", e))
            })?;
            Ok(secret_key)
        }
        38 => {
            // Compressed key format (prefix + key + suffix + checksum)
            let prefix = data[0];
            let key_bytes = &data[1..33];
            let suffix = data[33];
            let checksum = &data[34..];

            if prefix != 0x80 {
                return Err(HiveMemoError::InvalidWifFormat(
                    "Incorrect prefix".into(),
                ));
            }
            if suffix != 0x01 {
                return Err(HiveMemoError::InvalidWifFormat(
                    "Incorrect suffix".into(),
                ));
            }

            let checksum_data = &data[0..34];
            let checksum_calculated = &Sha256::digest(&Sha256::digest(checksum_data))[..4];

            if checksum_calculated != checksum {
                return Err(HiveMemoError::ChecksumMismatch);
            }

            let secret_key = SecretKey::from_be_bytes(key_bytes).map_err(|e| {
                HiveMemoError::InvalidWifFormat(format!("SecretKey parsing error: {}", e))
            })?;
            Ok(secret_key)
        }
        _ => Err(HiveMemoError::InvalidWifFormat(
            "Incorrect length".into(),
        )),
    }
}

pub fn public_key_from_string(key_str: &str) -> Result<PublicKey, HiveMemoError> {
    if !key_str.starts_with("STM") {
        return Err(HiveMemoError::InvalidPublicKeyFormat(
            "Does not start with 'STM'".into(),
        ));
    }
    let decoded = bs58::decode(&key_str[3..]).into_vec().map_err(|e| {
        HiveMemoError::InvalidPublicKeyFormat(format!("Base58 decode error: {}", e))
    })?;
    if decoded.len() != 37 {
        return Err(HiveMemoError::InvalidPublicKeyFormat(
            "Incorrect length".into(),
        ));
    }
    let key_bytes = &decoded[..33];
    let checksum = &decoded[33..];

    // Verify checksum
    let mut hasher = Ripemd160::new();
    hasher.update(&key_bytes);
    let result = hasher.finalize();
    let calculated_checksum = &result[..4];
    if calculated_checksum != checksum {
        return Err(HiveMemoError::ChecksumMismatch);
    }

    let public_key =
        PublicKey::from_sec1_bytes(key_bytes).map_err(|e| {
            HiveMemoError::InvalidPublicKeyFormat(format!("PublicKey parsing error: {}", e))
        })?;
    Ok(public_key)
}

pub fn public_key_to_hive_format(public_key: &PublicKey) -> String {
    // Get the compressed public key bytes (33 bytes)
    let binding = public_key.to_encoded_point(true);
    let public_key_bytes = binding.as_bytes();

    // Compute the RIPEMD-160 hash of the public key bytes
    let mut hasher = Ripemd160::new();
    hasher.update(&public_key_bytes);
    let result = hasher.finalize();

    // Extract the first 4 bytes as the checksum
    let checksum = &result[..4];

    // Concatenate the public key bytes and the checksum
    let mut key_with_checksum = Vec::new();
    key_with_checksum.extend_from_slice(&public_key_bytes);
    key_with_checksum.extend_from_slice(checksum);

    // Base58-encode the concatenated data
    let base58_encoded = bs58::encode(&key_with_checksum).into_string();

    // Remove the 'STM' prefix
    let hive_public_key = format!("STM{}", base58_encoded);
    hive_public_key
}

pub fn compute_shared_secret(
    public_key: &PublicKey,
    private_key: &SecretKey,
) -> Result<Vec<u8>, Box<dyn Error>> {
    use k256::{
        elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
        AffinePoint,
    };

    // Convert SecretKey to Scalar
    let nonzero_scalar = private_key
        .to_nonzero_scalar();
    let scalar = nonzero_scalar.as_ref();

    // Convert public key to AffinePoint (uncompressed)
    let public_point = AffinePoint::from_encoded_point(&public_key.to_encoded_point(false)).unwrap();
    // Perform scalar multiplication: shared_point = scalar * public_point
    let shared_point = public_point * scalar;

    // Ensure the shared point is not at infinity
    if shared_point.is_identity().into() {
        return Err("Shared secret point is at infinity".into());
    }

    // Get the x-coordinate of the shared point
    let x = shared_point.to_affine().x();

    // Serialize x-coordinate to 32-byte big-endian array
    let x_bytes = x.as_slice();

    let shared_secret_hash = Sha512::digest(&x_bytes);


    // The JavaScript code applies SHA-512 directly to the x-coordinate
    Ok(shared_secret_hash.to_vec())
}
