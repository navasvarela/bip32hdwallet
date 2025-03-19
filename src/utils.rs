use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub type HmacSha512 = Hmac<Sha512>;

/// Compute HMAC-SHA512
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut hash = [0u8; 64];
    hash.copy_from_slice(&result[..]);
    hash
}

/// Compute SHA256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Double SHA256 hash
pub fn hash_twice(data: &[u8]) -> [u8; 32] {
    let first = sha256(data);
    sha256(&first)
}

/// Calculate checksum (first 4 bytes of double-SHA256 hash)
pub fn checksum(data: &[u8]) -> [u8; 4] {
    let hash = hash_twice(data);
    let mut checksum = [0u8; 4];
    checksum.copy_from_slice(&hash[0..4]);
    checksum
}

/// Encode a base58 string with a checksum
pub fn base58check_encode(data: &[u8]) -> String {
    let mut check_data = Vec::with_capacity(data.len() + 4);
    check_data.extend_from_slice(data);
    check_data.extend_from_slice(&checksum(data));
    bs58::encode(check_data).into_string()
}

/// Decode a base58 string and verify its checksum
pub fn base58check_decode(data: &str) -> Result<Vec<u8>, crate::error::Error> {
    let decoded = bs58::decode(data)
        .into_vec()
        .map_err(|_| crate::error::Error::Base58DecodeError("Invalid base58 string".to_string()))?;

    if decoded.len() < 4 {
        return Err(crate::error::Error::InvalidChecksum);
    }

    let checksum_index = decoded.len() - 4;
    let data_part = &decoded[0..checksum_index];
    let checksum_part = &decoded[checksum_index..];

    let calculated_checksum = checksum(data_part);
    if checksum_part != &calculated_checksum[..] {
        return Err(crate::error::Error::InvalidChecksum);
    }

    Ok(data_part.to_vec())
}
