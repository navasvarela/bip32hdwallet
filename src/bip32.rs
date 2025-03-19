use crate::error::Error;
use crate::utils;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fmt;
use std::str::FromStr;

/// The network type for HD keys
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Bitcoin,
    Testnet,
}

impl Network {
    /// Get the version bytes for extended private keys
    pub fn xprv_version(&self) -> [u8; 4] {
        match self {
            Network::Bitcoin => [0x04, 0x88, 0xAD, 0xE4], // xprv
            Network::Testnet => [0x04, 0x35, 0x83, 0x94], // tprv
        }
    }

    /// Get the version bytes for extended public keys
    pub fn xpub_version(&self) -> [u8; 4] {
        match self {
            Network::Bitcoin => [0x04, 0x88, 0xB2, 0x1E], // xpub
            Network::Testnet => [0x04, 0x35, 0x87, 0xCF], // tpub
        }
    }
}

/// A path element in a derivation path
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildNumber {
    /// Normal derivation index (0..2^31-1)
    Normal(u32),
    /// Hardened derivation index (2^31..2^32-1)
    Hardened(u32),
}

impl ChildNumber {
    /// Maximum normal index
    pub const MAX_NORMAL_INDEX: u32 = 0x7fffffff;

    /// Convert to raw index value
    pub fn to_u32(&self) -> u32 {
        match self {
            ChildNumber::Normal(i) => *i,
            ChildNumber::Hardened(i) => i + ChildNumber::MAX_NORMAL_INDEX + 1,
        }
    }

    /// Check if the child number is hardened
    pub fn is_hardened(&self) -> bool {
        match self {
            ChildNumber::Normal(_) => false,
            ChildNumber::Hardened(_) => true,
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ChildNumber::Normal(i) => write!(f, "{}", i),
            ChildNumber::Hardened(i) => write!(f, "{}'", i),
        }
    }
}

impl FromStr for ChildNumber {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.ends_with('\'') || s.ends_with('h') {
            let index: u32 = s[..s.len() - 1]
                .parse()
                .map_err(|_| Error::InvalidDerivationPath("Invalid hardened index".to_string()))?;

            if index > ChildNumber::MAX_NORMAL_INDEX {
                return Err(Error::InvalidDerivationPath(
                    "Hardened index out of range".to_string(),
                ));
            }

            Ok(ChildNumber::Hardened(index))
        } else {
            let index: u32 = s
                .parse()
                .map_err(|_| Error::InvalidDerivationPath("Invalid normal index".to_string()))?;

            if index > ChildNumber::MAX_NORMAL_INDEX {
                return Err(Error::InvalidDerivationPath(
                    "Normal index out of range".to_string(),
                ));
            }

            Ok(ChildNumber::Normal(index))
        }
    }
}

/// A BIP-32 derivation path
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivationPath {
    pub path: Vec<ChildNumber>,
}

impl DerivationPath {
    /// Create a new derivation path from a string (e.g., "m/44'/0'/0'/0/0")
    pub fn from_str(path: &str) -> Result<Self, Error> {
        if !path.starts_with('m') {
            return Err(Error::InvalidDerivationPath(
                "Path must start with 'm'".to_string(),
            ));
        }

        // Skip "m" and possibly "/"
        let path_str = if path.starts_with("m/") {
            &path[2..]
        } else if path == "m" {
            return Ok(DerivationPath { path: vec![] });
        } else {
            return Err(Error::InvalidDerivationPath(
                "Invalid path format".to_string(),
            ));
        };

        let path: Result<Vec<ChildNumber>, Error> = path_str
            .split('/')
            .filter(|p| !p.is_empty())
            .map(|p| p.parse::<ChildNumber>())
            .collect();

        Ok(DerivationPath { path: path? })
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "m")?;
        for child in &self.path {
            write!(f, "/{}", child)?;
        }
        Ok(())
    }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        DerivationPath::from_str(s)
    }
}

/// Extended private key as defined in BIP-32
#[derive(Debug, Clone)]
pub struct ExtendedPrivKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub private_key: SecretKey,
    pub network: Network,
}

impl ExtendedPrivKey {
    /// Create a new master extended private key from a seed
    pub fn new_master(seed: &[u8], network: Network) -> Result<Self, Error> {
        if seed.len() < 16 {
            return Err(Error::InvalidSeed(
                "Seed must be at least 16 bytes".to_string(),
            ));
        }

        let hmac_result = utils::hmac_sha512("Bitcoin seed".as_bytes(), seed);

        let mut secret_key = [0u8; 32];
        let mut chain_code = [0u8; 32];

        secret_key.copy_from_slice(&hmac_result[0..32]);
        chain_code.copy_from_slice(&hmac_result[32..64]);

        let sk = SecretKey::from_slice(&secret_key)
            .map_err(|_| Error::InvalidKey("Invalid master key from seed".to_string()))?;

        Ok(ExtendedPrivKey {
            depth: 0,
            parent_fingerprint: [0, 0, 0, 0],
            child_number: 0,
            chain_code,
            private_key: sk,
            network,
        })
    }

    /// Derive a child key (CKDpriv)
    pub fn derive_child(&self, child_number: ChildNumber) -> Result<ExtendedPrivKey, Error> {
        let secp = Secp256k1::new();
        let mut hmac_input = Vec::with_capacity(37);

        if child_number.is_hardened() {
            // Hardened derivation: data = 0x00 || private_key || child_number
            hmac_input.push(0);
            hmac_input.extend_from_slice(&self.private_key[..]);
        } else {
            // Normal derivation: data = public_key || child_number
            let public_key = PublicKey::from_secret_key(&secp, &self.private_key);
            hmac_input.extend_from_slice(&public_key.serialize());
        }

        // Append child number in big-endian format
        let index = child_number.to_u32();
        hmac_input.extend_from_slice(&index.to_be_bytes());

        // Calculate I = HMAC-SHA512(chain_code, hmac_input)
        let hmac_result = utils::hmac_sha512(&self.chain_code, &hmac_input);

        // Split I into I_L and I_R (left 32 bytes, right 32 bytes)
        let mut i_l = [0u8; 32];
        let mut i_r = [0u8; 32];
        i_l.copy_from_slice(&hmac_result[0..32]);
        i_r.copy_from_slice(&hmac_result[32..64]);

        // Calculate child key = (parent_key + I_L) mod n
        let mut child_private_key = SecretKey::from_slice(&i_l)
            .map_err(|_| Error::InvalidKey("Invalid HMAC-SHA512 left half".to_string()))?;

        child_private_key = child_private_key
            .add_tweak(&self.private_key.into())
            .map_err(|_| Error::InvalidKey("Invalid child private key".to_string()))?;

        // Calculate fingerprint of parent key
        let parent_public_key = PublicKey::from_secret_key(&secp, &self.private_key);
        let parent_pubkey_hash = utils::sha256(&parent_public_key.serialize());
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&parent_pubkey_hash[0..4]);

        Ok(ExtendedPrivKey {
            depth: self.depth + 1,
            parent_fingerprint: fingerprint,
            child_number: index,
            chain_code: i_r,
            private_key: child_private_key,
            network: self.network,
        })
    }

    /// Derive a child key from a derivation path
    pub fn derive_path(&self, path: &DerivationPath) -> Result<ExtendedPrivKey, Error> {
        let mut key = self.clone();

        for &child_number in &path.path {
            key = key.derive_child(child_number)?;
        }

        Ok(key)
    }

    /// Get the corresponding extended public key
    pub fn to_extended_public_key(&self) -> ExtendedPubKey {
        let secp = Secp256k1::new();
        let public_key = PublicKey::from_secret_key(&secp, &self.private_key);

        ExtendedPubKey {
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            chain_code: self.chain_code,
            public_key,
            network: self.network,
        }
    }

    /// Serialize the extended private key to base58 format
    pub fn to_string(&self) -> String {
        let mut data = Vec::with_capacity(78);

        // Version bytes
        data.extend_from_slice(&self.network.xprv_version());

        // Depth
        data.push(self.depth);

        // Parent fingerprint
        data.extend_from_slice(&self.parent_fingerprint);

        // Child number
        data.extend_from_slice(&self.child_number.to_be_bytes());

        // Chain code
        data.extend_from_slice(&self.chain_code);

        // Private key with 0x00 prefix
        data.push(0);
        data.extend_from_slice(&self.private_key[..]);

        utils::base58check_encode(&data)
    }

    /// Parse an extended private key from a base58 string
    pub fn from_string(xprv: &str) -> Result<Self, Error> {
        let data = utils::base58check_decode(xprv)?;

        if data.len() != 78 {
            return Err(Error::InvalidExtendedKey(
                "Invalid extended key length".to_string(),
            ));
        }

        // Extract version bytes
        let mut version = [0u8; 4];
        version.copy_from_slice(&data[0..4]);

        // Determine network
        let network = if version == Network::Bitcoin.xprv_version() {
            Network::Bitcoin
        } else if version == Network::Testnet.xprv_version() {
            Network::Testnet
        } else {
            return Err(Error::InvalidExtendedKey(
                "Invalid version bytes".to_string(),
            ));
        };

        // Extract other fields
        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let mut child_number_bytes = [0u8; 4];
        child_number_bytes.copy_from_slice(&data[9..13]);
        let child_number = u32::from_be_bytes(child_number_bytes);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        // Validate private key prefix
        if data[45] != 0 {
            return Err(Error::InvalidExtendedKey(
                "Invalid private key prefix".to_string(),
            ));
        }

        let mut private_key_bytes = [0u8; 32];
        private_key_bytes.copy_from_slice(&data[46..78]);
        let private_key = SecretKey::from_slice(&private_key_bytes)
            .map_err(|_| Error::InvalidKey("Invalid private key".to_string()))?;

        Ok(ExtendedPrivKey {
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            private_key,
            network,
        })
    }
}

/// Extended public key as defined in BIP-32
#[derive(Debug, Clone)]
pub struct ExtendedPubKey {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    pub chain_code: [u8; 32],
    pub public_key: PublicKey,
    pub network: Network,
}

impl ExtendedPubKey {
    /// Derive a child key (CKDpub) - only for non-hardened derivation
    pub fn derive_child(&self, child_number: ChildNumber) -> Result<ExtendedPubKey, Error> {
        if child_number.is_hardened() {
            return Err(Error::HardenedDerivationRequiresPrivateKey);
        }

        let secp = Secp256k1::new();
        let mut hmac_input = Vec::with_capacity(37);

        // Data = public_key || child_number
        hmac_input.extend_from_slice(&self.public_key.serialize());

        // Append child number in big-endian format
        let index = child_number.to_u32();
        hmac_input.extend_from_slice(&index.to_be_bytes());

        // Calculate I = HMAC-SHA512(chain_code, hmac_input)
        let hmac_result = utils::hmac_sha512(&self.chain_code, &hmac_input);

        // Split I into I_L and I_R (left 32 bytes, right 32 bytes)
        let mut i_l = [0u8; 32];
        let mut i_r = [0u8; 32];
        i_l.copy_from_slice(&hmac_result[0..32]);
        i_r.copy_from_slice(&hmac_result[32..64]);

        // Calculate child key = point(I_L) + parent_key
        let hash = SecretKey::from_slice(&i_l)
            .map_err(|_| Error::InvalidKey("Invalid HMAC-SHA512 left half".to_string()))?;

        let point = PublicKey::from_secret_key(&secp, &hash);

        let child_public_key = self
            .public_key
            .combine(&point)
            .map_err(|_| Error::InvalidKey("Invalid child public key".to_string()))?;

        // Calculate fingerprint of parent key
        let parent_pubkey_hash = utils::sha256(&self.public_key.serialize());
        let mut fingerprint = [0u8; 4];
        fingerprint.copy_from_slice(&parent_pubkey_hash[0..4]);

        Ok(ExtendedPubKey {
            depth: self.depth + 1,
            parent_fingerprint: fingerprint,
            child_number: index,
            chain_code: i_r,
            public_key: child_public_key,
            network: self.network,
        })
    }

    /// Derive a child key from a derivation path (only non-hardened)
    pub fn derive_path(&self, path: &DerivationPath) -> Result<ExtendedPubKey, Error> {
        let mut key = self.clone();

        for &child_number in &path.path {
            if child_number.is_hardened() {
                return Err(Error::HardenedDerivationRequiresPrivateKey);
            }
            key = key.derive_child(child_number)?;
        }

        Ok(key)
    }

    /// Serialize the extended public key to base58 format
    pub fn to_string(&self) -> String {
        let mut data = Vec::with_capacity(78);

        // Version bytes
        data.extend_from_slice(&self.network.xpub_version());

        // Depth
        data.push(self.depth);

        // Parent fingerprint
        data.extend_from_slice(&self.parent_fingerprint);

        // Child number
        data.extend_from_slice(&self.child_number.to_be_bytes());

        // Chain code
        data.extend_from_slice(&self.chain_code);

        // Public key
        data.extend_from_slice(&self.public_key.serialize());

        utils::base58check_encode(&data)
    }

    /// Parse an extended public key from a base58 string
    pub fn from_string(xpub: &str) -> Result<Self, Error> {
        let data = utils::base58check_decode(xpub)?;

        if data.len() != 78 {
            return Err(Error::InvalidExtendedKey(
                "Invalid extended key length".to_string(),
            ));
        }

        // Extract version bytes
        let mut version = [0u8; 4];
        version.copy_from_slice(&data[0..4]);

        // Determine network
        let network = if version == Network::Bitcoin.xpub_version() {
            Network::Bitcoin
        } else if version == Network::Testnet.xpub_version() {
            Network::Testnet
        } else {
            return Err(Error::InvalidExtendedKey(
                "Invalid version bytes".to_string(),
            ));
        };

        // Extract other fields
        let depth = data[4];

        let mut parent_fingerprint = [0u8; 4];
        parent_fingerprint.copy_from_slice(&data[5..9]);

        let mut child_number_bytes = [0u8; 4];
        child_number_bytes.copy_from_slice(&data[9..13]);
        let child_number = u32::from_be_bytes(child_number_bytes);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let mut public_key_bytes = [0u8; 33];
        public_key_bytes.copy_from_slice(&data[45..78]);
        let public_key = PublicKey::from_slice(&public_key_bytes)
            .map_err(|_| Error::InvalidKey("Invalid public key".to_string()))?;

        Ok(ExtendedPubKey {
            depth,
            parent_fingerprint,
            child_number,
            chain_code,
            public_key,
            network,
        })
    }
}
