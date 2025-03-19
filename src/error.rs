use thiserror::Error;

/// Error types for the HD wallet implementation
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid seed: {0}")]
    InvalidSeed(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),

    #[error("Invalid extended key: {0}")]
    InvalidExtendedKey(String),

    #[error("Invalid checksum")]
    InvalidChecksum,

    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Invalid entropy: {0}")]
    InvalidEntropy(String),

    #[error("Secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),

    #[error("HMAC error")]
    HmacError,

    #[error("Base58 decoding error: {0}")]
    Base58DecodeError(String),

    #[error("Hardened derivation requires private key")]
    HardenedDerivationRequiresPrivateKey,

    #[error("Invalid word in mnemonic: {0}")]
    InvalidWord(String),

    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),
}
