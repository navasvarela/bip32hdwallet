# BIP-32 Hierarchical Deterministic Wallet

A Rust implementation of BIP-32, BIP-39, and BIP-44 specifications for hierarchical deterministic wallets.

This implementation was done for learning purposes and it should not be taken as production-ready code. 

## Features

- **BIP-32**: Create and manage hierarchical deterministic wallets

  - Create master keys from seed
  - Derive child keys (hardened and non-hardened)
  - Serialize and deserialize extended keys
  - Support for different networks (Bitcoin, Testnet)

- **BIP-39**: Mnemonic code for generating deterministic keys

  - Generate random mnemonic phrases
  - Import mnemonic phrases
  - Validate mnemonic phrases
  - Generate seeds from mnemonic phrases
  - Support for different languages (English, with more to come)

- **BIP-44**: Multi-account hierarchy
  - Purpose, coin type, account, change, and address index levels
  - Standard path structure
  - Support for different coin types
  - Parsing and validation of BIP-44 paths

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
bip32hdwallet = "0.1.0"
```

## Examples

### Generate a new mnemonic and derive a wallet

```rust
use bip32hdwallet::bip32::{ExtendedPrivKey, Network};
use bip32hdwallet::bip39::{Language, Mnemonic, MnemonicType, Seed};
use bip32hdwallet::bip44::{AccountLevel, AddressIndex, Bip44Path, Change, CoinType};

// Generate a new random mnemonic
let mnemonic = Mnemonic::generate(MnemonicType::Words12, Language::English).unwrap();
println!("Mnemonic: {}", mnemonic);

// Generate a seed from the mnemonic
let seed = mnemonic.to_seed("");

// Create a master key from the seed (for Bitcoin mainnet)
let master_key = ExtendedPrivKey::new_master(seed.as_bytes(), Network::Bitcoin).unwrap();

// Create a BIP-44 path for the first account, first external address
let path = Bip44Path::standard(
    CoinType::BITCOIN,
    AccountLevel::new(0),
    Change::External,
    AddressIndex::new(0),
);

// Derive the child key
let child_key = master_key.derive_path(&path.to_derivation_path()).unwrap();

// Get the extended public key
let xpub = child_key.to_extended_public_key();

println!("Extended Private Key: {}", child_key.to_string());
println!("Extended Public Key: {}", xpub.to_string());
```

### Import a mnemonic and use a custom derivation path

```rust
use bip32hdwallet::bip32::{DerivationPath, ExtendedPrivKey, Network};
use bip32hdwallet::bip39::{Language, Mnemonic, Seed};
use std::str::FromStr;

// Import an existing mnemonic
let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();

// Generate a seed with optional passphrase
let seed = mnemonic.to_seed("passphrase");

// Create a master key from the seed
let master_key = ExtendedPrivKey::new_master(seed.as_bytes(), Network::Bitcoin).unwrap();

// Custom derivation path (e.g., for SegWit)
let path = DerivationPath::from_str("m/49'/0'/0'/0/0").unwrap();

// Derive the child key
let child_key = master_key.derive_path(&path).unwrap();

// Get the extended public key
let xpub = child_key.to_extended_public_key();
```

## Documentation

For detailed documentation, run:

```bash
cargo doc --open
```

## License

This project is licensed under either the [MIT License](LICENSE-MIT) or the [Apache License 2.0](LICENSE-APACHE), at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
