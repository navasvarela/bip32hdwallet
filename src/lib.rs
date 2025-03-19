// BIP-32 HD Wallet implementation
// This library implements the BIP-32, BIP-39, and BIP-44 specifications for
// hierarchical deterministic wallets.

pub mod bip32;
pub mod bip39;
pub mod bip44;
pub mod error;
pub mod utils;

pub use bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
pub use bip39::{Language, Mnemonic, MnemonicType, Seed};
pub use bip44::{AccountLevel, AddressIndex, CoinType, Purpose};
pub use error::Error;

// Re-export types from dependencies that are part of our public API
pub use secp256k1::{self, PublicKey, Secp256k1, SecretKey};

#[cfg(test)]
mod tests {
    use super::*;
    use bip32::{ChildNumber, Network};
    use bip44::{Bip44Path, Change};
    use std::str::FromStr;

    #[test]
    fn test_mnemonic_generation() {
        let mnemonic = Mnemonic::generate(MnemonicType::Words12, Language::English).unwrap();
        assert_eq!(mnemonic.phrase().split_whitespace().count(), 12);
    }

    #[test]
    fn test_mnemonic_validation() {
        let valid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(valid_phrase, Language::English).unwrap();
        assert_eq!(mnemonic.phrase(), valid_phrase);

        let invalid_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon invalid";
        let result = Mnemonic::from_phrase(invalid_phrase, Language::English);
        assert!(result.is_err());
    }

    #[test]
    fn test_seed_generation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();

        // Known good seed from the BIP-39 spec
        let expected_seed_hex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
        let expected_seed = hex::decode(expected_seed_hex).unwrap();

        let seed = mnemonic.to_seed("TREZOR");
        assert_eq!(seed.as_bytes(), expected_seed.as_slice());
    }

    #[test]
    fn test_key_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = mnemonic.to_seed("");

        let master_key = ExtendedPrivKey::new_master(seed.as_bytes(), Network::Bitcoin).unwrap();

        // Derive a child key (m/44'/0'/0'/0/0)
        let path = Bip44Path::standard(
            CoinType::BITCOIN,
            AccountLevel::new(0),
            Change::External,
            AddressIndex::new(0),
        );

        let child_key = master_key.derive_path(&path.to_derivation_path()).unwrap();
        assert_eq!(child_key.depth, 5);
    }

    #[test]
    fn test_hardened_derivation() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = mnemonic.to_seed("");

        let master_key = ExtendedPrivKey::new_master(seed.as_bytes(), Network::Bitcoin).unwrap();

        // Derive a hardened child key (m/0')
        let child_key = master_key.derive_child(ChildNumber::Hardened(0)).unwrap();
        assert_eq!(child_key.depth, 1);

        // Check if it's a hardened index (should be >= 2^31)
        assert!(child_key.child_number >= 0x80000000);
    }

    #[test]
    fn test_derivation_path_parsing() {
        let path_str = "m/44'/0'/0'/0/0";
        let path = DerivationPath::from_str(path_str).unwrap();

        assert_eq!(path.path.len(), 5);
        assert_eq!(path.path[0], ChildNumber::Hardened(44));
        assert_eq!(path.path[1], ChildNumber::Hardened(0));
        assert_eq!(path.path[2], ChildNumber::Hardened(0));
        assert_eq!(path.path[3], ChildNumber::Normal(0));
        assert_eq!(path.path[4], ChildNumber::Normal(0));

        assert_eq!(path.to_string(), path_str);
    }

    #[test]
    fn test_bip44_path() {
        let path_str = "m/44'/0'/0'/0/0";

        let bip44_path = Bip44Path::from_str(path_str).unwrap();
        assert_eq!(bip44_path.purpose, Purpose::BIP44);
        assert_eq!(bip44_path.coin_type, CoinType::BITCOIN);
        assert_eq!(bip44_path.account, AccountLevel::new(0));
        assert_eq!(bip44_path.change, Change::External);
        assert_eq!(bip44_path.address_index, AddressIndex::new(0));

        assert_eq!(bip44_path.to_string(), path_str);
    }

    #[test]
    fn test_key_serialization() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = mnemonic.to_seed("");

        let master_key = ExtendedPrivKey::new_master(seed.as_bytes(), Network::Bitcoin).unwrap();

        let xprv = master_key.to_string();
        let parsed_key = ExtendedPrivKey::from_string(&xprv).unwrap();

        assert_eq!(parsed_key.depth, master_key.depth);
        assert_eq!(parsed_key.child_number, master_key.child_number);
        assert_eq!(parsed_key.chain_code, master_key.chain_code);

        let xpub = master_key.to_extended_public_key().to_string();
        let parsed_pub = ExtendedPubKey::from_string(&xpub).unwrap();

        assert_eq!(parsed_pub.depth, master_key.depth);
        assert_eq!(parsed_pub.child_number, master_key.child_number);
        assert_eq!(parsed_pub.chain_code, master_key.chain_code);
    }
}
