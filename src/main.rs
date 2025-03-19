use bip32hdwallet::bip32::{DerivationPath, ExtendedPrivKey, Network};
use bip32hdwallet::bip39::{Language, Mnemonic, MnemonicType};
use bip32hdwallet::bip44::{AccountLevel, AddressIndex, Bip44Path, Change, CoinType};

fn main() {
    // Example 1: Generate a mnemonic and use it to derive a Bitcoin wallet
    println!("Example 1: Generate new mnemonic and wallet");
    println!("-------------------------------------------");

    // Generate a new random mnemonic
    let mnemonic = Mnemonic::generate(MnemonicType::Words12, Language::English)
        .expect("Failed to generate mnemonic");

    println!("Mnemonic: {}", mnemonic);

    // Generate a seed from the mnemonic
    let seed = mnemonic.to_seed("");

    // Create a master key from the seed (for Bitcoin mainnet)
    let master_key = ExtendedPrivKey::new_master(seed.as_bytes(), Network::Bitcoin)
        .expect("Failed to create master key");

    // Create a BIP-44 path for the first account, first external address
    let path = Bip44Path::standard(
        CoinType::BITCOIN,
        AccountLevel::new(0),
        Change::External,
        AddressIndex::new(0),
    );

    // Derive the child key
    let child_key = master_key
        .derive_path(&path.to_derivation_path())
        .expect("Failed to derive child key");

    // Get the extended public key
    let xpub = child_key.to_extended_public_key();

    println!("Extended Private Key: {}", child_key.to_string());
    println!("Extended Public Key: {}", xpub.to_string());
    println!("Derivation Path: {}", path);

    // Example 2: Import a mnemonic and use a custom derivation path
    println!("\nExample 2: Import mnemonic and use custom path");
    println!("-------------------------------------------");

    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic =
        Mnemonic::from_phrase(phrase, Language::English).expect("Failed to import mnemonic");

    println!("Mnemonic: {}", mnemonic);

    let seed = mnemonic.to_seed("passphrase");

    let master_key = ExtendedPrivKey::new_master(seed.as_bytes(), Network::Bitcoin)
        .expect("Failed to create master key");

    // Custom derivation path (m/49'/0'/0'/0/0 for SegWit)
    let path = DerivationPath::from_str("m/49'/0'/0'/0/0").expect("Failed to parse path");

    let child_key = master_key
        .derive_path(&path)
        .expect("Failed to derive child key");

    let xpub = child_key.to_extended_public_key();

    println!("Extended Private Key: {}", child_key.to_string());
    println!("Extended Public Key: {}", xpub.to_string());
    println!("Derivation Path: {}", path);
}
