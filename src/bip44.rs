use crate::bip32::{ChildNumber, DerivationPath};
use crate::error::Error;
use std::fmt;
use std::str::FromStr;

/// Purpose constant as defined in BIP-44
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Purpose(pub u32);

impl Purpose {
    /// BIP-44 purpose (44')
    pub const BIP44: Purpose = Purpose(44);

    /// Create a new purpose
    pub fn new(value: u32) -> Self {
        Purpose(value)
    }

    /// Get the derivation path element
    pub fn child_number(&self) -> ChildNumber {
        ChildNumber::Hardened(self.0)
    }
}

impl fmt::Display for Purpose {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}'", self.0)
    }
}

/// Coin type as defined in BIP-44
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoinType(pub u32);

impl CoinType {
    /// Bitcoin (0')
    pub const BITCOIN: CoinType = CoinType(0);
    /// Bitcoin Testnet (1')
    pub const BITCOIN_TESTNET: CoinType = CoinType(1);
    /// Litecoin (2')
    pub const LITECOIN: CoinType = CoinType(2);
    /// Dogecoin (3')
    pub const DOGECOIN: CoinType = CoinType(3);
    /// Ethereum (60')
    pub const ETHEREUM: CoinType = CoinType(60);

    /// Create a new coin type
    pub fn new(value: u32) -> Self {
        CoinType(value)
    }

    /// Get the derivation path element
    pub fn child_number(&self) -> ChildNumber {
        ChildNumber::Hardened(self.0)
    }
}

impl fmt::Display for CoinType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}'", self.0)
    }
}

/// Account level as defined in BIP-44
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountLevel(pub u32);

impl AccountLevel {
    /// Create a new account level
    pub fn new(value: u32) -> Self {
        AccountLevel(value)
    }

    /// Get the derivation path element
    pub fn child_number(&self) -> ChildNumber {
        ChildNumber::Hardened(self.0)
    }
}

impl fmt::Display for AccountLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}'", self.0)
    }
}

/// Change level as defined in BIP-44
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    /// External chain (0) - addresses for receiving payments
    External,
    /// Internal chain (1) - addresses for change
    Internal,
}

impl Change {
    /// Get the derivation path element
    pub fn child_number(&self) -> ChildNumber {
        match self {
            Change::External => ChildNumber::Normal(0),
            Change::Internal => ChildNumber::Normal(1),
        }
    }
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Change::External => write!(f, "0"),
            Change::Internal => write!(f, "1"),
        }
    }
}

/// Address index as defined in BIP-44
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressIndex(pub u32);

impl AddressIndex {
    /// Create a new address index
    pub fn new(value: u32) -> Self {
        AddressIndex(value)
    }

    /// Get the derivation path element
    pub fn child_number(&self) -> ChildNumber {
        ChildNumber::Normal(self.0)
    }
}

impl fmt::Display for AddressIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// BIP-44 path as defined in the specification:
/// m / purpose' / coin_type' / account' / change / address_index
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip44Path {
    /// Purpose (hardened)
    pub purpose: Purpose,
    /// Coin type (hardened)
    pub coin_type: CoinType,
    /// Account (hardened)
    pub account: AccountLevel,
    /// Change (0 for external, 1 for internal)
    pub change: Change,
    /// Address index
    pub address_index: AddressIndex,
}

impl Bip44Path {
    /// Create a new BIP-44 path
    pub fn new(
        purpose: Purpose,
        coin_type: CoinType,
        account: AccountLevel,
        change: Change,
        address_index: AddressIndex,
    ) -> Self {
        Bip44Path {
            purpose,
            coin_type,
            account,
            change,
            address_index,
        }
    }

    /// Create a standard BIP-44 path (m/44'/coin_type'/account'/change/address_index)
    pub fn standard(
        coin_type: CoinType,
        account: AccountLevel,
        change: Change,
        address_index: AddressIndex,
    ) -> Self {
        Bip44Path {
            purpose: Purpose::BIP44,
            coin_type,
            account,
            change,
            address_index,
        }
    }

    /// Convert to a BIP-32 derivation path
    pub fn to_derivation_path(&self) -> DerivationPath {
        DerivationPath {
            path: vec![
                self.purpose.child_number(),
                self.coin_type.child_number(),
                self.account.child_number(),
                self.change.child_number(),
                self.address_index.child_number(),
            ],
        }
    }
}

impl FromStr for Bip44Path {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Parse as a derivation path first
        let path = DerivationPath::from_str(s)?;

        // Ensure the path has the correct length for BIP-44
        if path.path.len() != 5 {
            return Err(Error::InvalidDerivationPath(
                "BIP-44 path must have 5 components".to_string(),
            ));
        }

        // Extract and validate components
        let purpose = match path.path[0] {
            ChildNumber::Hardened(n) => Purpose(n),
            _ => {
                return Err(Error::InvalidDerivationPath(
                    "Purpose must be hardened".to_string(),
                ))
            }
        };

        let coin_type = match path.path[1] {
            ChildNumber::Hardened(n) => CoinType(n),
            _ => {
                return Err(Error::InvalidDerivationPath(
                    "Coin type must be hardened".to_string(),
                ))
            }
        };

        let account = match path.path[2] {
            ChildNumber::Hardened(n) => AccountLevel(n),
            _ => {
                return Err(Error::InvalidDerivationPath(
                    "Account must be hardened".to_string(),
                ))
            }
        };

        let change = match path.path[3] {
            ChildNumber::Normal(0) => Change::External,
            ChildNumber::Normal(1) => Change::Internal,
            _ => {
                return Err(Error::InvalidDerivationPath(
                    "Change must be normal and 0 or 1".to_string(),
                ))
            }
        };

        let address_index = match path.path[4] {
            ChildNumber::Normal(n) => AddressIndex(n),
            _ => {
                return Err(Error::InvalidDerivationPath(
                    "Address index must be normal".to_string(),
                ))
            }
        };

        Ok(Bip44Path {
            purpose,
            coin_type,
            account,
            change,
            address_index,
        })
    }
}

impl fmt::Display for Bip44Path {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "m/{}/{}/{}/{}/{}",
            self.purpose, self.coin_type, self.account, self.change, self.address_index
        )
    }
}
