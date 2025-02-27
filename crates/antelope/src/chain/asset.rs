use core::ops;
use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};
use thiserror::Error;
use crate::chain::{name::Name, Decoder, Encoder, Packer};
use crate::chain::name::NameError;

const MAX_AMOUNT: i64 = (1 << 62) - 1;
const MAX_PRECISION: u8 = 18;

/// Check if the given symbol code is valid.
pub fn is_valid_symbol_code(sym: u64) -> bool {
    let mut i: i32 = 0;
    let mut tmp = sym;
    if (sym >> 56) != 0 {
        return false;
    }

    for j in 0..7 {
        let c = (tmp & 0xFF) as u8;
        if !c.is_ascii_uppercase() {
            return false;
        }

        tmp >>= 8;
        if (tmp & 0xFF) == 0 {
            break;
        }
        i = j;
    }
    i += 1;

    for _ in i..7 {
        tmp >>= 8;
        if (tmp & 0xFF) != 0 {
            return false;
        }
    }
    true
}

#[derive(Debug, Error)]
pub enum SymbolCodeError {
    #[error("SymbolCode.from_string: bad symbol name")]
    BadSymbolName,

    #[error("SymbolCode.from_string: invalid symbol code character")]
    InvalidSymbolCharacter,
}

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolCode {
    pub value: u64,
}

impl SymbolCode {
    pub fn new(sym: &str) -> Self {
        let raw = sym.as_bytes();
        assert!(raw.len() < 7 && !raw.is_empty(), "bad symbol name");

        let mut value: u64 = 0;
        for i in (0..raw.len()).rev() {
            let c = raw[i];
            assert!(c.is_ascii_uppercase(), "invalid symbol code character");
            value <<= 8;
            value |= c as u64;
        }
        Self { value }
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn as_string(&self) -> String {
        let mut v: Vec<u8> = Vec::with_capacity(7);
        let mut tmp = self.value;
        for _ in 0..7 {
            let c = (tmp & 0xff) as u8;
            assert!(c.is_ascii_uppercase(), "invalid symbol character");
            v.push(c);
            tmp >>= 8;
            if tmp == 0 {
                break;
            }
        }
        String::from_utf8(v).unwrap()
    }

    pub fn from_string(sym: &str) -> Result<Self, SymbolCodeError> {
        let raw = sym.as_bytes();
        if raw.is_empty() || raw.len() >= 7 {
            return Err(SymbolCodeError::BadSymbolName);
        }

        let mut value: u64 = 0;
        for &c in raw.iter().rev() {
            if !c.is_ascii_uppercase() {
                return Err(SymbolCodeError::InvalidSymbolCharacter);
            }
            value = (value << 8) | c as u64;
        }

        Ok(Self { value })
    }

    pub fn is_valid(&self) -> bool {
        is_valid_symbol_code(self.value)
    }
}

impl Display for SymbolCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl Packer for SymbolCode {
    fn size(&self) -> usize {
        8
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        self.value.pack(enc)
    }

    fn unpack(&mut self, data: &[u8]) -> usize {
        assert!(
            data.len() >= self.size(),
            "SymbolCode.unpack: buffer overflow"
        );
        self.value.unpack(data);
        assert!(self.is_valid(), "SymbolCode.unpack:: bad symbol code");
        8
    }
}

#[derive(Debug, Error)]
pub enum SymbolError {
    #[error("Symbol.from_string: bad symbol name")]
    BadSymbolName,

    #[error("Symbol.from_string: invalid symbol character")]
    InvalidSymbolCharacter,

    #[error("Symbol.from_string: invalid precision")]
    InvalidPrecision,
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Symbol {
    value: u64,
}

impl Symbol {
    pub fn new(name: &str, precision: u8) -> Self {
        let raw = name.as_bytes();
        assert!(raw.len() < 7 && !raw.is_empty(), "bad symbol name");

        let mut value: u64 = 0;
        for i in (0..raw.len()).rev() {
            let c = raw[i];
            assert!(c.is_ascii_uppercase(), "invalid symbol character");
            value <<= 8;
            value |= c as u64;
        }

        value <<= 8;
        value |= precision as u64;
        Self { value }
    }

    pub fn value(&self) -> u64 {
        self.value
    }

    pub fn code(&self) -> SymbolCode {
        SymbolCode {
            value: self.value >> 8,
        }
    }

    pub fn precision(&self) -> usize {
        (self.value & 0xFF) as usize
    }

    pub fn as_string(&self) -> String {
        self.precision().to_string() + "," + &self.code().to_string()
    }

    pub fn is_valid(&self) -> bool {
        self.code().is_valid()
    }

    pub fn from_string(s: &str) -> Result<Self, SymbolError> {
        let parts: Vec<&str> = s.split(',').collect();
        if parts.len() != 2 {
            return Err(SymbolError::BadSymbolName);
        }

        let precision = parts[0].parse::<u8>().map_err(|_| SymbolError::InvalidPrecision)?;
        let code = SymbolCode::from_string(parts[1]).map_err(|_| SymbolError::InvalidSymbolCharacter)?;

        let mut value = code.value() << 8;
        value |= precision as u64;

        Ok(Self { value })
    }
}

impl Display for Symbol {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl Packer for Symbol {
    fn size(&self) -> usize {
        8
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        self.value.pack(enc)
    }

    fn unpack(&mut self, data: &[u8]) -> usize {
        assert!(data.len() >= self.size(), "Symbol.unpack: buffer overflow");
        self.value.unpack(data);
        assert!(self.code().is_valid(), "Symbol.unpack: bad symbol value");
        8
    }
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Asset {
    amount: i64,
    symbol: Symbol,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum AssetStringParseStatus {
    Initial,
    FoundDot,
    FoundSpace,
}

#[derive(Debug, Error)]
pub enum AssetFromStrError {
    #[error("Asset.from_string: empty string")]
    EmptyString,

    #[error("Asset.from_string: invalid dot character")]
    InvalidDot,

    #[error("Asset.from_string: invalid space character")]
    InvalidSpace,

    #[error("Asset.from_string: bad amount")]
    BadAmount,

    #[error("Asset.from_string: bad precision")]
    BadPrecision,

    #[error("Asset.from_string: bad symbol")]
    BadSymbol,

    #[error("Magnitude of asset amount must be less than 2^62")]
    AmountOutOfRange,

    #[error("Invalid symbol name")]
    InvalidSymbol,
}

fn is_amount_within_range(amount: i64) -> bool {
    (-MAX_AMOUNT..=MAX_AMOUNT).contains(&amount)
}

impl Asset {
    pub fn new(amount: i64, symbol: Symbol) -> Self {
        assert!(
            is_amount_within_range(amount),
            "magnitude of asset amount must be less than 2^62"
        );
        assert!(symbol.is_valid(), "invalid symbol name");
        Self { amount, symbol }
    }

    pub fn from_string(s: &str) -> Result<Self, AssetFromStrError> {
        if s.is_empty() {
            return Err(AssetFromStrError::EmptyString);
        }

        let mut status = AssetStringParseStatus::Initial;
        let mut raw = s.as_bytes();

        let mut minus: bool = false;
        let mut amount: i64 = 0;
        let mut symbol: u64 = 0;
        let mut precision: u8 = 0;
        let mut raw_symbol: Vec<u8> = Vec::with_capacity(7);

        if raw[0] == b'-' {
            minus = true;
            raw = &raw[1..];
        }

        for &c in raw {
            if c == b'.' {
                if status != AssetStringParseStatus::Initial {
                    return Err(AssetFromStrError::InvalidDot);
                }
                status = AssetStringParseStatus::FoundDot;
                continue;
            } else if c == b' ' {
                if status != AssetStringParseStatus::Initial
                    && status != AssetStringParseStatus::FoundDot
                {
                    return Err(AssetFromStrError::InvalidSpace);
                }
                status = AssetStringParseStatus::FoundSpace;
                continue;
            }

            match status {
                AssetStringParseStatus::Initial => {
                    if !c.is_ascii_digit() {
                        return Err(AssetFromStrError::BadAmount);
                    }
                    amount = amount
                        .checked_mul(10)
                        .and_then(|a| a.checked_add((c - b'0') as i64))
                        .ok_or(AssetFromStrError::BadAmount)?;

                    if !is_amount_within_range(amount) {
                        return Err(AssetFromStrError::AmountOutOfRange);
                    }
                }
                AssetStringParseStatus::FoundDot => {
                    if !c.is_ascii_digit() {
                        return Err(AssetFromStrError::BadAmount);
                    }
                    amount = amount
                        .checked_mul(10)
                        .and_then(|a| a.checked_add((c - b'0') as i64))
                        .ok_or(AssetFromStrError::BadAmount)?;
                    precision += 1;

                    if precision > MAX_PRECISION {
                        return Err(AssetFromStrError::BadPrecision);
                    }
                    if !is_amount_within_range(amount) {
                        return Err(AssetFromStrError::AmountOutOfRange);
                    }
                }
                AssetStringParseStatus::FoundSpace => {
                    if !c.is_ascii_uppercase() {
                        return Err(AssetFromStrError::BadSymbol);
                    }
                    raw_symbol.push(c);
                    if raw_symbol.len() >= 7 {
                        return Err(AssetFromStrError::BadSymbol);
                    }
                }
            }
        }

        if raw_symbol.is_empty() {
            return Err(AssetFromStrError::BadSymbol);
        }

        if minus {
            amount = -amount;
        }

        raw_symbol.reverse();
        for c in raw_symbol {
            symbol = (symbol << 8) | c as u64;
        }

        symbol = (symbol << 8) | precision as u64;

        let symbol_struct = Symbol { value: symbol };
        if !symbol_struct.is_valid() {
            return Err(AssetFromStrError::InvalidSymbol);
        }

        Ok(Self { amount, symbol: symbol_struct })
    }

    pub fn amount(&self) -> i64 {
        self.amount
    }

    pub fn symbol(&self) -> Symbol {
        self.symbol
    }

    pub fn as_string(self) -> String {
        let mut part1: i64 = self.amount;

        for _ in 0..self.symbol.precision() {
            part1 /= 10;
        }

        let mut part2: Vec<u8> = vec![0u8; self.symbol.precision()];

        let mut tmp: i64 = self.amount;
        for i in (0..self.symbol.precision()).rev() {
            part2[i] = b'0' + (tmp % 10) as u8;
            tmp /= 10;
        }
        let mut decimal = String::from_utf8(part2).unwrap();
        if !decimal.is_empty() {
            decimal = String::from(".") + decimal.as_str();
        }

        part1.to_string() + decimal.as_str() + " " + &self.symbol.code().to_string()
    }

    pub fn is_valid(&self) -> bool {
        is_amount_within_range(self.amount) && self.symbol().is_valid()
    }
}

impl Display for Asset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

// assert!(a.symbol.value == b.symbol.value, "symbol not the same");
// let amount: i64 = a.amount + b.amount;
// assert!(-MAX_AMOUNT <= amount, "addition underflow");
// assert!(amount <= MAX_AMOUNT, "addition overflow");
// return new Asset(amount, Symbol.fromU64(a.symbol.value));

impl ops::Add for Asset {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        assert!(self.symbol == rhs.symbol, "add: bad symbol");
        let amount = self.amount + rhs.amount;
        assert!(amount >= -MAX_AMOUNT, "addition underflow");
        assert!(amount <= MAX_AMOUNT, "addition overflow");
        Self {
            amount,
            symbol: self.symbol,
        }
    }
}

impl ops::AddAssign for Asset {
    fn add_assign(&mut self, rhs: Asset) {
        *self = *self + rhs;
    }
}

impl ops::Sub for Asset {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        assert!(self.symbol == rhs.symbol, "sub: bad symbol");
        let amount = self.amount() - rhs.amount();
        assert!(amount >= -MAX_AMOUNT, "subtraction underflow");
        assert!(amount <= MAX_AMOUNT, "subtraction overflow");
        Self {
            amount,
            symbol: self.symbol,
        }
    }
}

impl ops::SubAssign for Asset {
    fn sub_assign(&mut self, rhs: Asset) {
        *self = *self - rhs;
    }
}

impl Packer for Asset {
    fn size(&self) -> usize {
        16
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        let pos = enc.get_size();

        self.amount.pack(enc);
        self.symbol.pack(enc);

        enc.get_size() - pos
    }

    fn unpack(&mut self, data: &[u8]) -> usize {
        assert!(data.len() >= self.size(), "Asset.unpack: buffer overflow");

        let mut dec = Decoder::new(data);
        dec.unpack(&mut self.amount);
        assert!(
            self.amount >= -MAX_AMOUNT && self.amount <= MAX_AMOUNT,
            "Asset.unpack: bad asset amount"
        );
        dec.unpack(&mut self.symbol);
        dec.get_pos()
    }
}

pub(crate) fn deserialize_asset<'de, D>(deserializer: D) -> Result<Asset, D::Error>
where
    D: Deserializer<'de>,
{
    struct AssetVisitor;

    impl de::Visitor<'_> for AssetVisitor {
        type Value = Asset;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a string representing an asset in the format 'amount symbol_code'")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            // Directly return the Asset instance since Asset::from_string does not produce errors.
            Ok(Asset::from_string(value).map_err(|e| de::Error::custom(e.to_string()))?)
        }
    }

    deserializer.deserialize_str(AssetVisitor)
}

pub(crate) fn deserialize_optional_asset<'de, D>(deserializer: D) -> Result<Option<Asset>, D::Error>
where
    D: Deserializer<'de>,
{
    struct OptionalAssetVisitor;

    impl<'de> de::Visitor<'de> for OptionalAssetVisitor {
        type Value = Option<Asset>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str(
                "an optional string representing an asset in the format 'amount symbol_code'",
            )
        }

        fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: Deserializer<'de>,
        {
            Ok(Some(deserialize_asset(deserializer)?))
        }
    }

    deserializer.deserialize_option(OptionalAssetVisitor)
}

#[derive(Debug, Error)]
pub enum ExtendedAssetErrror {
    #[error("ExtendedAsset.from_string: invalid format expected asset@contract")]
    FormatError,
    #[error("ExtendedAsset.from_string: invalid asset")]
    AssetError(AssetFromStrError),
    #[error("ExtendedAsset.from_string: invalid contract name")]
    ContractError(NameError)
}

#[derive(Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtendedAsset {
    quantity: Asset,
    contract: Name,
}

impl ExtendedAsset {
    pub fn new(quantity: Asset, contract: Name) -> Self {
        Self { quantity, contract }
    }

    pub fn quantity(&self) -> Asset {
        self.quantity
    }

    pub fn contract(&self) -> Name {
        self.contract
    }

    pub fn as_string(&self) -> String {
        format!("{}@{}", self.quantity, self.contract)
    }

    pub fn from_string(s: &str) -> Result<ExtendedAsset, ExtendedAssetErrror> {
        let (first, second) = match s.split_once("@") {
            Some((first, second)) => Ok((first, second)),
            None => Err(ExtendedAssetErrror::FormatError)
        }?;

        let quantity = Asset::from_string(first).map_err(|e| ExtendedAssetErrror::AssetError(e))?;
        let contract = Name::from_string(second).map_err(|e| ExtendedAssetErrror::ContractError(e))?;

        Ok(ExtendedAsset {
            quantity,
            contract
        })
    }
}

impl Display for ExtendedAsset {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl Packer for ExtendedAsset {
    fn size(&self) -> usize {
        16 + 8
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        let pos = enc.get_size();

        self.quantity.pack(enc);
        self.contract.pack(enc);

        enc.get_size() - pos
    }

    fn unpack(&mut self, data: &[u8]) -> usize {
        assert!(
            data.len() >= self.size(),
            "ExtendedAsset.unpack: buffer overflow"
        );

        let mut dec = Decoder::new(data);
        dec.unpack(&mut self.quantity);
        dec.unpack(&mut self.contract);
        dec.get_pos()
    }
}