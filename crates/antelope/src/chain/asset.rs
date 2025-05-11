use serde::{de, Deserialize, Deserializer, Serialize};
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;
use crate::chain::name::Name;
use crate::{check_unpack_len, define_error, packer_error};
use crate::serializer::{Decoder, Encoder, Packer, PackerError};

const MAX_AMOUNT: i64 = (1 << 62) - 1;
const MAX_PRECISION: u8 = 18;

/// Check if the given symbol code is valid.
#[inline]
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

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct SymbolCode {
    value: u64,
}

impl Into<u64> for SymbolCode {
    #[inline]
    fn into(self) -> u64 {
        self.value
    }
}

define_error!(SymbolCodeTryFromError);

impl TryFrom<u64> for SymbolCode {
    type Error = SymbolCodeTryFromError;

    #[inline]
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if !is_valid_symbol_code(value) {
            return Err(SymbolCodeTryFromError::new("invalid symbol code"));
        }
        Ok(SymbolCode { value })
    }
}

impl FromStr for SymbolCode {
    type Err = SymbolCodeTryFromError;

    #[inline]
    fn from_str(sym: &str) -> Result<Self, Self::Err> {
        let raw = sym.as_bytes();
        if raw.is_empty() {
            return Err(SymbolCodeTryFromError::new("sym code string empty"))
        }
        if raw.len() > 7 {
            return Err(SymbolCodeTryFromError::new("sym code string too long"))
        }

        let mut value: u64 = 0;
        for i in (0..raw.len()).rev() {
            let c = raw[i];
            if !c.is_ascii_uppercase() {
                return Err(SymbolCodeTryFromError::new(
                    format!("invalid symbol code character: {}", c as char))
                )
            }
            value <<= 8;
            value |= c as u64;
        }
        Ok(Self { value })
    }
}

impl Display for SymbolCode {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let mut string = String::with_capacity(7);
        let mut tmp = self.value;
        for i in 0usize..7usize {
            let c = (tmp & 0xff) as u8;
            // no need to check if c is valid ascii char, no way to construct a SymbolCode without
            // checking it
            string.insert(i, c as char);
            tmp >>= 8;
            if tmp == 0 {
                break;
            }
        }
        write!(f, "{}", string)
    }
}

impl Packer for SymbolCode {
    fn size(&self) -> usize {
        8
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        self.value.pack(enc)
    }

    fn unpack(&mut self, data: &[u8]) -> Result<usize, PackerError> {
        check_unpack_len!(self, data, 8);
        let mut val: u64 = 0;
        val.unpack(data)?;
        if !is_valid_symbol_code(val) {
            return Err(packer_error!("bad symbol code!"));
        }
        self.value = val;
        Ok(8)
    }
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Symbol {
    value: u64,
}

define_error!(SymbolTryFromError);

#[inline]
pub fn str_to_symbol(input: &str) -> Result<u64, SymbolTryFromError> {
    let (prec_str, code) = input
        .split_once(',')
        .ok_or(SymbolTryFromError::new("symbol must contain a comma (e.g. \"4,EOS\")"))?;

    let precision: u8 = prec_str
        .parse()
        .map_err(|_| SymbolTryFromError::new("precision must be a non‑negative integer <= 255"))?;

    if !(1..=7).contains(&code.len()) || !code.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(SymbolTryFromError::new("symbol code must be 1–7 uppercase ASCII letters"));
    }

    let mut value = precision as u64;
    for (i, byte) in code.bytes().enumerate() {
        value |= (byte as u64) << (8 * (i + 1));
    }
    Ok(value)
}

impl From<u64> for Symbol {
    #[inline]
    fn from(value: u64) -> Self {
        Self { value }
    }
}

impl Into<u64> for Symbol {
    #[inline]
    fn into(self) -> u64 {
        self.value
    }
}

impl FromStr for Symbol {
    type Err = SymbolTryFromError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self {
            value: str_to_symbol(s)?,
        })
    }
}

impl TryFrom<(&str, u8)> for Symbol {
    type Error = SymbolTryFromError;

    fn try_from(value: (&str, u8)) -> Result<Self, Self::Error> {
        let (name, precision) = value;
        let raw = name.as_bytes();
        if raw.is_empty() {
            return Err(SymbolTryFromError::new("symbol name empty"));
        }
        if raw.len() > 7 {
            return Err(SymbolTryFromError::new("symbol name too long"));
        }

        let mut value: u64 = 0;
        for i in (0..raw.len()).rev() {
            let c = raw[i];
            if !c.is_ascii_uppercase() {
                return Err(SymbolTryFromError::new(format!("invalid symbol name: {}", c as char)));
            }
            value <<= 8;
            value |= c as u64;
        }

        value <<= 8;
        value |= precision as u64;
        Ok(Self { value })
    }
}

impl Symbol {
    #[inline]
    pub fn value(&self) -> u64 {
        self.value
    }

    #[inline]
    pub fn code(&self) -> SymbolCode {
        SymbolCode {
            value: self.value >> 8,
        }
    }

    #[inline]
    pub fn precision(&self) -> usize {
        (self.value & 0xFF) as usize
    }
}

impl Display for Symbol {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.precision().to_string() + "," + &self.code().to_string())
    }
}

impl Packer for Symbol {
    fn size(&self) -> usize {
        8
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        self.value.pack(enc)
    }

    fn unpack(&mut self, data: &[u8]) -> Result<usize, PackerError> {
        check_unpack_len!(self, data, 8);
        self.value.unpack(data)?;
        Ok(8)
    }
}

#[derive(Debug, Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Asset {
    amount: i64,
    symbol: Symbol,
}

define_error!(AssetOpError);

#[derive(Copy, Clone, Eq, PartialEq)]
enum AssetStringParseStatus {
    Initial,
    FoundDot,
    FoundSpace,
}

fn is_amount_within_range(amount: i64) -> bool {
    (-MAX_AMOUNT..=MAX_AMOUNT).contains(&amount)
}

impl Asset {
    #[inline]
    pub fn amount(&self) -> i64 {
        self.amount
    }

    #[inline]
    pub fn symbol(&self) -> Symbol {
        self.symbol
    }

    pub fn try_add(&self, other: Asset) -> Result<Asset, AssetOpError> {
        if self.symbol != other.symbol {
            return Err(AssetOpError::new(format!("addition symbol mismatch: {} != {}", self.symbol, other.symbol)));
        }
        let amount = self.amount + other.amount;
        if amount > MAX_AMOUNT {
            return Err(AssetOpError::new(format!("addition overflow: {} + {} > {}", self.amount, amount, MAX_AMOUNT)));
        }
        if amount < -MAX_AMOUNT {
            return Err(AssetOpError::new(format!("addition underflow: {} + {} < {}", self.amount, amount, -MAX_AMOUNT)));
        }
        Ok(Asset::try_from((amount, self.symbol))
            .map_err(
                |e| AssetOpError::new(format!("AssetTryFromError: {}", e.to_string()))
            )?
        )
    }

    pub fn try_sub(&self, other: Asset) -> Result<Asset, AssetOpError> {
        if self.symbol != other.symbol {
            return Err(AssetOpError::new(format!("subtraction symbol mismatch: {} != {}", self.symbol, other.symbol)));
        }
        let amount = self.amount - other.amount;
        if amount > MAX_AMOUNT {
            return Err(AssetOpError::new(format!("subtraction overflow: {} - {} > {}", self.amount, amount, MAX_AMOUNT)));
        }
        if amount < -MAX_AMOUNT {
            return Err(AssetOpError::new(format!("subtraction underflow: {} - {} < {}", self.amount, amount, -MAX_AMOUNT)));
        }
        Ok(Asset::try_from((amount, self.symbol))
            .map_err(
                |e| AssetOpError::new(format!("AssetTryFromError: {}", e.to_string()))
            )?
        )
    }
}

impl Display for Asset {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let prec = self.symbol.precision() as u32;

        // 10^prec  (precision is <= 18 in EOSIO, so this never overflows i64)
        let pow10 = 10_i64.pow(prec);

        // split into integer and fractional parts
        let int_part = self.amount / pow10;
        let frac_part = (self.amount.abs() % pow10) as u64; // always non-negative

        // integer
        write!(f, "{int_part}")?;

        // fractional (only if precision > 0)
        if prec != 0 {
            // leading-zero padded to exactly `prec` digits
            write!(f, ".{:0width$}", frac_part, width = prec as usize)?;
        }

        write!(f, " {}", self.symbol.code())
    }
}

define_error!(AssetTryFromError);

impl TryFrom<(i64, Symbol)> for Asset {
    type Error = AssetTryFromError;

    fn try_from(value: (i64, Symbol)) -> Result<Self, Self::Error> {
        let (amount, symbol) = value;
        if !is_amount_within_range(amount) {
            return Err(AssetTryFromError::new(
                format!("magnitude of asset amount must be less than 2^62: {}", amount))
            )
        }
        Ok(Self { amount, symbol })
    }
}

impl FromStr for Asset {
    type Err = AssetTryFromError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(AssetTryFromError::new("empty string"));
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
                    return Err(AssetTryFromError::new("invalid dot character"));
                }
                status = AssetStringParseStatus::FoundDot;
                continue;
            } else if c == b' ' {
                if status != AssetStringParseStatus::Initial &&
                    status != AssetStringParseStatus::FoundDot {
                    return Err(AssetTryFromError::new("invalid space character"));
                }
                status = AssetStringParseStatus::FoundSpace;
                continue;
            }

            match status {
                AssetStringParseStatus::Initial => {
                    if !c.is_ascii_digit() {
                        return Err(AssetTryFromError::new("bad amount: char is not ascii digit"));
                    }
                    amount *= 10;
                    amount += (c - b'0') as i64;
                    if !is_amount_within_range(amount) {
                        return Err(AssetTryFromError::new("bad amount: not in range"));
                    }
                }
                AssetStringParseStatus::FoundDot => {
                    if !c.is_ascii_digit() {
                        return Err(AssetTryFromError::new("bad amount: char is not ascii digit"));
                    }
                    amount *= 10;
                    amount += (c - b'0') as i64;
                    precision += 1;
                    if precision > MAX_PRECISION {
                        return Err(AssetTryFromError::new("precision overflow"))
                    }
                    if !is_amount_within_range(amount) {
                        return Err(AssetTryFromError::new("bad amount: not in range"));
                    }
                }
                AssetStringParseStatus::FoundSpace => {
                    if !c.is_ascii_uppercase() {
                        return Err(AssetTryFromError::new("bad amount: char is not ascii digit"));
                    }
                    raw_symbol.push(c);
                    if raw_symbol.len() >= 7 {
                        return Err(AssetTryFromError::new("bad symbol: too long"));
                    }
                }
            }
        }

        if raw_symbol.is_empty() {
            return Err(AssetTryFromError::new("bad symbol: empty sym"));
        }

        if minus {
            amount = -amount;
        }

        raw_symbol.reverse();
        for c in raw_symbol {
            symbol <<= 8;
            symbol |= c as u64;
        }

        symbol <<= 8;
        symbol |= precision as u64;

        Ok(Self {
            amount,
            symbol: Symbol { value: symbol },
        })
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

    fn unpack(&mut self, data: &[u8]) -> Result<usize, PackerError> {
        check_unpack_len!(self, data, 16);
        // First amount as i64
        let mut dec = Decoder::new(data);
        dec.unpack(&mut self.amount)?;
        if self.amount < -MAX_AMOUNT || self.amount > MAX_AMOUNT {
            return Err(packer_error!("bad asset amount while unpacking: {}", self.amount));
        }
        dec.unpack(&mut self.symbol)?;
        Ok(dec.get_pos())
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
            Ok(Asset::from_str(value).map_err(|e| E::custom(e.to_string()))?)
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

#[derive(Copy, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExtendedAsset {
    pub quantity: Asset,
    pub contract: Name,
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

    fn unpack(&mut self, data: &[u8]) -> Result<usize, PackerError> {
        check_unpack_len!(self, data, 16 + 8);
        let mut dec = Decoder::new(data);
        dec.unpack(&mut self.quantity)?;
        dec.unpack(&mut self.contract)?;
        Ok(dec.get_pos())
    }
}

impl Display for ExtendedAsset {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.quantity, self.contract)
    }
}

define_error!(ExtendedAssetParsingError);

impl TryFrom<&str> for ExtendedAsset {
    type Error = ExtendedAssetParsingError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parts = value.split("@").collect::<Vec<&str>>();
        if parts.len() != 2 {
            return Err(ExtendedAssetParsingError::new(format!("Expected two parts after split by @ but got {:?}", parts)))
        }
        let quantity = Asset::from_str(parts[0])
            .map_err(|e| ExtendedAssetParsingError::new(format!("Invalid quantity: {}", e)))?;

        let contract = Name::try_from(parts[1])
            .map_err(|e| ExtendedAssetParsingError::new(format!("Could not parse asset name: {:?}", e)))?;

        Ok(ExtendedAsset { quantity, contract })
    }
}