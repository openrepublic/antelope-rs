use std::fmt::{Display, Formatter};

use serde::de::{SeqAccess};
use serde::de::Error as SerdeDeError;
use serde::ser::Error as SerdeSerError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::{check_unpack_len, define_error};
use crate::serializer::{Encoder, Packer, PackerError};

define_error!(NameParsingError);

macro_rules! name_parse_error {
    ($($arg:tt)*) => {
        $crate::chain::name::NameParsingError::fmt(format_args!($($arg)*))
    };
}

const INVALID_NAME_CHAR: u8 = 0xffu8;

/// a helper function that converts a single ASCII character to
/// a symbol used by the eosio::name object.
/// ".12345abcdefghijklmnopqrstuvwxyz"
pub const fn char_to_index(c: u8) -> u8 {
    match c as char {
        'a'..='z' => (c - b'a') + 6,
        '1'..='5' => (c - b'1') + 1,
        '.' => 0,
        _ => INVALID_NAME_CHAR,
    }
}

const INVALID_NAME: u64 = 0xFFFF_FFFF_FFFF_FFFFu64;

// converts a static string to an `name` object.
pub const fn str_to_name(s: &str) -> u64 {
    let mut value: u64 = 0;
    let _s = s.as_bytes();

    if _s.len() > 13 {
        return INVALID_NAME;
    }

    if _s.is_empty() {
        return 0;
    }

    let mut n = _s.len();
    if n == 13 {
        n = 12;
    }

    let mut i = 0usize;

    loop {
        if i >= n {
            break;
        }
        let tmp = char_to_index(_s[i]) as u64;
        if tmp == INVALID_NAME_CHAR as u64 {
            return INVALID_NAME;
        }
        value <<= 5;
        value |= tmp;

        i += 1;
    }
    value <<= 4 + 5 * (12 - n);

    if _s.len() == 13 {
        let tmp = char_to_index(_s[12]) as u64;
        if tmp == INVALID_NAME_CHAR as u64 {
            return INVALID_NAME;
        }
        if tmp > 0x0f {
            return INVALID_NAME;
        }
        value |= tmp;
    }

    value
}

/// similar to static_str_to_name,
/// but also checks the validity of the resulting `name` object.
pub fn str_to_name_checked(s: &str) -> Result<u64, NameParsingError> {
    let n = str_to_name(s);
    if n == INVALID_NAME {
        return Err(name_parse_error!("Invalid name: {}", n));
    }
    Ok(n)
}

// ".12345abcdefghijklmnopqrstuvwxyz"
pub const CHAR_MAP: [u8; 32] = [
    46, 49, 50, 51, 52, 53, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122,
];

/// converts an `name` object to a string.
pub fn name_to_string(value: u64) -> Result<String, NameParsingError> {
    // 13 dots
    let mut s: [u8; 13] = [46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46, 46]; //'.'
    let mut tmp = value;
    for i in 0..13 {
        let c: u8 = if i == 0 {
            CHAR_MAP[(tmp & 0x0f) as usize]
        } else {
            CHAR_MAP[(tmp & 0x1f) as usize]
        };
        s[12 - i] = c;
        if i == 0 {
            tmp >>= 4
        } else {
            tmp >>= 5
        }
    }

    let mut i = s.len() - 1;
    while i != 0 {
        if s[i] != b'.' {
            break;
        }
        i -= 1;
    }
    if i == 0 {
        return Ok(String::from(""));
    }
    String::from_utf8(s[0..i + 1].to_vec())
        .map_err(|e| name_parse_error!("name to str err: {:?}", e))
}

/// a wrapper around a 64-bit unsigned integer that represents a name in the
/// Antelope blockchain
#[repr(C, align(8))]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Name {
    n: u64,
}

impl Name {
    #[inline(always)]
    pub fn value(&self) -> u64 {
        self.n
    }

    pub fn as_string(&self) -> Result<String, NameParsingError> {
        name_to_string(self.n)
    }
}

/* ---------- From / TryFrom *into* Name ---------- */

/// `str`-like inputs --------------------------------------------------------
impl TryFrom<&str> for Name {
    type Error = NameParsingError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Ok(Name { n: str_to_name_checked(s)? })
    }
}

impl TryFrom<String> for Name {
    type Error = NameParsingError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

impl TryFrom<&String> for Name {
    type Error = NameParsingError;
    fn try_from(s: &String) -> Result<Self, Self::Error> {
        Self::try_from(s.as_str())
    }
}

/// Integer inputs -----------------------------------------------------------
/// Helper macro: implement `TryFrom<$int>` for every integer width you need.
macro_rules! impl_int_tryfrom {
    ($($t:ty),*) => {$(
        impl TryFrom<$t> for Name {
            type Error = NameParsingError;
            fn try_from(v: $t) -> Result<Self, Self::Error> {
                let n = v as u64;
                name_to_string(n)?;                 // validate range / charset
                Ok(Name { n })
            }
        }
    )*};
}

impl_int_tryfrom!(u8, u16, u32, u64, i8, i16, i32, i64);

/* ---------- Conversions *out of* Name ---------- */

/// Into the backing `u64`
impl From<Name> for u64 {
    fn from(name: Name) -> Self { name.n }
}
impl From<&Name> for u64 {
    fn from(name: &Name) -> Self { name.n }
}

/// Into a heap-allocated `String`
impl TryFrom<Name> for String {
    type Error = NameParsingError;
    fn try_from(name: Name) -> Result<Self, Self::Error> { name.as_string() }
}
impl TryFrom<&Name> for String {
    type Error = NameParsingError;
    fn try_from(name: &Name) -> Result<Self, Self::Error> { name.as_string() }
}

impl Display for Name {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string().map_err(|_| std::fmt::Error)?)
    }
}

impl Packer for Name {
    fn size(&self) -> usize {
        8
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        self.n.pack(enc)
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<usize, PackerError> {
        check_unpack_len!(self, raw, 8);
        self.n = u64::from_le_bytes(raw[0..8].try_into().unwrap());
        Ok(8)
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.n.cmp(&other.n)
    }
}

pub(crate) fn deserialize_name<'de, D>(deserializer: D) -> Result<Name, D::Error>
where
    D: Deserializer<'de>,
{
    struct NameVisitor;

    impl serde::de::Visitor<'_> for NameVisitor {
        type Value = Name;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("a string representing an EOSIO name")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            Ok(Name::try_from(v).map_err(|e| E::custom(e.to_string()))?)
        }
    }

    deserializer.deserialize_str(NameVisitor)
}

pub(crate) fn deserialize_optional_name<'de, D>(deserializer: D) -> Result<Option<Name>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(deserializer)?;
    let result = match opt {
        Some(name_str) => Some(
            Name::try_from(name_str.as_str())
                .map_err(|e| D::Error::custom(e))?
        ),
        None => None
    };
    Ok(result)
}

pub(crate) fn deserialize_vec_name<'de, D>(deserializer: D) -> Result<Vec<Name>, D::Error>
where
    D: Deserializer<'de>,
{
    struct VecNameVisitor;

    impl<'de> serde::de::Visitor<'de> for VecNameVisitor {
        type Value = Vec<Name>;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("a vector of strings representing EOSIO names")
        }

        fn visit_seq<S>(self, mut seq: S) -> Result<Vec<Name>, S::Error>
        where
            S: SeqAccess<'de>,
        {
            let mut names = Vec::new();

            while let Some(elem) = seq.next_element::<String>()? {
                names.push(
                    Name::try_from(&elem)
                        .map_err(|e| S::Error::custom(e.to_string()))?
                );
            }

            Ok(names)
        }
    }

    deserializer.deserialize_seq(VecNameVisitor)
}

pub(crate) fn serialize_name<S>(name: &Name, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(
        &name.as_string()
            .map_err(|e| S::Error::custom(e))?
    )
}

#[allow(dead_code)]
pub(crate) fn serialize_optional_name<S>(
    name: &Option<Name>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match name {
        Some(n) => serializer.serialize_some(
            &n.as_string()
                .map_err(|e| S::Error::custom(e))?
        ),
        None => serializer.serialize_none(),
    }
}


#[allow(dead_code)]
pub(crate) fn serialize_vec_name<S>(
    names: &Vec<Name>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut strings = Vec::new();
    for name in names {
        strings.push(
            name.as_string()
                .map_err(|e| S::Error::custom(e))?
        );
    }
    serializer.collect_seq(strings)
}

pub const SAME_PAYER: Name = Name { n: 0 };

pub const ACTIVE: Name = Name {
    n: str_to_name("active"),
};
pub const OWNER: Name = Name {
    n: str_to_name("owner"),
};
pub const CODE: Name = Name {
    n: str_to_name("eosio.code"),
};
