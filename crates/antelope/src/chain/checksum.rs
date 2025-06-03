use std::fmt;
use std::fmt::{Display, Formatter};

use ripemd::{Digest as Ripemd160Digest, Ripemd160};
use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_big_array::BigArray;
use sha2::{Sha256, Sha512};

use crate::{
    check_unpack_len,
    util::{bytes_to_hex, slice_copy}
};
use crate::serializer::{Encoder, Packer, PackerError};
use hex::decode;

#[derive(Clone, Copy, Eq, PartialEq, Default, Serialize, Deserialize, Debug)]
pub struct Checksum160 {
    pub data: [u8; 20],
}

impl Checksum160 {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        if s.len() != 40 {
            return Err(String::from("Checksum160: bad hex string length"));
        }
        let data = decode(s)
            .map_err(|e| e.to_string())?;
        Self::from_bytes(data.as_slice())
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != 20 {
            return Err(String::from("Checksum160: bad byte array length"));
        }
        let mut ret = Self::default();
        slice_copy(&mut ret.data, b);
        Ok(ret)
    }

    pub fn hash(bytes: Vec<u8>) -> Self {
        let mut hasher = Ripemd160::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        Self { data: result.into() }
    }

    pub fn as_string(&self) -> String {
        bytes_to_hex(&self.data.to_vec())
    }
}

impl From<[u8; 20]> for Checksum160 {
    #[inline]
    fn from(data: [u8; 20]) -> Self {
        Checksum160 { data }
    }
}

impl Display for Checksum160 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl Packer for Checksum160 {
    fn size(&self) -> usize {
        20
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        pack_checksum(self.size(), &self.data, enc)
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<usize, PackerError> {
        check_unpack_len!(self, raw, 20);
        slice_copy(&mut self.data, &raw[..20]);
        Ok(20)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Default, Debug, Serialize, Deserialize)]
pub struct Checksum256 {
    pub data: [u8; 32],
}

pub(crate) fn deserialize_checksum256<'de, D>(deserializer: D) -> Result<Checksum256, D::Error>
where
    D: Deserializer<'de>,
{
    struct Checksum256Visitor;

    impl Visitor<'_> for Checksum256Visitor {
        type Value = Checksum256;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a hex string of length 64 (for 32 bytes)")
        }

        fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if value.len() != 64 {
                return Err(E::custom("hex string must be exactly 64 characters long"));
            }

            let mut data = [0u8; 32];
            for i in 0..32 {
                let byte_slice = &value[i * 2..i * 2 + 2];
                data[i] = u8::from_str_radix(byte_slice, 16).map_err(E::custom)?;
            }

            // Adjust this to properly construct a Checksum256 instance
            Checksum256::from_bytes(&data).map_err(E::custom)
        }
    }

    deserializer.deserialize_str(Checksum256Visitor)
}

impl Checksum256 {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        if s.len() != 64 {
            return Err(String::from("Checksum256: bad hex string length"));
        }
        let data = decode(s)
            .map_err(|e| e.to_string())?;
        Self::from_bytes(data.as_slice())
    }

    pub fn from_bytes(b: &[u8]) -> Result<Self, String> {
        if b.len() != 32 {
            return Err(String::from("Checksum256: bad byte array length"));
        }
        let mut ret = Self::default();
        slice_copy(&mut ret.data, b);
        Ok(ret)
    }

    pub fn hash(bytes: Vec<u8>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let result = hasher.finalize();
        Self { data: result.into() }
    }

    pub fn as_string(&self) -> String {
        bytes_to_hex(&self.data.to_vec())
    }

    pub fn to_index(&self) -> String {
        assert_eq!(self.data.len(), 32);

        let (first_16, second_16) = self.data.split_at(16);

        let mut first_reversed = first_16.to_vec();
        first_reversed.reverse();

        let mut second_reversed = second_16.to_vec();
        second_reversed.reverse();

        let mut new_vec = second_reversed;
        new_vec.extend(first_reversed);

        bytes_to_hex(&new_vec)
    }
}

impl From<[u8; 32]> for Checksum256 {
    #[inline]
    fn from(data: [u8; 32]) -> Self {
        Checksum256 { data }
    }
}

impl Display for Checksum256 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl Packer for Checksum256 {
    fn size(&self) -> usize {
        32
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        pack_checksum(self.size(), &self.data, enc)
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<usize, PackerError> {
        check_unpack_len!(self, raw, 32);
        slice_copy(&mut self.data, &raw[..32]);
        Ok(32)
    }
}

#[derive(Clone, Copy, Eq, Debug, PartialEq, Serialize, Deserialize)]
pub struct Checksum512 {
    #[serde(with = "BigArray")]
    pub data: [u8; 64],
}

impl Checksum512 {
    pub fn from_hex(s: &str) -> Result<Self, String> {
        if s.len() != 128 {
            return Err(String::from("Checksum512: bad hex string length"));
        }
        let data = decode(s)
            .map_err(|e| e.to_string())?;
        Ok(Self::from_bytes(data.as_slice()))
    }

    pub fn from_bytes(b: &[u8]) -> Self {
        assert_eq!(b.len(), 64, "Checksum512: bad byte array length");
        let mut ret = Self::default();
        slice_copy(&mut ret.data, b);
        ret
    }

    pub fn hash(bytes: Vec<u8>) -> Self {
        Checksum512::from_bytes(Sha512::digest(bytes).as_slice())
    }

    pub fn as_string(&self) -> String {
        bytes_to_hex(&self.data.to_vec())
    }
}

impl From<[u8; 64]> for Checksum512 {
    #[inline]
    fn from(data: [u8; 64]) -> Self {
        Checksum512 { data }
    }
}

impl Display for Checksum512 {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_string())
    }
}

impl Default for Checksum512 {
    fn default() -> Self {
        Checksum512 { data: [0; 64] }
    }
}

impl Packer for Checksum512 {
    fn size(&self) -> usize {
        64
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        pack_checksum(self.size(), &self.data, enc)
    }

    fn unpack(&mut self, raw: &[u8]) -> Result<usize, PackerError> {
        check_unpack_len!(self, raw, 64);
        slice_copy(&mut self.data, &raw[..64]);
        Ok(64)
    }
}

fn pack_checksum(size: usize, data: &[u8], enc: &mut Encoder) -> usize {
    let allocated = enc.alloc(size);
    slice_copy(allocated, data);
    size
}
