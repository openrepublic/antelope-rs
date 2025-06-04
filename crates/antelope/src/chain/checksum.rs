use std::fmt;
use std::str::FromStr;

use ripemd::{Digest as Ripemd160Digest};
use serde::de::Visitor;
use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    util::slice_copy
};
use crate::serializer::Encoder;
use serde_big_array::BigArray;

fn pack_checksum(size: usize, data: &[u8], enc: &mut Encoder) -> usize {
    let allocated = enc.alloc(size);
    slice_copy(allocated, data);
    size
}

/// All checksum classes are defined using this macro (see below)
#[macro_export]
macro_rules! define_checksum {
    ($name:ident, $bits:literal, $hasher:path, $err_name:ident) => {
        #[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Debug)]
        pub struct $name {
            #[serde(with = "BigArray")]
            pub data: [u8; $bits / 8],
        }

        impl Default for $name {
            fn default() -> Self {
                Self { data: [0u8; $bits / 8] }
            }
        }

        impl $name {
            pub fn hash(bytes: Vec<u8>) -> Self {
                let mut hasher = <$hasher>::new();
                hasher.update(bytes);
                Self { data: hasher.finalize().into() }
            }
        }

        impl From<[u8; $bits / 8]> for $name {
            #[inline] fn from(data: [u8; $bits / 8]) -> Self { Self { data } }
        }

        impl TryFrom<&[u8]> for $name {
            type Error = $crate::serializer::PackerError;
            fn try_from(raw: &[u8]) -> Result<Self, Self::Error> {
                let mut dec = $crate::serializer::Decoder::new(raw);
                let mut sum = Self::default();
                dec.unpack(&mut sum)?;
                Ok(sum)
            }
        }

        $crate::define_error!($err_name);

        impl std::str::FromStr for $name {
            type Err = $err_name;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if s.len() != $bits / 4 {
                    return Err($err_name::new(concat!(stringify!($name), ": bad hex string length")));
                }
                let bytes = ::hex::decode(s)
                    .map_err(|e| $err_name::new(format!("{} decode error {e}", stringify!($name))))?;
                Self::try_from(bytes.as_slice())
                    .map_err(|e| $err_name::new(format!("{} packer error {e}", stringify!($name))))
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", ::hex::encode(self.data))
            }
        }

        impl $crate::serializer::Packer for $name {
            fn size(&self) -> usize { $bits / 8 }
            fn pack(&self, enc: &mut $crate::serializer::Encoder) -> usize {
                pack_checksum(self.size(), &self.data, enc)
            }
            fn unpack(&mut self, raw: &[u8]) -> Result<usize, $crate::serializer::PackerError> {
                $crate::check_unpack_len!(self, raw, $bits / 8);
                $crate::util::slice_copy(&mut self.data, &raw[..$bits / 8]);
                Ok(self.size())
            }
        }

        paste::paste! {
            #[allow(non_snake_case, dead_code)]
            pub(crate) fn [<deserialize_checksum $bits>]<'de, D>(
                deserializer: D,
            ) -> Result<$name, D::Error>
            where
                D: Deserializer<'de>,
            {
                struct VisitorImpl;
                impl<'de> Visitor<'de> for VisitorImpl {
                    type Value = $name;

                    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                        write!(
                            f,
                            "a hex string of length {} ({} bytes)",
                            $bits / 4,
                            $bits / 8
                        )
                    }

                    fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                    where
                        E: de::Error,
                    {
                        $name::from_str(s).map_err(|e| de::Error::custom(e.to_string()))
                    }
                }

                deserializer.deserialize_str(VisitorImpl)
            }
        }
    };
}

define_checksum!(Checksum160, 160, ripemd::Ripemd160, Sum160ParseError);
define_checksum!(Checksum256, 256, sha2::Sha256, Sum256ParseError);
define_checksum!(Checksum512, 512, sha2::Sha512, Sum512ParseError);
