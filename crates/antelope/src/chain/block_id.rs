use crate::define_error;
use crate::serializer::{Encoder, Packer, PackerError};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use std::str::FromStr;

use crate::chain::checksum::Checksum256;

/// In the reference C++ impl block_id is an alias of checksum256, in order to make BlockId struct
/// easy to change in the future we use a single item tuple struct
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Default)]
pub struct BlockId(pub Checksum256);

impl From<Checksum256> for BlockId {
    fn from(value: Checksum256) -> Self {
        BlockId(value)
    }
}

impl From<BlockId> for Checksum256 {
    fn from(value: BlockId) -> Self {
        value.0
    }
}

impl From<[u8; 32]> for BlockId {
    fn from(value: [u8; 32]) -> Self {
        Checksum256::from(value).into()
    }
}

impl TryFrom<&[u8]> for BlockId {
    type Error = PackerError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Checksum256::try_from(value)
            .map(|sum| sum.into())
    }
}

define_error!(BlockIdParseError);

impl FromStr for BlockId {
    type Err = BlockIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Checksum256::from_str(s)
            .map(|sum| sum.into())
            .map_err(|e| BlockIdParseError::new(e.to_string()))
    }
}

impl BlockId {
    pub fn block_num(&self) -> u32 {
        let [a, b, c, d, ..] = self.0.data;
        (u32::from(a) << 24)
            | (u32::from(b) << 16)
            | (u32::from(c) << 8)
            | u32::from(d)
    }
}

impl Packer for BlockId {

    fn size(&self) -> usize {
        self.0.size()
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        self.0.pack(enc)
    }

    fn unpack(&mut self, data: &[u8]) -> Result<usize, PackerError> {
        self.0.unpack(data)
    }
}

impl Display for BlockId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for BlockId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {self}", self.block_num())
    }
}

pub(crate) fn deserialize_block_id<'de, D>(d: D) -> Result<BlockId, D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor;
    impl Visitor<'_> for HexVisitor {
        type Value = BlockId;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("64-char hex string for BlockId")
        }

        fn visit_str<E>(self, s: &str) -> Result<BlockId, E>
        where
            E: de::Error,
        {
            BlockId::from_str(s)
                .map_err(|e| de::Error::custom(e.to_string()))
        }
    }

    d.deserialize_str(HexVisitor)
}

pub(crate) fn deserialize_optional_block_id<'de, D>(
    d: D,
) -> Result<Option<BlockId>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt: Option<String> = Option::deserialize(d)?;
    opt.map(|s| {
        BlockId::from_str(&s)
            .map_err(|e| de::Error::custom(e.to_string()))
    })
    .transpose()
}
