use crate::serializer::{Encoder, Packer, PackerError};
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt::{self, Display, Formatter};

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Debug, Default)]
pub struct BlockId {
    pub bytes: [u8; 32],
}

impl BlockId {
    pub fn from_bytes(src: &[u8]) -> Result<Self, String> {
        if src.len() != 32 {
            return Err("BlockId.from_bytes expected 32 bytes".into());
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(src);
        Ok(Self { bytes })
    }

    pub fn block_num(&self) -> u32 {
        let [a, b, c, d, ..] = self.bytes;
        (u32::from(a) << 24)
            | (u32::from(b) << 16)
            | (u32::from(c) << 8)
            | u32::from(d)
    }

    pub fn as_string(&self) -> String {
        self.block_num().to_string()
    }
}

impl Packer for BlockId {

    fn size(&self) -> usize {
        32
    }

    fn pack(&self, enc: &mut Encoder) -> usize {
        let buf = enc.alloc(32);
        buf.copy_from_slice(&self.bytes);
        32
    }

    fn unpack(&mut self, data: &[u8]) -> Result<usize, PackerError> {
        self.bytes.copy_from_slice(data);
        Ok(32)
    }
}

impl Display for BlockId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.as_string().fmt(f)
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

        fn visit_str<E>(self, v: &str) -> Result<BlockId, E>
        where
            E: de::Error,
        {
            if v.len() != 64 {
                return Err(E::custom("hex length must be 64"));
            }
            let mut bytes = [0u8; 32];
            for i in 0..32 {
                let b = u8::from_str_radix(&v[i * 2..i * 2 + 2], 16)
                    .map_err(|_| E::custom("invalid hex"))?;
                bytes[i] = b;
            }
            Ok(BlockId { bytes })
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
        if s.len() != 64 {
            return Err(serde::de::Error::custom("hex length must be 64"));
        }
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| serde::de::Error::custom("invalid hex"))?;
        }
        Ok(BlockId { bytes })
    })
    .transpose()
}
