// https://github.com/AntelopeIO/leap/blob/92b6fec5e949660bae78e90ebf555fe71ab06940/libraries/chain/abi_serializer.cpp#L89

/*
void abi_serializer::configure_built_in_types() {
    built_in_types.emplace("bool",                      pack_unpack<uint8_t>());
    built_in_types.emplace("int8",                      pack_unpack<int8_t>());
    built_in_types.emplace("uint8",                     pack_unpack<uint8_t>());
    built_in_types.emplace("int16",                     pack_unpack<int16_t>());
    built_in_types.emplace("uint16",                    pack_unpack<uint16_t>());
    built_in_types.emplace("int32",                     pack_unpack<int32_t>());
    built_in_types.emplace("uint32",                    pack_unpack<uint32_t>());
    built_in_types.emplace("int64",                     pack_unpack<int64_t>());
    built_in_types.emplace("uint64",                    pack_unpack<uint64_t>());
    built_in_types.emplace("int128",                    pack_unpack<int128_t>());
    built_in_types.emplace("uint128",                   pack_unpack<uint128_t>());
    built_in_types.emplace("varint32",                  pack_unpack<fc::signed_int>());
    built_in_types.emplace("varuint32",                 pack_unpack<fc::unsigned_int>());

    built_in_types.emplace("float32",                   pack_unpack<float>());
    built_in_types.emplace("float64",                   pack_unpack<double>());
    built_in_types.emplace("float128",                  pack_unpack<float128_t>());

    built_in_types.emplace("time_point",                pack_unpack<fc::time_point>());
    built_in_types.emplace("time_point_sec",            pack_unpack<fc::time_point_sec>());
    built_in_types.emplace("block_timestamp_type",      pack_unpack<block_timestamp_type>());

    built_in_types.emplace("name",                      pack_unpack<name>());

    built_in_types.emplace("bytes",                     pack_unpack<bytes>());
    built_in_types.emplace("string",                    pack_unpack<string>());

    built_in_types.emplace("checksum160",               pack_unpack<checksum160_type>());
    built_in_types.emplace("checksum256",               pack_unpack<checksum256_type>());
    built_in_types.emplace("checksum512",               pack_unpack<checksum512_type>());

    built_in_types.emplace("public_key",                pack_unpack_deadline<public_key_type>());
    built_in_types.emplace("signature",                 pack_unpack_deadline<signature_type>());

    built_in_types.emplace("symbol",                    pack_unpack<symbol>());
    built_in_types.emplace("symbol_code",               pack_unpack<symbol_code>());
    built_in_types.emplace("asset",                     pack_unpack<asset>());
    built_in_types.emplace("extended_asset",            pack_unpack<extended_asset>());
}

Any other type should be able to be represented by a sequence of these types

 */
use std::cmp::PartialEq;
use std::fmt;


#[derive(Debug, Clone, PartialEq)]
pub enum Exception {
    VariantIndexNotInJumpTable,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    None,
    Bool(bool),
    Int(Vec<u8>, bool),
    Float(Vec<u8>),
    Bytes(Vec<u8>),
    Condition(isize),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::None => write!(f, "None"),
            Value::Bool(b) => write!(f, "{}", b),
            Value::Int(bytes, signed) => {
                write!(f, "Int({} bytes, signed: {})", bytes.len(), signed)
            }
            Value::Float(bytes) => {
                write!(f, "Float({} bytes)", bytes.len())
            }
            Value::Bytes(bytes) => {
                write!(f, "Bytes(0x{})", hex::encode(bytes))
            }
            Value::Condition(size) => {
                write!(f, "Condition({})", size)
            }
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum Instruction {
    // io stack manipulation
    // pack a value of specific type poping it from the io stack
    // or unpack a value from the source bytes buffer to the io stack
    Bool,
    UInt(u8),
    Int(u8),
    VarUInt,
    VarInt,
    Float(u8),
    Bytes,  // bytes with LEB128 encoded size first
    BytesRaw(u8),  // raw bytes, if param is > 0 do size check on stack value
    // these modify how the next instructions are handled
    Optional(u8),
    Extension(u8),

    // push condition from io stack into condition stack
    PushCND,
    // discard condition from stack
    PopCND,

    // jumps
    Jmp(usize),  // absolute jmp

    // conditional jumps based on first value on program stack
    JmpCND(usize, isize, isize),  // target ptr, condition value, cnd delta to apply
    JmpNotCND(usize, isize, isize),  // target ptr, condition value, cnd delta to apply

    // used to indicate a program shouldn't reach this instruction
    Raise(Exception),

    DebugVariantDef(String),
    DebugVariantImpl(String),
    DebugTypeAlias(String),
    DebugNextType(String),
    DebugEndType(String),
}

#[inline(always)]
pub fn instruction_sequence_for(ty: &str) -> Option<Vec<Instruction>> {
    Some(match ty {
        "bool" => vec![Instruction::Bool],

        "uint8" => vec![Instruction::UInt(1)],
        "uint16" => vec![Instruction::UInt(2)],
        "uint32" => vec![Instruction::UInt(4)],
        "uint64" => vec![Instruction::UInt(8)],
        "uint128" => vec![Instruction::UInt(16)],

        "int8" => vec![Instruction::Int(1)],
        "int16" => vec![Instruction::Int(2)],
        "int32" => vec![Instruction::Int(4)],
        "int64" => vec![Instruction::Int(8)],
        "int128" => vec![Instruction::Int(16)],

        "varuint32" => vec![Instruction::VarUInt],
        "varint32" => vec![Instruction::VarInt],

        "float32" => vec![Instruction::Float(4)],
        "float64" => vec![Instruction::Float(8)],
        "float128" => vec![Instruction::BytesRaw(16)],

        "time_point" => vec![Instruction::UInt(8)],
        "time_point_sec" => vec![Instruction::UInt(4)],
        "block_timestamp_type" => vec![Instruction::UInt(4)],

        "name" => vec![Instruction::UInt(8)],

        "bytes" => vec![Instruction::Bytes],
        "string" => vec![Instruction::Bytes],

        "checksum160" => vec![Instruction::BytesRaw(20)],
        "checksum256" => vec![Instruction::BytesRaw(32)],
        "checksum512" => vec![Instruction::BytesRaw(64)],

        "public_key" => vec![Instruction::BytesRaw(0)],
        "signature" => vec![Instruction::BytesRaw(0)],

        "symbol" => vec![Instruction::UInt(8)],
        "symbol_code" => vec![Instruction::UInt(8)],

        "asset" => vec![Instruction::Int(8), Instruction::UInt(8)],
        "extended_asset" => vec![Instruction::UInt(8), Instruction::UInt(8), Instruction::UInt(8)],

        _ => return None,
    })
}
