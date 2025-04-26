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
use std::fmt::Debug;
use crate::chain::binary_extension::BinaryExtension;
use crate::chain::name::Name;
use crate::chain::varint::VarUint32;
use crate::serializer::Packer;

#[derive(Debug, Clone, PartialEq)]
pub enum Exception {
    VariantIndexNotInJumpTable,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    None,
    Bool(bool),

    // unsigned
    Uint8 (u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Uint128(u128),

    // signed
    Int8 (i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Int128(i128),

    // var-len encoded integers
    VarUInt32(u32),
    VarInt32(i32),

    // floats
    Float32(f32),
    Float64(f64),
    Float128([u8; 16]),

    Bytes(Vec<u8>),
    Condition(isize),
}


macro_rules! impl_value_from {
    ($( ($src:ty, $dst:ident) ),* $(,)?) => {
        $(impl From<$src> for Value {
            #[inline] fn from(v: $src) -> Self { Value::$dst(v) }
        })*

        $(impl From<&$src> for Value {
            #[inline] fn from(v: &$src) -> Self { Value::$dst(*v) }
        })*
    };
}

impl_value_from!(
    (bool, Bool),
    (u8, Uint8), (u16, Uint16), (u32, Uint32), (u64, Uint64), (u128, Uint128),
    (i8, Int8), (i16, Int16), (i32, Int32), (i64, Int64), (i128, Int128),
    (f32, Float32), (f64, Float64)
);

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::Bytes(s.into_bytes())
    }
}

impl From<&String> for Value {
    fn from(s: &String) -> Self {
        Value::Bytes(s.clone().into_bytes())
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Value::Bytes(value.as_bytes().to_vec())
    }
}

impl From<Vec<u8>> for Value {
    fn from(value: Vec<u8>) -> Self {
        Value::Bytes(value)
    }
}

impl From<VarUint32> for Value {
    fn from(value: VarUint32) -> Self {
        Value::VarUInt32(value.n)
    }
}

impl From<[u8; 16]> for Value {
    fn from(value: [u8; 16]) -> Self {
        Value::Float128(value)
    }
}

impl From<Name> for Value {
    fn from(n: Name) -> Self {
        n.value().into()
    }
}


impl From<&Name> for Value {
    fn from(n: &Name) -> Self {
        n.value().into()
    }
}

impl From<isize> for Value {
    fn from(value: isize) -> Self {
        Value::Condition(value)
    }
}

impl<T> From<Option<T>> for Value where T: Into<Value> {
    fn from(value: Option<T>) -> Self {
        if let Some(v) = value {
            v.into()
        } else {
            Value::None
        }
    }
}

impl<T> From<BinaryExtension<T>> for Value where
    T: Into<Value> + Packer + Default,
{
    fn from(ext: BinaryExtension<T>) -> Self {
        ext.value.into()
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::None => write!(f, "None"),
            Value::Bool(v) => write!(f, "{}", v),

            Value::Uint8(v) => write!(f, "{}", v),
            Value::Uint16(v) => write!(f, "{}", v),
            Value::Uint32(v) => write!(f, "{}", v),
            Value::Uint64(v) => write!(f, "{}", v),
            Value::Uint128(v) => write!(f, "{}", v),

            Value::Int8(v) => write!(f, "{}", v),
            Value::Int16(v) => write!(f, "{}", v),
            Value::Int32(v) => write!(f, "{}", v),
            Value::Int64(v) => write!(f, "{}", v),
            Value::Int128(v) => write!(f, "{}", v),

            Value::VarUInt32(v) => write!(f, "{}", v),
            Value::VarInt32(v) => write!(f, "{}", v),

            Value::Float32(v) => write!(f, "{}", v),
            Value::Float64(v) => write!(f, "{}", v),
            Value::Float128(bytes) => write!(f, "Float128({:02x?})", bytes),

            Value::Bytes(vec) => write!(f, "Bytes({:02x?})", vec),

            Value::Condition(v) => write!(f, "Condition({})", v),
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

    // stop the runtime
    Exit(u8)
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
        "float128" => vec![Instruction::Float(16)],

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

// traits for things that can be part of an IO stack
pub trait IOStackValue {
    fn push_to_stack(&self, stack: &mut Vec<Value>);
}

macro_rules! impl_io_stack_value {
    ($( $src:ty ),* $(,)?) => {
        $(impl IOStackValue for $src {
            fn push_to_stack(&self, stack: &mut Vec<Value>) {
                stack.push(self.into())
            }
        })*

        $(impl IOStackValue for &$src {
            fn push_to_stack(&self, stack: &mut Vec<Value>) {
                stack.push(Value::from(*self).into())
            }
        })*
    };
}

impl_io_stack_value!(
    bool,
    u8,
    u16,
    u32,
    u64,
    u128,
    i8,
    i16,
    i32,
    i64,
    i128,
    f32, f64,
    String,
    Name
);


impl IOStackValue for Vec<u8> {
    fn push_to_stack(&self, out: &mut Vec<Value>) {
        out.push(Value::Bytes(self.clone()));
    }
}

impl IOStackValue for Vec<String> {
    fn push_to_stack(&self, out: &mut Vec<Value>) {
        out.push(Value::Condition(self.len() as isize));
        self.iter()
            .map(|s| s.clone().into_bytes().into())
            .for_each(|raw| out.push(Value::Bytes(raw)));
    }
}

impl IOStackValue for Option<Vec<u8>> {
    fn push_to_stack(&self, out: &mut Vec<Value>) {
        match self {
            Some(v) => v.push_to_stack(out),
            None    => out.push(Value::None),
        }
    }
}

impl IOStackValue for Option<String> {
    fn push_to_stack(&self, out: &mut Vec<Value>) {
        match self {
            Some(v) => v.push_to_stack(out),
            None    => out.push(Value::None),
        }
    }
}

impl IOStackValue for Option<Name> {
    fn push_to_stack(&self, out: &mut Vec<Value>) {
        match self {
            Some(v) => v.n.push_to_stack(out),
            None    => out.push(Value::None),
        }
    }
}

default impl<T: IOStackValue> IOStackValue for Option<T> {
    fn push_to_stack(&self, out: &mut Vec<Value>) {
        match self {
            Some(v) => v.push_to_stack(out),
            None    => out.push(Value::None),
        }
    }
}

impl IOStackValue for BinaryExtension<Name> {
    fn push_to_stack(&self, stack: &mut Vec<Value>) {
        match &self.value {
            Some(v) => v.push_to_stack(stack),
            None    => stack.push(Value::None),
        }
    }
}

default impl<T: IOStackValue> IOStackValue for BinaryExtension<T>
where
    T: Packer + Default,
{
    fn push_to_stack(&self, out: &mut Vec<Value>) {
        match &self.value {
            Some(v) => v.push_to_stack(out),
            None    => out.push(Value::None),
        }
    }
}

pub trait IntoIOStack: IOStackValue {
    fn to_stack(&self) -> Vec<Value> {
        let mut v = Vec::new();
        self.push_to_stack(&mut v);
        v
    }
}
impl<T: IOStackValue + ?Sized> IntoIOStack for T {}