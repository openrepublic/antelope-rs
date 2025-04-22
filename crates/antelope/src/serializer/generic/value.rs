use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,

    Bool(bool),

    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Int128(i128),

    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Uint128(u128),

    Float32(f32),
    Float64(f64),

    Bytes(Vec<u8>),
    String(String),

    Name(u64),
    Symbol(u64),
    SymbolCode(u64),
    Asset(i64, u64),

    Array(Vec<Value>),

    Struct(HashMap<String, Value>),
}
