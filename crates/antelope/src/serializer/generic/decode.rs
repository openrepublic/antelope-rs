use thiserror::Error;
use crate::chain::abi::{ABIResolvedType, ABITypeResolver};
use crate::chain::asset::{Asset, ExtendedAsset, Symbol, SymbolCode};
use crate::chain::checksum::{Checksum160, Checksum256, Checksum512};
use crate::chain::name::Name;
use crate::chain::public_key::PublicKey;
use crate::chain::signature::Signature;
use crate::chain::time::{BlockTimestamp, TimePoint, TimePointSec};
use crate::chain::varint::VarUint32;
use crate::serializer::Decoder;
use crate::serializer::generic::value::Value;
use crate::util::Backtraced;

#[derive(Error, Debug)]
pub enum DecodeABITypeError {
    #[error("{0} not found in ABI")]
    ABITypeNotFound(String),

    #[error("Number conversion error: {0}")]
    NumberConversionError(String),

    #[error("Timestamp conversion error: {0}")]
    TimestampConversionError(String),

    #[error("Unknown standard type: {0}")]
    UnknownStandardType(String),

    #[error("Unknown variant index: {0}")]
    UnknownVariantIndex(u32),
}

pub fn decode_abi_type<T: ABITypeResolver>(
    abi: &T,
    field_type: &str,
    buf_size: usize,
    decoder: &mut Decoder,
) -> Result<Value, Backtraced<DecodeABITypeError>> {
    let (field_meta, resolved_type) = abi
        .resolve_type(field_type)
        .ok_or_else(|| DecodeABITypeError::ABITypeNotFound(field_type.to_string()))?;

    match field_meta {
        ABIResolvedType::Standard(std_type) => match std_type.as_str() {
            "bool" => {
                let mut val = 0u8;
                decoder.unpack(&mut val);
                Ok(Value::Bool(val != 0))
            }
            "int8" => { let mut val = 0i8; decoder.unpack(&mut val); Ok(Value::Int8(val)) }
            "int16" => { let mut val = 0i16; decoder.unpack(&mut val); Ok(Value::Int16(val)) }
            "int32" => { let mut val = 0i32; decoder.unpack(&mut val); Ok(Value::Int32(val)) }
            "int64" => { let mut val = 0i64; decoder.unpack(&mut val); Ok(Value::Int64(val)) }
            "int128" => { let mut val = 0i128; decoder.unpack(&mut val); Ok(Value::Int128(val)) }

            "uint8" => { let mut val = 0u8; decoder.unpack(&mut val); Ok(Value::Uint8(val)) }
            "uint16" => { let mut val = 0u16; decoder.unpack(&mut val); Ok(Value::Uint16(val)) }
            "uint32" => { let mut val = 0u32; decoder.unpack(&mut val); Ok(Value::Uint32(val)) }
            "uint64" => { let mut val = 0u64; decoder.unpack(&mut val); Ok(Value::Uint64(val)) }
            "uint128" => { let mut val = 0u128; decoder.unpack(&mut val); Ok(Value::Uint128(val)) }

            "varuint32" => {
                let mut val = VarUint32::default();
                decoder.unpack(&mut val);
                Ok(Value::Uint32(val.n))
            }

            "float32" => {
                let mut val = 0f32;
                decoder.unpack(&mut val);
                Ok(Value::Float32(val))
            }

            "float64" => {
                let mut val = 0f64;
                decoder.unpack(&mut val);
                Ok(Value::Float64(val))
            }

            "bytes" => {
                let mut val: Vec<u8> = Vec::new();
                decoder.unpack(&mut val);
                Ok(Value::Bytes(val))
            }

            "string" => {
                let mut val = String::new();
                decoder.unpack(&mut val);
                Ok(Value::String(val))
            }

            "rd160" | "checksum160" => {
                let mut val = Checksum160::default();
                decoder.unpack(&mut val);
                Ok(Value::String(val.to_string()))
            }

            "sha256" | "checksum256" | "transaction_id" => {
                let mut val = Checksum256::default();
                decoder.unpack(&mut val);
                Ok(Value::String(val.to_string()))
            }

            "checksum512" => {
                let mut val = Checksum512::default();
                decoder.unpack(&mut val);
                Ok(Value::String(val.to_string()))
            }

            "name" | "account_name" => {
                let mut val = Name::default();
                decoder.unpack(&mut val);
                Ok(Value::Name(val.value()))
            }

            "symbol_code" => {
                let mut val = SymbolCode::default();
                decoder.unpack(&mut val);
                Ok(Value::Symbol(val.value()))
            }

            "symbol" => {
                let mut val = Symbol::default();
                decoder.unpack(&mut val);
                Ok(Value::SymbolCode(val.value()))
            }

            "asset" => {
                let mut val = Asset::default();
                decoder.unpack(&mut val);
                Ok(Value::Asset(val.amount(), val.symbol().value()))
            }

            "extended_asset" => {
                let mut val = ExtendedAsset::default();
                decoder.unpack(&mut val);
                Ok(Value::String(val.to_string()))
            }

            "public_key" => {
                let mut val = PublicKey::default();
                decoder.unpack(&mut val);
                Ok(Value::String(val.to_string()))
            }

            "signature" => {
                let mut val = Signature::default();
                decoder.unpack(&mut val);
                Ok(Value::String(val.to_string()))
            }

            "block_timestamp_type" => {
                let mut val = BlockTimestamp::default();
                decoder.unpack(&mut val);
                Ok(Value::String(val.to_string().unwrap_or_else(|| val.slot.to_string())))
            }

            "time_point_sec" => {
                let mut val = TimePointSec::default();
                decoder.unpack(&mut val);
                Ok(Value::String(val.to_string().unwrap_or_else(|| val.seconds.to_string())))
            }

            "time_point" => {
                let mut val = TimePoint::default();
                decoder.unpack(&mut val);
                Ok(Value::String(val.to_string().unwrap_or_else(|| val.elapsed.to_string())))
            }

            _ => Err(DecodeABITypeError::UnknownStandardType(std_type.clone()).into()),
        }

        ABIResolvedType::Optional(_) => {
            let mut flag: u8 = 0;
            decoder.unpack(&mut flag);
            if flag == 1 {
                decode_abi_type(abi, &resolved_type, buf_size, decoder)
            } else {
                Ok(Value::Null)
            }
        }

        ABIResolvedType::Array(_) => {
            let mut len = VarUint32::default();
            decoder.unpack(&mut len);
            let mut items = Vec::with_capacity(len.n as usize);
            for _ in 0..len.n {
                let val = decode_abi_type(abi, &resolved_type, buf_size, decoder)?;
                items.push(val);
            }
            Ok(Value::Array(items))
        }

        ABIResolvedType::Extension(_) => {
            if decoder.get_pos() < buf_size {
                decode_abi_type(abi, &resolved_type, buf_size, decoder)
            } else {
                Ok(Value::Null)
            }
        }

        ABIResolvedType::Struct(struct_meta) => {
            let mut obj = std::collections::HashMap::new();
            for field in &struct_meta.fields {
                let val = decode_abi_type(abi, &field.r#type, buf_size, decoder)?;
                obj.insert(field.name.clone(), val);
            }
            Ok(Value::Struct(obj))
        }

        ABIResolvedType::Variant(variant_types) => {
            let mut index = VarUint32::default();
            decoder.unpack(&mut index);

            let type_name = variant_types
                .types
                .get(index.n as usize)
                .ok_or(DecodeABITypeError::UnknownVariantIndex(index.n))?;

            let value = decode_abi_type(abi, type_name, buf_size, decoder)?;

            match value {
                Value::Struct(map) => {
                    let mut obj = std::collections::HashMap::new();
                    obj.insert("type".to_string(), Value::String(type_name.clone()));
                    for (k, v) in map {
                        obj.insert(k, v);
                    }
                    Ok(Value::Struct(obj))
                },
                _ => Ok(value)
            }
        }
    }
}
