use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde_json::{Map, Number, Value};
use thiserror::Error;
use crate::chain::abi::{ABIResolvedType, ABI};
use crate::chain::asset::{Asset, ExtendedAsset, Symbol, SymbolCode};
use crate::chain::checksum::{Checksum160, Checksum256, Checksum512};
use crate::chain::name::Name;
use crate::chain::public_key::PublicKey;
use crate::chain::signature::Signature;
use crate::chain::time::{BlockTimestamp, TimePoint, TimePointSec};
use crate::chain::varint::VarUint32;
use crate::serializer::Decoder;

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

pub fn decode_abi_type(
    abi: &ABI,
    field_type: &str,
    buf_size: usize,
    decoder: &mut Decoder
) -> Result<Value, DecodeABITypeError> {
    let (field_meta, resolved_type) = match abi.resolve_type(&field_type) {
        Some(val) => Ok(val),
        None => Err(DecodeABITypeError::ABITypeNotFound(field_type.to_string())),
    }?;

    match field_meta {
        ABIResolvedType::Standard(std_type) => {
            match std_type.as_str() {
                "bool" => {
                    let mut val = 0u8;
                    decoder.unpack(&mut val);

                    Ok(Value::Bool(val == 1u8))
                }
                "int8" => {
                    let mut val = 0i8;
                    decoder.unpack(&mut val);

                    Ok(Value::Number(Number::from(val)))
                }
                "int16" => {
                    let mut val = 0i16;
                    decoder.unpack(&mut val);

                    Ok(Value::Number(Number::from(val)))
                }
                "int32" => {
                    let mut val = 0i32;
                    decoder.unpack(&mut val);

                    Ok(Value::Number(Number::from(val)))
                }
                "int64" => {
                    let mut val = 0i64;
                    decoder.unpack(&mut val);

                    Ok(Value::Number(Number::from(val)))
                }
                "int128" => {
                    let mut val = 0i128;
                    decoder.unpack(&mut val);

                    let num = match Number::from_i128(val) {
                        None => Err(DecodeABITypeError::NumberConversionError(format!("{} is not a number", val.to_string()))),
                        Some(num) => Ok(num),
                    }?;

                    Ok(Value::Number(num))
                }
                "uint8" => {
                    let mut val = 0u8;
                    decoder.unpack(&mut val);

                    Ok(Value::Number(Number::from(val)))
                }
                "uint16" => {
                    let mut val = 0u16;
                    decoder.unpack(&mut val);

                    Ok(Value::Number(Number::from(val)))
                }
                "uint32" => {
                    let mut val = 0u32;
                    decoder.unpack(&mut val);

                    Ok(Value::Number(Number::from(val)))
                }
                "uint64" => {
                    let mut val = 0u64;
                    decoder.unpack(&mut val);

                    Ok(Value::Number(Number::from(val)))
                }
                "uint128" => {
                    let mut val = 0u128;
                    decoder.unpack(&mut val);

                    let num = match Number::from_u128(val) {
                        None => Err(DecodeABITypeError::NumberConversionError(format!("{} is not a number", val.to_string()))),
                        Some(num) => Ok(num),
                    }?;

                    Ok(Value::Number(num))
                }
                "varuint32" => {
                    let mut val = VarUint32::default();
                    decoder.unpack(&mut val);

                    Ok(Value::Number(Number::from(val.n)))
                }
                "float32" => {
                    let mut val = 0f32;
                    decoder.unpack(&mut val);

                    let num = match Number::from_f64(val as f64) {
                        None => Err(DecodeABITypeError::NumberConversionError(format!("{} is not a valid f32", val.to_string()))),
                        Some(num) => Ok(num),
                    }?;

                    Ok(Value::Number(num))
                }
                "float64" => {
                    let mut val = 0f64;
                    decoder.unpack(&mut val);

                    let num = match Number::from_f64(val) {
                        None => Err(DecodeABITypeError::NumberConversionError(format!("{} is not a valid f64", val.to_string()))),
                        Some(num) => Ok(num),
                    }?;

                    Ok(Value::Number(num))
                }
                "bytes" => {
                    let mut val: Vec<u8> = Vec::new();
                    decoder.unpack(&mut val);

                    Ok(Value::String(BASE64_STANDARD.encode(&val)))
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

                    Ok(Value::String(val.to_string()))
                }
                "symbol_code" => {
                    let mut val = SymbolCode::default();
                    decoder.unpack(&mut val);

                    Ok(Value::String(val.to_string()))
                }
                "symbol" => {
                    let mut val = Symbol::default();
                    decoder.unpack(&mut val);

                    Ok(Value::String(val.to_string()))
                }
                "asset" => {
                    let mut val = Asset::default();
                    decoder.unpack(&mut val);

                    Ok(Value::String(val.to_string()))
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

                    let time_str = val.to_string()
                        .ok_or_else(|| DecodeABITypeError::TimestampConversionError(format!("block timestamp slot: {}", val.slot)))?;

                    Ok(Value::String(time_str))
                }
                "time_point_sec" => {
                    let mut val = TimePointSec::default();
                    decoder.unpack(&mut val);

                    let time_str = val.to_string()
                        .ok_or_else(|| DecodeABITypeError::TimestampConversionError(format!("time point sec: {}", val.seconds)))?;

                    Ok(Value::String(time_str))
                }
                "time_point" => {
                    let mut val = TimePoint::default();
                    decoder.unpack(&mut val);

                    let time_str = val.to_string()
                        .ok_or_else(|| DecodeABITypeError::TimestampConversionError(format!("time point: {}", val.elapsed)))?;

                    Ok(Value::String(time_str))
                }
                _ => Err(DecodeABITypeError::UnknownStandardType(format!("Unknown standard type {}", field_type)))
            }
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
            let mut len = VarUint32::new(0);
            decoder.unpack(&mut len);

            let mut list = Vec::new();
            for _ in 0..len.n {
                let result = decode_abi_type(abi, &resolved_type, buf_size, decoder)?;
                list.push(result);
            }
            Ok(Value::Array(list))
        }
        ABIResolvedType::Extension(_) => {
            if decoder.get_pos() < buf_size {
                let result = decode_abi_type(abi, &resolved_type, buf_size, decoder)?;
                return Ok(result);
            }
            Ok(Value::Null)
        }
        ABIResolvedType::Variant(inner) => {
            let mut vindex = VarUint32::new(0);
            decoder.unpack(&mut vindex);

            let var_type: &String = inner.types.get(vindex.n as usize)
                .ok_or_else(|| DecodeABITypeError::UnknownVariantIndex(vindex.n))?;

            let mut list = Vec::new();
            list.push(Value::String(var_type.clone()));
            list.push(decode_abi_type(abi, &var_type, buf_size, decoder)?);
            Ok(Value::Array(list))
        }
        ABIResolvedType::Struct(inner) => {
            let mut obj_map: Map<String, Value> = Map::new();
            for field in &inner.fields {
                let result = decode_abi_type(abi, &field.r#type, buf_size, decoder)?;
                obj_map.insert(field.name.clone(), result);
            }
            Ok(Value::Object(obj_map))
        }
    }
}
