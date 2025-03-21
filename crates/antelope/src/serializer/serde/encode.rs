use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use serde_json::Value;
use thiserror::Error;
use crate::chain::abi::{ABIResolvedType, AbiStruct, ABI};
use crate::chain::asset::{Asset, ExtendedAsset, Symbol, SymbolCode};
use crate::chain::checksum::{Checksum160, Checksum256, Checksum512};
use crate::chain::name::Name;
use crate::chain::public_key::PublicKey;
use crate::chain::signature::Signature;
use crate::chain::time::{BlockTimestamp, TimePoint, TimePointSec};
use crate::chain::varint::VarUint32;
use crate::serializer::{Encoder, Packer};

#[derive(Error, Debug)]
pub enum EncodeABITypeError {
    #[error("{0} not found in ABI")]
    ABITypeNotFound(String),

    #[error("Expected Value::{0} but got {1}")]
    ValueTypeMismatch(String, String),

    #[error("Invalid num conversion from {0} to {1}")]
    NumberConversionError(String, String),

    #[error("Base64 encoding issue: {0}")]
    Base64EncodingError(String),

    #[error("Unknown field type {0} for {1}")]
    FieldTypeMismatch(String, String),

    #[error("Timestamp conversion error: {0}")]
    TimestampConversionError(String),

    #[error("{0} from String error: {1}")]
    FromStringError(String, String),

    #[error("{0}")]
    VariantTypeError(String),

    #[error("Expected variant list to have 2 items")]
    VariantSizeError,

    #[error("Expected variant type id to be String")]
    VariantTypeIdError,

    #[error("No matching variant type found for type {0}")]
    VariantTypeNotFound(String),

    #[error("Expected variant value to be decodable into serde_json::Value")]
    VariantValueTypeError,

    #[error("Value::Object missing field {0} of type {1}")]
    ObjectMissingField(String, String),

    #[error("Expected object type for struct")]
    ObjectTypeError,

    #[error("Unexpected Value::Null")]
    UnexpectedNull
}

pub fn encode_abi_type(
    abi: &ABI,
    field_type: &str,
    field_value: &Value,
    encoder: &mut Encoder
) -> Result<usize, EncodeABITypeError> {
    let mut size: usize = 0;

    let (field_meta, resolved_type) = match abi.resolve_type(&field_type) {
        Some(val) => Ok(val),
        None => Err(EncodeABITypeError::ABITypeNotFound(field_type.to_string())),
    }?;

    match field_meta {
        ABIResolvedType::Optional(_) => {
            return match field_value {
                Value::Null => {
                    size += 0u8.pack(encoder);
                    Ok(size)
                }
                _ => {
                    size += 1u8.pack(encoder);
                    size += encode_abi_type(&abi, &resolved_type, field_value, encoder)?;
                    Ok(size)
                }
            }
        }
        ABIResolvedType::Array(_) => {
            return match field_value {
                Value::Array(values) => {
                    size += VarUint32::new(values.len() as u32).pack(encoder);
                    for value in values {
                        size += encode_abi_type(abi, &resolved_type, value, encoder)?;
                    }
                    Ok(size)
                },
                _ => Err(EncodeABITypeError::ValueTypeMismatch("Array".to_string(), field_type.to_string())),
            }
        }
        ABIResolvedType::Extension(_) => {
            return match field_value {
                Value::Null => Ok(0),
                _ => encode_abi_type(abi, &resolved_type, field_value, encoder),
            }
        }
        _ => ()
    };

    size += match field_value {
        Value::Bool(val) => Ok(val.pack(encoder)),
        Value::Number(val) => {
            match resolved_type.as_str() {
                "int8" => {
                    let v: i8 = val.as_i64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as i8;
                    Ok(v.pack(encoder))
                }
                "int16" => {
                    let v: i16 = val.as_i64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as i16;
                    Ok(v.pack(encoder))
                }
                "int32" => {
                    let v: i32 = val.as_i64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as i32;
                    Ok(v.pack(encoder))
                }
                "int64" => {
                    let v: i64 = val.as_i64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))?;
                    Ok(v.pack(encoder))
                }
                "int128" => {
                    let v: i128 = val.as_i128()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))?;
                    Ok(v.pack(encoder))
                }
                "uint8" => {
                    let v: u8 = val.as_u64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as u8;
                    Ok(v.pack(encoder))
                }
                "uint16" => {
                    let v: u16 = val.as_u64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as u16;
                    Ok(v.pack(encoder))
                }
                "uint32" => {
                    let v: u32 = val.as_u64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as u32;
                    Ok(v.pack(encoder))
                }
                "uint64" => {
                    let v: u64 = val.as_u64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))?;
                    Ok(v.pack(encoder))
                }
                "uint128" => {
                    let v: u128 = val.as_u128()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))?;
                    Ok(v.pack(encoder))
                }
                "varuint32" => {
                    let v: u32 = val.as_u64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as u32;
                    let v = VarUint32::new(v);
                    Ok(v.pack(encoder))
                }
                "block_timestamp_type" => {
                    let v: u32 = val.as_u64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as u32;
                    let block_ts = BlockTimestamp::from_time_point_sec(TimePointSec::new(v));
                    Ok(block_ts.pack(encoder))
                }
                "time_point" => {
                    let v: u64 = val.as_u64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))?;
                    Ok(v.pack(encoder))
                }
                "time_point_sec" => {
                    let v: u32 = val.as_u64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as u32;
                    Ok(v.pack(encoder))
                }
                "name" | "account_name" => {
                    let v: u64 = val.as_u64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))?;
                    Ok(v.pack(encoder))
                }
                "float32" => {
                    let v: f32 = val.as_f64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))? as f32;
                    Ok(v.pack(encoder))
                }
                "float64" => {
                    let v: f64 = val.as_f64()
                        .ok_or_else(|| EncodeABITypeError::NumberConversionError(val.to_string(), resolved_type))?;
                    Ok(v.pack(encoder))
                }
                _ => Err(EncodeABITypeError::FieldTypeMismatch(field_type.to_string(), "Value::Number".to_string())),
            }
        }
        Value::String(val) => {
            match field_type {
                "bytes" => {
                    let buf = BASE64_STANDARD.decode(&val)
                        .map_err(|e| EncodeABITypeError::Base64EncodingError(e.to_string()))?;
                    Ok(buf.pack(encoder))
                },
                "string" => {
                    Ok(val.pack(encoder))
                }
                "block_timestamp_type" => {
                    let block_ts = BlockTimestamp::from_time_point_sec(
                        TimePointSec::from_timestamp(val.as_str()).map_err(|e| EncodeABITypeError::TimestampConversionError(e))?);
                    Ok(block_ts.pack(encoder))
                }
                "time_point_sec" => {
                    let ts = TimePointSec::from_timestamp(val.as_str()).map_err(|e| EncodeABITypeError::TimestampConversionError(e))?;
                    Ok(ts.pack(encoder))
                }
                "time_point" => {
                    let ts = TimePoint::from_timestamp(val.as_str()).map_err(|e| EncodeABITypeError::TimestampConversionError(e))?;
                    Ok(ts.pack(encoder))
                }
                "name" | "account_name" => {
                    let name = Name::from_string(val)
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;

                    Ok(name.pack(encoder))
                }
                "symbol_code" => {
                    let scode = SymbolCode::from_string(val)
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;
                    Ok(scode.pack(encoder))
                }
                "symbol" => {
                    let sym = Symbol::from_string(val)
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;
                    Ok(sym.pack(encoder))
                }
                "asset" => {
                    let asset = Asset::from_string(val)
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;
                    Ok(asset.pack(encoder))
                }
                "extended_asset" => {
                    let ex_asset = ExtendedAsset::from_string(val)
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;
                    Ok(ex_asset.pack(encoder))
                }
                "checksum160" | "rd160" => {
                    let c = Checksum160::from_hex(val.as_str())
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;
                    Ok(c.pack(encoder))
                }
                "checksum256" | "sha256" | "transaction_id" => {
                    let c = Checksum256::from_hex(val.as_str())
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;

                    Ok(c.pack(encoder))
                }
                "checksum512" => {
                    let c = Checksum512::from_hex(val.as_str())
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;
                    Ok(c.pack(encoder))
                }
                "public_key" => {
                    let key = PublicKey::new_from_str(val.as_str())
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;
                    Ok(key.pack(encoder))
                }
                "signature" => {
                    let sig = Signature::from_string(val.as_str())
                        .map_err(|_err| EncodeABITypeError::FromStringError(val.clone(), field_type.to_string()))?;
                    Ok(sig.pack(encoder))
                }
                _ => Err(EncodeABITypeError::FieldTypeMismatch(field_type.to_string(), "Value::String".to_string())),
            }
        }
        Value::Array(values) => {
            // If we got here, it might be a variant (encoded as [type, value]),
            // because array handling was done earlier.
            let variant_types = match field_meta {
                ABIResolvedType::Variant(ref v) => v,
                _ => return Err(EncodeABITypeError::VariantTypeError("ABI resolve did not yield variant type...".to_string())),
            };

            if values.len() != 2 {
                return Err(EncodeABITypeError::VariantTypeError("Variant list is not size 2!".to_string()));
            }

            let variant_type: String = values.get(0)
                .ok_or_else(|| EncodeABITypeError::VariantTypeIdError)?
                .as_str()
                .ok_or_else(|| EncodeABITypeError::VariantTypeError("Could not cast serde_json::Value to str".to_string()))?
                .to_string();
            let variant_index = variant_types
                .types
                .iter()
                .position(|var_type_name| **var_type_name == variant_type)
                .ok_or_else(|| EncodeABITypeError::VariantTypeNotFound(variant_type.clone()))?;

            size += VarUint32::new(variant_index as u32).pack(encoder);

            let variant_val  = values.get(1)
                .ok_or_else(|| EncodeABITypeError::VariantValueTypeError)?;
            Ok(encode_abi_type(abi, &variant_type, variant_val, encoder)?)
        }
        Value::Object(obj_map) => {
            return match field_meta {
                ABIResolvedType::Struct(struct_meta) => {
                    let mut struct_size = 0;
                    for field in &struct_meta.fields {
                        let item = obj_map.get(&field.name)
                            .ok_or_else(|| EncodeABITypeError::ObjectMissingField(field.name.clone(), field.r#type.clone()))?;

                        struct_size += encode_abi_type(abi, &field.r#type, item, encoder)?;
                    }
                    Ok(struct_size)
                }
                _ => Err(EncodeABITypeError::ObjectTypeError)
            }
        }
        Value::Null => Err(EncodeABITypeError::UnexpectedNull),
    }?;

    Ok(size)
}

#[derive(Error, Debug)]
pub enum EncodeParamsError {
    #[error("Expected eosio::setabi::abi param to be of type bytes")]
    ABIEncodingError,

    #[error("Base 64 decode error: {0}")]
    Base64DecodeError(String),

    #[error("Encoder size mismatch, got {0} expected {1}")]
    EncoderSizeMismatch(usize, usize),

    #[error("{0}")]
    EncoderError(EncodeABITypeError),
}

pub fn encode_params(
    abi: &ABI,
    account_name: &str,
    action_name: &str,
    params: &Vec<Value>,
) -> Result<Vec<u8>, EncodeParamsError> {
    let struct_meta: &AbiStruct = abi.structs.iter().find(|s| s.name == *action_name).unwrap();

    let mut size = 0;
    let mut encoder = Encoder::new(0);
    for (i, field_value) in params.iter().enumerate() {
        let field_name = struct_meta.fields.get(i).expect("Field not found").name.clone();

        let field_type: String = struct_meta.fields.iter().find(|f| f.name == field_name)
            .unwrap()
            .r#type.clone();

        if account_name == "eosio" && action_name == "setabi" && field_name == "abi" {
            let abi_str = match field_value {
                Value::String(b64_bytes) => {
                    Ok(String::from_utf8(
                        BASE64_STANDARD.decode(b64_bytes)
                            .map_err(|e| EncodeParamsError::Base64DecodeError(e.to_string()))?
                    ).map_err(|_e| EncodeParamsError::ABIEncodingError))?
                }
                _ => Err(EncodeParamsError::ABIEncodingError)?,
            }?;
            let abi = ABI::from_string(&abi_str).map_err(|_e| EncodeParamsError::ABIEncodingError)?;
            size += abi.pack(&mut encoder);
        }

        size += encode_abi_type(&abi, &field_type, &field_value, &mut encoder)
            .map_err(|e| EncodeParamsError::EncoderError(e))?;
    }
    let encoder_size = encoder.get_size();
    if size != encoder_size {
        return Err(EncodeParamsError::EncoderSizeMismatch(size, encoder_size));
    }
    Ok(encoder.get_bytes().to_vec())
}
