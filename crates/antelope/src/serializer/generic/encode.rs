use thiserror::Error;
use crate::chain::abi::{ABIResolvedType, AbiStruct, ABI};
use crate::chain::asset::{Asset, ExtendedAsset, Symbol, SymbolCode};
use crate::chain::checksum::{Checksum160, Checksum256, Checksum512};
use crate::chain::Decoder;
use crate::chain::name::Name;
use crate::chain::public_key::PublicKey;
use crate::chain::signature::Signature;
use crate::chain::time::{BlockTimestamp, TimePoint, TimePointSec};
use crate::chain::varint::VarUint32;
use crate::serializer::{Encoder, Packer};
use crate::serializer::generic::value::Value;
use crate::util::Backtraced;

/// All the meaningful cases live here, unchanged.
#[derive(Debug, Error)]
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

    #[error("Expected variant obj to have key: {0}")]
    VariantKeyError(String),

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

    #[error("Unexpected Value::Array")]
    UnexpectedArray,

    #[error("Unexpected Value::Null")]
    UnexpectedNull,
}

pub fn encode_abi_type(
    abi: &ABI,
    field_type: &str,
    field_value: &Value,
    encoder: &mut Encoder
) -> Result<usize, Backtraced<EncodeABITypeError>> {
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
                _ => Err(EncodeABITypeError::ValueTypeMismatch("Array".to_string(), field_type.to_string()).into()),
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

    macro_rules! numeric {
        ($val:expr) => {{
            // this expands into exactly the same resolved_type‐match
            match resolved_type.as_str() {
                "int8"    => Ok(($val as i8).pack(encoder)),
                "int16"   => Ok(($val as i16).pack(encoder)),
                "int32"   => Ok(($val as i32).pack(encoder)),
                "int64"   => Ok(($val as i64).pack(encoder)),
                "int128"  => Ok(($val as i128).pack(encoder)),

                "uint8"   => Ok(($val as u8).pack(encoder)),
                "uint16"  => Ok(($val as u16).pack(encoder)),
                "uint32"  => Ok(($val as u32).pack(encoder)),
                "uint64"  => Ok(($val as u64).pack(encoder)),
                "uint128" => Ok(($val as u128).pack(encoder)),

                "varuint32" => Ok(VarUint32::new($val as u32).pack(encoder)),

                "float32" => Ok(($val as f32).pack(encoder)),
                "float64" => Ok(($val as f64).pack(encoder)),

                _ => Err(EncodeABITypeError::NumberConversionError(
                    stringify!($val).to_string(),
                    resolved_type.to_string(),
                )),
            }
        }};
    }

    size += match field_value {
        Value::Bool(val) => Ok(val.pack(encoder)),

        Value::Int8(v)    => numeric!(*v),
        Value::Int16(v)   => numeric!(*v),
        Value::Int32(v)   => numeric!(*v),
        Value::Int64(v)   => numeric!(*v),
        Value::Int128(v)  => numeric!(*v),

        Value::Uint8(v)   => numeric!(*v),
        Value::Uint16(v)  => numeric!(*v),
        Value::Uint32(v)  => numeric!(*v),
        Value::Uint64(v)  => numeric!(*v),
        Value::Uint128(v) => numeric!(*v),

        Value::Float32(v) => numeric!(*v),
        Value::Float64(v) => numeric!(*v),

        Value::Name(v) => Ok(v.pack(encoder)),
        Value::Symbol(v) => Ok(v.pack(encoder)),
        Value::SymbolCode(v) => Ok(v.pack(encoder)),

        Value::Bytes(buf) => Ok(buf.pack(encoder)),
        Value::String(val) => {
            match field_type {
                "string" => Ok(val.pack(encoder)),

                "block_timestamp_type" => {
                    let block_ts = BlockTimestamp::from_time_point_sec(
                        TimePointSec::from_timestamp(val).map_err(|e| EncodeABITypeError::TimestampConversionError(e))?
                    );
                    Ok(block_ts.pack(encoder))
                }

                "time_point" => {
                    let ts = TimePoint::from_timestamp(val.as_str())
                        .map_err(|e| EncodeABITypeError::TimestampConversionError(e))?;
                    Ok(ts.pack(encoder))
                }

                "time_point_sec" => {
                    let ts = TimePointSec::from_timestamp(val.as_str())
                        .map_err(|e| EncodeABITypeError::TimestampConversionError(e))?;
                    Ok(ts.pack(encoder))
                }

                "name" | "account_name" => {
                    let name = Name::from_string(val)
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(name.pack(encoder))
                }

                "symbol_code" => {
                    let scode = SymbolCode::from_string(val)
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(scode.pack(encoder))
                }

                "symbol" => {
                    let sym = Symbol::from_string(val)
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(sym.pack(encoder))
                }

                "asset" => {
                    let asset = Asset::from_string(val)
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(asset.pack(encoder))
                }

                "extended_asset" => {
                    let ex_asset = ExtendedAsset::from_string(val)
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(ex_asset.pack(encoder))
                }

                "checksum160" | "rd160" => {
                    let c = Checksum160::from_hex(val.as_str())
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(c.pack(encoder))
                }

                "checksum256" | "sha256" | "transaction_id" => {
                    let c = Checksum256::from_hex(val.as_str())
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(c.pack(encoder))
                }

                "checksum512" => {
                    let c = Checksum512::from_hex(val.as_str())
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(c.pack(encoder))
                }

                "public_key" => {
                    let key = PublicKey::new_from_str(val.as_str())
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(key.pack(encoder))
                }

                "signature" => {
                    let sig = Signature::from_string(val.as_str())
                        .map_err(|e| EncodeABITypeError::FromStringError(val.clone(), e.to_string()))?;
                    Ok(sig.pack(encoder))
                }

                _ => Err(EncodeABITypeError::FieldTypeMismatch(field_type.to_string(), "Value::String".to_string())),
            }
        }

        Value::Asset(amount, symbol) => Ok(Asset::new(*amount, Symbol::from_value(*symbol)).pack(encoder)),

        Value::Struct(var_map) => match field_meta {
            ABIResolvedType::Variant(variant_types) => {
                let variant_type_val = var_map.get("type")
                    .ok_or_else(|| EncodeABITypeError::VariantKeyError("type".to_string()))?;

                let variant_type = match variant_type_val {
                    Value::String(s) => s.clone(),
                    _ => return Err(EncodeABITypeError::VariantTypeIdError.into()),
                };

                let variant_index = variant_types.types.iter()
                    .position(|v| **v == variant_type)
                    .ok_or_else(|| EncodeABITypeError::VariantTypeNotFound(variant_type.clone()))?;

                size += VarUint32::new(variant_index as u32).pack(encoder);

                Ok(encode_abi_type(abi, &variant_type, field_value, encoder)?)
            }

            ABIResolvedType::Struct(struct_meta) => {
                let mut struct_size = 0;
                for field in &struct_meta.fields {
                    let item = var_map.get(&field.name)
                        .ok_or_else(|| EncodeABITypeError::ObjectMissingField(field.name.clone(), field.r#type.clone()))?;

                    struct_size += encode_abi_type(abi, &field.r#type, item, encoder)?;
                }
                Ok(struct_size)
            }

            _ => Err(EncodeABITypeError::ObjectTypeError),
        },

        Value::Array(_) => Err(EncodeABITypeError::UnexpectedArray),
        Value::Null => Err(EncodeABITypeError::UnexpectedNull),
    }?;

    Ok(size)
}

#[derive(Error, Debug)]
pub enum EncodeParamsError {
    #[error("Expected eosio::setabi::abi param to be of type bytes")]
    ABIEncodingError,

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
) -> Result<Vec<u8>, Backtraced<EncodeParamsError>> {
    let struct_meta: &AbiStruct = abi.structs.iter().find(|s| s.name == *action_name).unwrap();

    let mut size = 0;
    let mut encoder = Encoder::new(0);
    for (i, field_value) in params.iter().enumerate() {
        let field_name = struct_meta.fields.get(i).expect("Field not found").name.clone();

        let field_type: String = struct_meta.fields.iter().find(|f| f.name == field_name)
            .unwrap()
            .r#type.clone();

        if account_name == "eosio" && action_name == "setabi" && field_name == "abi" {
            let abi: ABI = match field_value {
                Value::Bytes(enc_abi_def) => {
                    let mut dec = Decoder::new(enc_abi_def.as_slice());
                    let mut abi = ABI::default();
                    dec.unpack(&mut abi);
                    Ok::<ABI, EncodeParamsError>(abi)
                },
                Value::String(abi_def) => {
                    Ok(ABI::from_string(abi_def).map_err(|_e| EncodeParamsError::ABIEncodingError)?)
                },
                _ => Err(EncodeParamsError::ABIEncodingError)?,
            }?;
            size += abi.pack(&mut encoder);
        }

        size += encode_abi_type(&abi, &field_type, &field_value, &mut encoder)
            .map_err(|e| EncodeParamsError::EncoderError(e.inner))?;
    }
    let encoder_size = encoder.get_size();
    if size != encoder_size {
        return Err(EncodeParamsError::EncoderSizeMismatch(size, encoder_size).into());
    }
    Ok(encoder.get_bytes().to_vec())
}
