use crate::chain::{Decoder, Encoder, Packer};
use antelope_client_macros::StructPacker;
use serde::{Deserialize, Serialize};

use crate::{
    chain::name::{deserialize_name, Name},
    // serializer::{Decoder, Encoder, Packer},
};

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct ABI {
    pub version: String,
    #[serde(default)]
    pub types: Vec<AbiTypeDef>,
    #[serde(default)]
    pub structs: Vec<AbiStruct>,
    #[serde(default)]
    pub actions: Vec<AbiAction>,
    #[serde(default)]
    pub tables: Vec<AbiTable>,
    #[serde(default)]
    pub ricardian_clauses: Vec<AbiClause>,
    #[serde(default)]
    error_messages: Vec<String>,
    #[serde(default)]
    abi_extensions: Vec<String>,
    #[serde(default)]
    pub variants: Vec<AbiVariant>,
    #[serde(default)]
    pub action_results: Vec<AbiActionResult>,
    // kv_tables: {}
}

#[derive(Debug, Clone)]
pub enum ABIResolvedType {
    Standard(String),
    Variant(AbiVariant),
    Struct(AbiStruct),
    Optional(Box<ABIResolvedType>),
    Array(Box<ABIResolvedType>),
    Extension(Box<ABIResolvedType>),
}

pub const STD_TYPES: [&str; 33] = [
    "bool",

    "int8",
    "int16",
    "int32",
    "int64",
    "int128",

    "uint8",
    "uint16",
    "uint32",
    "uint64",
    "uint128",

    "varuint32",

    "float32",
    "float64",

    "bytes",
    "string",

    "rd160",
    "sha256",
    "checksum160",
    "checksum256",
    "checksum512",

    "transaction_id",

    "name",
    "account_name",

    "symbol_code",
    "symbol",
    "asset",
    "extended_asset",

    "public_key",
    "signature",

    "block_timestamp_type",
    "time_point",
    "time_point_sec",

];

impl ABI {
    pub fn from_string(str: &str) -> Result<Self, String> {
        let mut abi = serde_json::from_str::<ABI>(str).unwrap();
        abi.error_messages = vec![];
        abi.abi_extensions = vec![];
        Ok(abi)
    }

    pub fn resolve_type(&self, type_name: &str) -> Option<(ABIResolvedType, String)> {
        // Given an ABI type as a string process its modifiers (?, [], $), resolve
        // type aliases, and find struct or variant, the second value returned is
        // the type resolved without its modifiers.

        // is type part of std types?
        if STD_TYPES.contains(&type_name) {
            return Some((ABIResolvedType::Standard(type_name.to_string()), type_name.to_string()));
        }

        // _type will change as type_name gets resolved
        let mut _type = type_name.to_string();

        // is optional?
        if _type.ends_with("?") {
            _type.pop();
            let (resolved, _) = self.resolve_type(&_type)?;
            return Some((ABIResolvedType::Optional(Box::from(resolved)), _type));
        }

        // is array?
        if _type.ends_with("[]") {
            _type.truncate(_type.len().saturating_sub(2));
            let (resolved, _) = self.resolve_type(&_type)?;
            return Some((ABIResolvedType::Array(Box::from(resolved)), _type));
        }

        // is extension?
        if _type.ends_with("$") {
            _type.pop();
            let (resolved, _) = self.resolve_type(&_type)?;
            return Some((ABIResolvedType::Extension(Box::from(resolved)), _type));
        }

        // is type alias?
        let maybe_type_meta = self.types.iter().find(|t| t.new_type_name == type_name);
        if let Some(type_meta) = maybe_type_meta {
            _type = type_meta.r#type.clone();
        }

        // is variant?
        let maybe_var_meta = self.variants.iter().find(|v| v.name == _type);
        if let Some(var_meta) = maybe_var_meta {
            return Some((ABIResolvedType::Variant(var_meta.clone()), _type));
        }

        // is table?
        let maybe_table_meta = self.tables.iter().find(|t| t.name == _type);
        if let Some(table_meta) = maybe_table_meta {
            return Some(self.resolve_type(&table_meta.r#type)?);
        }

        // is struct?
        let maybe_struct_meta = self.structs.iter().find(|s| s.name == _type);
        match maybe_struct_meta {
            Some(struct_meta) => {
                let mut expanded_struct = struct_meta.clone();
                if !struct_meta.base.is_empty() {
                    // recursive solve base
                    match self.resolve_type(struct_meta.base.as_str()) {
                        Some((base_meta, _)) => {
                            match base_meta {
                                ABIResolvedType::Struct(base_struct) => {
                                    for base_field in base_struct.fields.iter().rev() {
                                        expanded_struct.fields.insert(0, base_field.clone());
                                    }
                                }
                                _ => ()
                            }
                        },
                        None => ()
                    }
                }
                Some((ABIResolvedType::Struct(expanded_struct), _type))
            },
            None => None
        }
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiTypeDef {
    pub new_type_name: String,
    pub r#type: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiField {
    pub name: String,
    pub r#type: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiStruct {
    pub name: String,
    #[serde(default)]
    pub base: String,
    pub fields: Vec<AbiField>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiVariant {
    pub name: String,
    pub types: Vec<String>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiAction {
    #[serde(deserialize_with = "deserialize_name")]
    pub name: Name,
    pub r#type: String,
    pub ricardian_contract: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiTable {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub index_type: String,
    #[serde(default)]
    pub key_names: Vec<String>,
    #[serde(default)]
    pub key_types: Vec<String>,
    pub r#type: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiClause {
    pub id: String,
    pub body: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiActionResult {
    #[serde(deserialize_with = "deserialize_name")]
    pub name: Name,
    pub result_type: String,
}
