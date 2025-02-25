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

pub enum ABIResolvedType {
    Variant(AbiVariant),
    Struct(AbiStruct),
}

impl ABI {
    pub fn from_string(str: &str) -> Result<Self, String> {
        let mut abi = serde_json::from_str::<ABI>(str).unwrap();
        abi.error_messages = vec![];
        abi.abi_extensions = vec![];
        Ok(abi)
    }

    pub fn resolve_type(&self, type_name: &str) -> Option<ABIResolvedType> {
        // _type will change as type_name gets resolved
        let mut _type = type_name.to_string();

        // is type alias?
        let maybe_type_meta = self.types.iter().find(|t| t.new_type_name == type_name);
        if let Some(type_meta) = maybe_type_meta {
            _type = type_meta.r#type.clone();
        }

        // is variant?
        let maybe_var_meta = self.variants.iter().find(|v| v.name == _type);
        if maybe_var_meta.is_some() {
            return Some(ABIResolvedType::Variant(maybe_var_meta.unwrap().clone()));
        }

        // is struct?
        let maybe_struct_meta = self.structs.iter().find(|s| s.name == _type);
        match maybe_struct_meta {
            Some(struct_meta) => {
                Some(ABIResolvedType::Struct(struct_meta.clone()))
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
    #[serde(deserialize_with = "deserialize_name")]
    pub name: Name,
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
