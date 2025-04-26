use antelope_client_macros::StructPacker;
use serde::{Deserialize, Serialize};

use crate::{
    chain::name::{deserialize_name, Name},
    serializer::{Decoder, Encoder, Packer, PackerError},
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
    error_messages: Vec<AbiErrorMessage>,
    #[serde(default)]
    abi_extensions: Vec<String>,
    #[serde(default)]
    pub variants: Vec<AbiVariant>,
    #[serde(default)]
    pub action_results: Vec<AbiActionResult>,
    // kv_tables: {}
}

impl ABI {
    pub fn from_string(str: &str) -> Result<Self, String> {
        let mut abi = serde_json::from_str::<ABI>(str).unwrap();
        abi.error_messages = vec![];
        abi.abi_extensions = vec![];
        Ok(abi)
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

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiErrorMessage {
    pub error_code: u64,
    pub error_msg: String,
}

/*
    Ship ABI:

    State history plugin's first message on connection is the "standard" ABI encoded as a
    JSON string, the structure is exactly the same as a ABI encoded in JSON except it
    uses String instead of Name for some values allowing it to have this table definition

    "tables": [
        {
            "name": "account_metadata",
            "type": "account_metadata",
            "key_names": [
                "name"
            ]
        }
    ]

    In an ABI that table entry would fail cause "name" key is of type Name
 */

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct ShipAbiAction {
    pub name: String,
    pub r#type: String,
    pub ricardian_contract: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct ShipAbiTable {
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
pub struct ShipAbiActionResult {
    pub name: Name,
    pub result_type: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct ShipABI {
    pub version: String,
    #[serde(default)]
    pub types: Vec<AbiTypeDef>,
    #[serde(default)]
    pub structs: Vec<AbiStruct>,
    #[serde(default)]
    pub actions: Vec<ShipAbiAction>,
    #[serde(default)]
    pub tables: Vec<ShipAbiTable>,
    #[serde(default)]
    pub ricardian_clauses: Vec<AbiClause>,
    #[serde(default)]
    error_messages: Vec<AbiErrorMessage>,
    #[serde(default)]
    abi_extensions: Vec<String>,
    #[serde(default)]
    pub variants: Vec<AbiVariant>,
    #[serde(default)]
    pub action_results: Vec<ShipAbiActionResult>,
}

impl ShipABI {
    pub fn from_string(str: &str) -> Result<Self, String> {
        let abi = serde_json::from_str::<ShipABI>(str)
            .map_err(|e| e.to_string())?;

        Ok(abi)
    }
}