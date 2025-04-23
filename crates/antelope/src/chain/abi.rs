use crate::chain::{Decoder, Encoder, Packer};
use antelope_client_macros::StructPacker;
use serde::{Deserialize, Serialize};
use crate::{
    chain::name::{
        serialize_name,
        deserialize_name,
        Name
    },
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
}

impl ABI {
    pub fn from_string(str: &str) -> Result<Self, String> {
        let abi = serde_json::from_str::<ABI>(str)
            .map_err(|e| e.to_string())?;

        Ok(abi)
    }
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

pub trait ABITypeResolver {
    fn resolve_type(&self, str: &str) -> Option<(ABIResolvedType, String)>;
}

pub trait HasNameAndType {
    fn name_str(&self) -> String;
    fn type_str(&self) -> String;
}

pub trait ABIView {
    fn types(&self) -> &[AbiTypeDef];
    fn structs(&self) -> &[AbiStruct];
    fn variants(&self) -> &[AbiVariant];
    fn tables(&self) -> &[impl HasNameAndType]; // generic over ABI and ShipABI table
}

pub fn resolve_type<T: ABIView>(abi: &T, type_name: &str) -> Option<(ABIResolvedType, String)> {
    if STD_TYPES.contains(&type_name) {
        return Some((ABIResolvedType::Standard(type_name.to_string()), type_name.to_string()));
    }

    let mut _type = type_name.to_string();

    // Handle modifiers
    if _type.ends_with("?") {
        _type.pop();
        let (resolved, _) = resolve_type(abi, &_type)?;
        return Some((ABIResolvedType::Optional(Box::new(resolved)), _type));
    }
    if _type.ends_with("[]") {
        _type.truncate(_type.len().saturating_sub(2));
        let (resolved, _) = resolve_type(abi, &_type)?;
        return Some((ABIResolvedType::Array(Box::new(resolved)), _type));
    }
    if _type.ends_with("$") {
        _type.pop();
        let (resolved, _) = resolve_type(abi, &_type)?;
        return Some((ABIResolvedType::Extension(Box::new(resolved)), _type));
    }

    if let Some(type_meta) = abi.types().iter().find(|t| t.new_type_name == type_name) {
        _type = type_meta.r#type.clone();
    }

    if let Some(var_meta) = abi.variants().iter().find(|v| v.name == _type) {
        return Some((ABIResolvedType::Variant(var_meta.clone()), _type));
    }

    if let Some(table) = abi.tables().iter().find(|t| t.name_str() == _type) {
        return resolve_type(abi, &table.type_str());
    }

    if let Some(struct_meta) = abi.structs().iter().find(|s| s.name == _type) {
        let mut expanded_struct = struct_meta.clone();
        if !struct_meta.base.is_empty() {
            if let Some((base_meta, _)) = resolve_type(abi, struct_meta.base.as_str()) {
                if let ABIResolvedType::Struct(base_struct) = base_meta {
                    for field in base_struct.fields.iter().rev() {
                        expanded_struct.fields.insert(0, field.clone());
                    }
                }
            }
        }
        return Some((ABIResolvedType::Struct(expanded_struct), _type));
    }

    None
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
    #[serde(
        serialize_with = "serialize_name",
        deserialize_with = "deserialize_name"
    )]
    pub name: Name,
    pub r#type: String,
    pub ricardian_contract: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize, StructPacker)]
pub struct AbiTable {
    #[serde(
        serialize_with = "serialize_name",
        deserialize_with = "deserialize_name"
    )]
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
    #[serde(
        serialize_with = "serialize_name",
        deserialize_with = "deserialize_name"
    )]
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

impl HasNameAndType for AbiTable {
    fn name_str(&self) -> String { self.name.to_string() }
    fn type_str(&self) -> String { self.r#type.clone() }
}

impl HasNameAndType for ShipAbiTable {
    fn name_str(&self) -> String { self.name.clone() }
    fn type_str(&self) -> String { self.r#type.clone() }
}

impl ABIView for ABI {
    fn types(&self) -> &[AbiTypeDef] { &self.types }
    fn structs(&self) -> &[AbiStruct] { &self.structs }
    fn variants(&self) -> &[AbiVariant] { &self.variants }
    fn tables(&self) -> &[impl HasNameAndType] { &self.tables }
}

impl ABIView for ShipABI {
    fn types(&self) -> &[AbiTypeDef] { &self.types }
    fn structs(&self) -> &[AbiStruct] { &self.structs }
    fn variants(&self) -> &[AbiVariant] { &self.variants }
    fn tables(&self) -> &[impl HasNameAndType] { &self.tables }
}

impl ABITypeResolver for ABI {
    fn resolve_type(&self, type_name: &str) -> Option<(ABIResolvedType, String)> {
        resolve_type(self, type_name)
    }
}

impl ABITypeResolver for ShipABI {
    fn resolve_type(&self, type_name: &str) -> Option<(ABIResolvedType, String)> {
        resolve_type(self, type_name)
    }
}
