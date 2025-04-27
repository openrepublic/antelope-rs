use serde::Serialize;
use serde_json::from_str;
use antelope::chain::abi::{ShipABI, ABI};
use antelope::chain::binary_extension::BinaryExtension;
use antelope::chain::name::Name;
use antelope::name;
use antelope::serializer::{
    Encoder, Decoder, Packer, PackerError,
    vm::{
        PackVM,
        Value,
        IOStackValue,
        IntoIOStack,
        compile_program
    }
};
use antelope_client_macros::{EnumPacker, StackEnum, StackStruct, StructPacker};

const STDABI: &str = include_str!("std_abi.json");
const TESTABI: &str = include_str!("test_abi.json");

macro_rules! pack_value_and_assert {
    ($type_name:expr, $value:expr, $expected:expr) => {
        let abi: ShipABI = from_str(STDABI).expect("failed to parse ABI JSON");
        let program = compile_program(&abi, $type_name)
            .expect(&format!("No instruction sequence for {}", $type_name));
        let encoded = PackVM::run(&program, $value).expect("Pack failed");
        assert_eq!(encoded, $expected);
    };
}
#[test]
fn test_pack_bool() {
    pack_value_and_assert!("bool", &[Value::Bool(true)], &[1u8]);
    pack_value_and_assert!("bool", &[Value::Bool(false)], &[0u8]);
}

#[test]
fn test_pack_uints() {
    pack_value_and_assert!("uint8", &[Value::Uint8(0x12)], &[0x12]);
    pack_value_and_assert!("uint16", &[Value::Uint16(0x1234)], &[0x34, 0x12]);
    pack_value_and_assert!("uint32", &[Value::Uint32(0x12345678)], &[0x78, 0x56, 0x34, 0x12]);
    pack_value_and_assert!("uint64", &[Value::Uint64(0x1234567890abcdef)], &[0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12]);
    pack_value_and_assert!("uint128", &[Value::Uint128(0x112233445566778899aabbccddeeff00u128)], &0x112233445566778899aabbccddeeff00u128.to_le_bytes());
}

#[test]
fn test_pack_ints() {
    pack_value_and_assert!("int8", &[Value::Int8(-1)], &[0xff]);
    pack_value_and_assert!("int16", &[Value::Int16(-2)], &[0xfe, 0xff]);
    pack_value_and_assert!("int32", &[Value::Int32(-3)], &[0xfd, 0xff, 0xff, 0xff]);
    pack_value_and_assert!("int64", &[Value::Int64(-4)], &[0xfc, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    pack_value_and_assert!("int128", &[Value::Int128(-5)], &(-5i128).to_le_bytes());
}

#[test]
fn test_pack_varuint32() {
    pack_value_and_assert!("varuint32", &[Value::VarUInt32(0x7F)], &[0x7F]);
    pack_value_and_assert!("varuint32", &[Value::VarUInt32(0x80)], &[0x80, 0x01]);
}

#[test]
fn test_pack_floats() {
    pack_value_and_assert!("float32", &[Value::Float32(1.0f32)], &1.0f32.to_le_bytes());
    pack_value_and_assert!("float64", &[Value::Float64(2.0f64)], &2.0f64.to_le_bytes());
    pack_value_and_assert!("float128", &[Value::Float128([1u8; 16])], &[1u8; 16]);
}

#[test]
fn test_pack_bytes() {
    let mut enc = Encoder::new(0);
    let raw = vec![1u8, 2u8, 3u8];
    raw.pack(&mut enc);
    pack_value_and_assert!(
        "bytes",
        &[Value::Bytes(raw)],
        enc.get_bytes()
    );
}

#[test]
fn test_pack_string() {
    let mut enc = Encoder::new(0);
    "abc".to_string().pack(&mut enc);
    pack_value_and_assert!(
        "string",
        &[Value::Bytes(vec![b'a', b'b', b'c'])],
        enc.get_bytes()
    );
}

#[test]
fn test_pack_longname() {
    let mut enc = Encoder::new(0);
    let name = Name::new_from_str("testlongname");
    name.pack(&mut enc);
    pack_value_and_assert!("name", &[Value::Uint64(name.value())], enc.get_bytes());
}

#[test]
fn test_pack_shortname() {
    let mut enc = Encoder::new(0);
    let name = Name::new_from_str("eosio");
    name.pack(&mut enc);
    pack_value_and_assert!("name", &[Value::Uint64(name.value())], enc.get_bytes());
}

#[test]
fn test_pack_array() {
    let mut enc = Encoder::new(0);
    let actual: Vec<u32> = vec![1, 2];
    actual.pack(&mut enc);
    pack_value_and_assert!(
        "uint32[]",
        &[Value::Condition(2), Value::Uint32(1), Value::Uint32(2)],
        enc.get_bytes()
    );
}

#[test]
fn test_pack_option() {
    let mut enc = Encoder::new(0);
    Some(1u32).pack(&mut enc);
    pack_value_and_assert!("uint32?", &[Value::Uint32(1)], enc.get_bytes());

    let mut enc = Encoder::new(0);
    None::<u32>.pack(&mut enc);
    pack_value_and_assert!("uint32?", &[Value::None], enc.get_bytes());
}

#[test]
fn test_pack_extension() {
    let mut enc = Encoder::new(0);
    BinaryExtension::new(Some(1u32)).pack(&mut enc);
    pack_value_and_assert!("uint32$", &[Value::Uint32(1)], enc.get_bytes());

    let mut enc = Encoder::new(0);
    BinaryExtension::<u32>::new(None).pack(&mut enc);
    pack_value_and_assert!("uint32$", &[Value::None], enc.get_bytes());

    let empty: [u8; 0] = [];
    pack_value_and_assert!("uint32$", &[], &empty);
}

#[test]
fn test_pack_struct() {
    #[derive(Serialize, PartialEq, Debug, EnumPacker, StackEnum)]
    enum TestEnum {
        Type0(u64),
        Type1(f64),
        Type2(String),
    }

    #[derive(Serialize, PartialEq, Debug, StructPacker, StackStruct)]
    struct TestStruct {
        field0: bool,
        field1: u32,
        field2: i32,
        field3: f32,
        field4: Vec<String>,
        field5: Option<Vec<u8>>,
        field6: TestEnum,
        field7: bool,
        field8: u32,
        field9: i32,
        field10: f32,
        field11: Option<String>,
        field12: Option<Vec<u8>>,
        field13: Option<Name>,
        field_end0: BinaryExtension<Name>,
        field_end1: BinaryExtension<Name>,
    }

    let mut enc = Encoder::new(0);
    let test = TestStruct {
        field0: true,
        field1: 420,
        field2: 420,
        field3: 42.0,
        field4: vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string(),
            "fourth".to_string(),
        ],
        field5: Some(vec![1, 2, 3, 4, 5]),
        field6: TestEnum::Type2("type2".to_string()),
        field7: false,
        field8: 69,
        field9: 69,
        field10: 6.9,
        field11: Some("IADJIASJDAJSD".to_string()),
        field12: Some("afsafasfasf".as_bytes().to_vec()),
        field13: None,
        field_end0: BinaryExtension::<Name>::new(Some(name!("eosio"))),
        field_end1: BinaryExtension::<Name>::new(None),
    };
    test.pack(&mut enc);

    let stack: Vec<Value> = test.to_stack();

    for value in stack.iter().enumerate() {
        println!("{:?}", value);
    }


    let abi: ABI = from_str(TESTABI).expect("failed to parse ABI JSON");
    let program = compile_program(&abi, "test_struct")
        .expect("No instruction sequence for test_struct");

    for op in program.iter().enumerate() {
        println!("{:?}", op);
    }

    let encoded = PackVM::run(&program, &stack).expect("Pack failed");
    assert_eq!(encoded, enc.get_bytes());
}
