use crate::chain::varint::VarUint32;
use crate::packer_error;
use crate::serializer::vm::isa::{Exception, Instruction, Value};
use crate::serializer::{Encoder, Packer, PackerError};
use crate::serializer::packer::Float128;

macro_rules! type_mismatch {
    ($expected:expr, $self:ident) => {
        Err(packer_error!("Expected {}, got {}", $expected, &$self.stack[$self.sp]))
    };
}

#[cfg(feature = "debug_vm")]
macro_rules! debug_log {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{
        println!(
            "ip({:4}) sp({:4}) csp({:4}) cnd({:4}) | instr: {:32} {:?} | s: {:?}",
            $vm.ip,
            $vm.sp,
            $vm.csp,
            $vm.cndstack.last().unwrap_or(&-1),
            $instr,
            format_args!($($args)*),
            $vm.stack.get($vm.sp),
        );
    }};
}

#[cfg(not(feature = "debug_vm"))]
macro_rules! debug_log {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{}};
}

pub struct PackVM {
    ip:  usize,
    sp:  usize,
    csp: usize,

    stack:      Vec<Value>,
    cndstack:   Vec<isize>,

    encoder: Encoder,
}

impl Default for PackVM {
    fn default() -> Self {
        Self {
            ip: 0,
            sp: 0,
            csp: 0,

            stack: Vec::new(),
            cndstack: vec![0],

            encoder: Encoder::new(0)
        }
    }
}
/// Nominal wrapper that breaks the type-alias recursion
#[derive(Copy, Clone)]
pub struct Code<'a>(&'a [Handler]);

/// A boxed, 'static, re-usable handler closure
type Handler = Box<dyn Fn(&mut PackVM, Code) -> Result<u8, PackerError> + 'static>;

fn boolean() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Bool(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Bool", vm)
        }
        debug_log!(vm, "bool", "()");
        code.0[vm.ip](vm, code)
    })
}

fn uint8() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Uint8(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Uint8", vm)
        }
        debug_log!(vm, "uint8", "()");
        code.0[vm.ip](vm, code)
    })
}

fn uint16() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Uint16(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Uint16", vm)
        }
        debug_log!(vm, "uint16", "()");
        code.0[vm.ip](vm, code)
    })
}

fn uint32() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Uint32(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Uint32", vm)
        }
        debug_log!(vm, "uint32", "()");
        code.0[vm.ip](vm, code)
    })
}

fn uint64() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Uint64(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Uint64", vm)
        }
        debug_log!(vm, "uint64", "()");
        code.0[vm.ip](vm, code)
    })
}

fn uint128() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Uint128(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Uint128", vm)
        }
        debug_log!(vm, "uint128", "()");
        code.0[vm.ip](vm, code)
    })
}

fn int8() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Int8(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Int8", vm)
        }
        debug_log!(vm, "int8", "()");
        code.0[vm.ip](vm, code)
    })
}

fn int16() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Int16(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Int16", vm)
        }
        debug_log!(vm, "int16", "()");
        code.0[vm.ip](vm, code)
    })
}

fn int32() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Int32(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Int32", vm)
        }
        debug_log!(vm, "int32", "()");
        code.0[vm.ip](vm, code)
    })
}

fn int64() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Int64(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Int64", vm)
        }
        debug_log!(vm, "int64", "()");
        code.0[vm.ip](vm, code)
    })
}

fn int128() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Int128(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Int128", vm)
        }
        debug_log!(vm, "int128", "()");
        code.0[vm.ip](vm, code)
    })
}

fn varuint32() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::VarUInt32(v) => {
                VarUint32::new(v).pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("VarUInt32", vm)
        }
        debug_log!(vm, "varuint32", "()");
        code.0[vm.ip](vm, code)
    })
}

fn float32() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Float32(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Float32", vm)
        }
        debug_log!(vm, "float32", "()");
        code.0[vm.ip](vm, code)
    })
}

fn float64() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Float64(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Float64", vm)
        }
        debug_log!(vm, "float64", "()");
        code.0[vm.ip](vm, code)
    })
}

fn float128() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Float128(v) => {
                Float128::new(v).pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Float128", vm)
        }
        debug_log!(vm, "float128", "()");
        code.0[vm.ip](vm, code)
    })
}

fn bytes() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match &vm.stack[vm.sp] {
            Value::Bytes(v) => {
                v.pack(&mut vm.encoder);
                vm.step();
            }
            _ => return type_mismatch!("Bytes", vm)
        }
        debug_log!(vm, "bytes", "()");
        code.0[vm.ip](vm, code)
    })
}

fn bytes_raw(len: u8) -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match &vm.stack[vm.sp] {
            Value::Bytes(v) => {
                if len > 0 && v.len() != len as usize {
                    return Err(packer_error!("Raw bytes fixed size mistmatch: {} != {}", v.len(), len))
                }
                let target = vm.encoder.alloc(v.len());
                target.copy_from_slice(v);
                vm.step();
            }
            _ => return type_mismatch!("Bytes", vm)
        }
        debug_log!(vm, "bytes_raw", "({})", len);
        code.0[vm.ip](vm, code)
    })
}

fn optional(stride: u8) -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match &vm.stack[vm.sp] {
            Value::None => {
                0u8.pack(&mut vm.encoder);      // marker
                vm.sp += 1;                     // pop the None
                vm.ip += stride as usize + 1;   // jump over wrapped code
            }
            _ => {
                1u8.pack(&mut vm.encoder);      // marker
                vm.ip += 1;                     // execute wrapped code next
                /*  ───────── NO stack change ─────────
                 *  the wrapped handler(s) still need the
                 *  actual value currently on top-of-stack
                 */
            }
        }
        debug_log!(vm, "optional", "({})", stride);
        code.0[vm.ip](vm, code)
    })
}

fn extension(stride: u8) -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack.get(vm.sp) {
            Some(Value::None) => {
                0u8.pack(&mut vm.encoder);          // marker
                vm.sp += 1;                         // pop the sentinel
                vm.ip += stride as usize + 1;       // jump over wrapped code
            }

            Some(_) => {
                1u8.pack(&mut vm.encoder);          // marker
                vm.ip += 1;                         // execute wrapped code next
            }

            None => {
                // no flag byte, behaviour identical to old VM
                vm.ip += stride as usize + 1;       // skip wrapped code
            }
        }
        debug_log!(vm, "extension", "({})", stride);
        code.0[vm.ip](vm, code)
    })
}

fn pushcnd() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        match vm.stack[vm.sp] {
            Value::Condition(cnd) => {
                vm.cndstack.push(cnd);
                vm.csp += 1;
                vm.step();
            }
            _ => return type_mismatch!("Condition", vm)
        }
        debug_log!(vm, "pushcnd", "io -> ({})", vm.cndstack[vm.cndstack.len() - 1]);
        code.0[vm.ip](vm, code)
    })
}

fn popcnd() -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        vm.cndstack.pop();
        vm.csp -= 1;
        vm.ip += 1;
        debug_log!(vm, "popcnd", "()");
        code.0[vm.ip](vm, code)
    })
}

fn jmp(ptr: usize) -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        vm.ip = ptr;
        debug_log!(vm, "jmp", "({})", ptr);
        code.0[ptr](vm, code)
    })
}

fn jmpcnd(target: usize, value: isize, delta: isize) -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        /* fast-path: update the running counter */
        {
            vm.cndstack[vm.csp] += delta;
            if vm.cndstack[vm.csp] == value {
                vm.ip = target;       // branch taken
                debug_log!(
                    vm,
                    "jmpcnd",
                    "(t: {}, v: {}, d: {}) triggered", target, value, delta
                );
            } else {
                vm.ip += 1;           // fall-through
                debug_log!(
                    vm,
                    "jmpcnd",
                    "(t: {}, v: {}, d: {})", target, value, delta
                );
            }
        }
        code.0[vm.ip](vm, code)
    })
}

/// Jump *if current condition != `value`*
fn jmpnotcnd(target: usize, value: isize, delta: isize) -> Handler {
    Box::new(move |vm: &mut PackVM, code: Code| {
        {
            vm.cndstack[vm.csp] += delta;
            if vm.cndstack[vm.csp] != value {
                vm.ip = target;       // branch taken
                debug_log!(
                    vm,
                    "jmpnotcnd",
                    "(t: {}, v: {}, d: {}) triggered", target, value, delta
                );
            } else {
                vm.ip += 1;           // fall-through
                debug_log!(
                    vm,
                    "jmpnotcnd",
                    "(t: {}, v: {}, d: {})", target, value, delta
                );
            }
        }
        code.0[vm.ip](vm, code)        // tail-call
    })
}

fn raise(e: Exception) -> Handler {
    Box::new(move |vm: &mut PackVM, _code: Code| {
        debug_log!(
            vm,
            "raise",
            "({:?})", e
        );
        Err(packer_error!("raise exception: {:?}", e))
    })
}

fn exit(status: u8) -> Handler {
    Box::new(move |vm: &mut PackVM, _code: Code| {
        debug_log!(
            vm,
            "exit",
            "({})", status
        );
        Ok(status)
    })
}

impl Instruction {
    pub fn to_handler(&self) -> Handler {
        match self {
            Instruction::Bool => boolean(),
            Instruction::UInt(size) => {
                match size {
                    1 => uint8(),
                    2 => uint16(),
                    4 => uint32(),
                    8 => uint64(),
                    16 => uint128(),
                    _ => unreachable!(),
                }
            }
            Instruction::Int(size) => {
                match size {
                    1 => int8(),
                    2 => int16(),
                    4 => int32(),
                    8 => int64(),
                    16 => int128(),
                    _ => unreachable!(),
                }
            }
            Instruction::VarUInt => varuint32(),
            Instruction::VarInt => unreachable!(),
            Instruction::Float(size) => {
                match size {
                    4 => float32(),
                    8 => float64(),
                    16 => float128(),
                    _ => unreachable!(),
                }
            }
            Instruction::Bytes => bytes(),
            Instruction::BytesRaw(len) => bytes_raw(*len),
            Instruction::Optional(stride) => optional(*stride),
            Instruction::Extension(stride) => extension(*stride),
            Instruction::PushCND => pushcnd(),
            Instruction::PopCND => popcnd(),
            Instruction::Jmp(ptr) => jmp(*ptr),
            Instruction::JmpCND(t, v, d) => jmpcnd(*t, *v, *d),
            Instruction::JmpNotCND(t, v, d) => jmpnotcnd(*t, *v, *d),
            Instruction::Raise(e) => raise(e.clone()),
            Instruction::Exit(code) => exit(*code)
        }
    }
}

impl PackVM {

    pub fn new(stack: Vec<Value>) -> Self {
        let mut vm = PackVM::default();
        vm.stack = stack;
        vm
    }

    /// advance ip and sp by one — the single most-typed line in every handler
    #[inline(always)]
    fn step(&mut self) {
        self.ip += 1;
        self.sp += 1;
    }

    pub fn pack(&mut self, program: &[Instruction]) -> Result<Vec<u8>, PackerError> {
        let handlers: Vec<Handler> = program.iter()
            .map(|op| op.to_handler())
            .collect();

        let code = Code(&handlers);            // wrapper slice
        (handlers[0])(self, code)?;

        Ok(self.encoder.get_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::abi::ABI;
    use serde_json::from_str;
    use crate::chain::asset::Asset;
    use crate::chain::name::Name;
    use crate::chain::public_key::PublicKey;
    use crate::serializer::vm::compiler::compile_program;

    const EOSIO_JSON: &str = include_str!("eosio.json");
    const TEST_JSON: &str = include_str!("test.json");

    #[test]
    fn test_custom_type_var_0() {
        let abi: ABI = from_str(TEST_JSON).expect("failed to parse ABI JSON");

        let program = compile_program(&abi, "test_types")
            .expect("failed to compile type");

        let bigfloat: [u8; 16] = [
            6, 9, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 4, 2, 0,
        ];

        let quanitity = Asset::from_string("420.6900 TLOS");

        let stack: Vec<Value> = vec![
            Value::Condition(0),
            Value::Bool(true),
            69u8.into(),
            69u16.into(),
            69u32.into(),
            69u64.into(),
            69u128.into(),
            (-69i8).into(),
            (-69i16).into(),
            (-69i32).into(),
            (-69i64).into(),
            (-69i128).into(),
            Value::VarUInt32(420u32),
            4.20f32.into(),
            4.20f64.into(),
            Value::Float128(bigfloat),
            Name::new_from_str("eosio").value().into(),
            Value::Bytes(bigfloat.to_vec()),
            Value::Bytes("this is a test".as_bytes().to_vec()),
            Value::Condition(3),
            42u32.into(),
            42u32.into(),
            42u32.into(),
            Value::None,
            Name::new_from_str("eosio").value().into(),
            // asset
            quanitity.amount().into(),
            quanitity.symbol().value().into(),
        ];

        let mut vm = PackVM::new(stack);

        let result = vm.pack(&program)
            .expect("failed to pack value");

        println!("{:?}", result);
    }

    #[test]
    fn test_custom_type_var_1() {
        let abi: ABI = from_str(TEST_JSON).expect("failed to parse ABI JSON");

        let program = compile_program(&abi, "test_types")
            .expect("failed to compile type");

        let bigfloat: [u8; 16] = [
            6, 9, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 4, 2, 0,
        ];

        let quanitity = Asset::from_string("420.6900 TLOS");

        let stack: Vec<Value> = vec![
            Value::Condition(1),
            Value::Bool(true),
            69u8.into(),
            69u16.into(),
            69u32.into(),
            69u64.into(),
            69u128.into(),
            (-69i8).into(),
            (-69i16).into(),
            (-69i32).into(),
            (-69i64).into(),
            (-69i128).into(),
            Value::VarUInt32(420u32),
            4.20f32.into(),
            4.20f64.into(),
            Value::Float128(bigfloat),
            Name::new_from_str("eosio").value().into(),
            Value::Bytes(bigfloat.to_vec()),
            Value::Bytes("this is a test".as_bytes().to_vec()),
            Value::Condition(3),
            42u32.into(),
            42u32.into(),
            42u32.into(),
            Value::None,
            // sub fields
            Name::new_from_str("eosio").value().into(),
            Value::Bytes(bigfloat.to_vec()),
            Value::Bool(false)
        ];

        let mut vm = PackVM::new(stack);

        let result = vm.pack(&program)
            .expect("failed to pack value");

        println!("{:?}", result);
    }

    #[test]
    fn test_pack_voter_info() {
        let abi: ABI = from_str(EOSIO_JSON).expect("failed to parse ABI JSON");
        let mut encoder = Encoder::new(0);
        let pkey = PublicKey::default();
        pkey.pack(&mut encoder);
        let pkey_bytes = encoder.get_bytes().to_vec();

        let program = compile_program(&abi, "variant_block_signing_authority_v0")
            .expect("failed to compile type");

        let stack = vec![
            Value::Condition(0),
            420u32.into(),
            Value::Condition(1),
            Value::Bytes(pkey_bytes),
            69u16.into(),
        ];

        let mut vm = PackVM::new(stack);

        let result = vm.pack(&program)
            .expect("failed to pack value");

        println!("{:?}", result);
    }
}
