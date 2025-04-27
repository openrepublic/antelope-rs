use tailcall::tailcall;
use crate::chain::varint::VarUint32;
use crate::packer_error;
use crate::serializer::{
    Decoder,
    PackerError,
    packer::Float128,
    vm::{
        isa_impl::common::OpResult,
        Value,
        Instruction,
        Exception,
        UnpackVM
    }
};

#[cfg(feature = "debug_vm")]
macro_rules! debug_log {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{
        println!(
            "ip({:4}) sp({:4}) csp({:4}) cnd({:4}) | {:80} | s: {:?}",
            $vm.ip,
            $vm.stack.len(),
            $vm.csp,
            $vm.cndstack.last().unwrap_or(&-1),
            &format!("{}{}", $instr, format_args!($($args)*)),
            $vm.stack.last(),
        );
    }};
}

#[cfg(not(feature = "debug_vm"))]
macro_rules! debug_log {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{}};
}

#[inline(always)]
pub fn step(vm: &mut UnpackVM) -> () {
    vm.ip += 1;
}

macro_rules! impl_unpack_op {
    ($( ($fname:ident, $ty:ty, $variant:ident, $dbg:literal) ),* $(,)?) => {$(
        #[inline(always)]
        pub fn $fname(vm: &mut UnpackVM, decoder: &mut Decoder) -> OpResult {
            let mut val: $ty = Default::default();
            decoder.unpack(&mut val)?;

            vm.stack.push(Value::$variant(val));

            step(vm);
            debug_log!(vm, $dbg, "()");
            Ok(())
        }
    )*};
}

impl_unpack_op!(
    (boolean, bool,     Bool,    "bool"),

    (uint8,   u8,       Uint8,   "uint8"),
    (uint16,  u16,      Uint16,  "uint16"),
    (uint32,  u32,      Uint32,  "uint32"),
    (uint64,  u64,      Uint64,  "uint64"),
    (uint128, u128,     Uint128, "uint128"),

    (int8,    i8,       Int8,    "int8"),
    (int16,   i16,      Int16,   "int16"),
    (int32,   i32,      Int32,   "int32"),
    (int64,   i64,      Int64,   "int64"),
    (int128,  i128,     Int128,  "int128"),

    (float32, f32,      Float32, "float32"),
    (float64, f64,      Float64, "float64"),
);

#[inline(always)]
pub fn varuint32(vm: &mut UnpackVM, decoder: &mut Decoder) -> OpResult {
    let mut val: VarUint32 = Default::default();
    decoder.unpack(&mut val)?;
    vm.stack.push(Value::VarUInt32(val.n));
    step(vm);
    debug_log!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn float128(vm: &mut UnpackVM, decoder: &mut Decoder) -> OpResult {
    let mut val: Float128 = Default::default();
    decoder.unpack(&mut val)?;
    vm.stack.push(Value::Float128(val.data));
    step(vm);
    debug_log!(vm, "float128", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes(vm: &mut UnpackVM, decoder: &mut Decoder) -> OpResult {
    let mut val: Vec<u8> = Default::default();
    decoder.unpack(&mut val)?;
    vm.stack.push(Value::Bytes(val));
    step(vm);
    debug_log!(vm, "bytes", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes_raw(vm: &mut UnpackVM, len: u8, decoder: &mut Decoder) -> OpResult {
    let raw = decoder.unpack_raw(len as usize)?;
    vm.stack.push(Value::Bytes(raw.to_vec()));
    step(vm);
    debug_log!(vm, "bytes_raw", "({})", len);
    Ok(())
}

#[inline(always)]
pub fn optional(vm: &mut UnpackVM, stride: u8, decoder: &mut Decoder) -> OpResult {
    let mut flag: u8 = Default::default();
    decoder.unpack(&mut flag)?;
    if flag == 1 {
        vm.ip += 1;
        debug_log!(vm, "optional some", "({})", stride);
    } else {
        vm.stack.push(Value::None);
        vm.ip += stride as usize + 1;
        debug_log!(vm, "optional none", "({})", stride);
    }
    Ok(())
}

#[inline(always)]
pub fn extension(vm: &mut UnpackVM, stride: u8, decoder: &mut Decoder) -> OpResult {
    if decoder.reached_end() {
        vm.stack.push(Value::None);
        vm.ip += stride as usize + 1;
        debug_log!(vm, "extension stack empty", "({})", stride);
    } else {
        vm.ip += 1;
        debug_log!(vm, "extension", "({})", stride);
    }
    Ok(())
}

#[inline(always)]
pub fn pushcnd(vm: &mut UnpackVM, decoder: &mut Decoder) -> OpResult {
    let mut cnd = VarUint32::default();
    decoder.unpack(&mut cnd)?;
    let cnd = cnd.n as isize;
    vm.stack.push(Value::Condition(cnd));
    vm.cndstack.push(cnd);
    vm.csp += 1;
    step(vm);
    debug_log!(vm, "pushcnd", "io -> ({})", cnd);
    Ok(())
}

#[inline(always)]
pub fn popcnd(vm: &mut UnpackVM) -> OpResult {
    vm.cndstack.pop();
    vm.csp -= 1;
    vm.ip += 1;
    debug_log!(vm, "popcnd", "()");
    Ok(())
}

pub fn jmp(vm: &mut UnpackVM, ptr: usize) -> OpResult {
    vm.ip = ptr;
    debug_log!(vm, "jmp", "({})", ptr);
    Ok(())
}

#[inline(always)]
pub fn jmpcnd(vm: &mut UnpackVM, target: usize, value: isize, delta: isize) -> OpResult {
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
    Ok(())
}

#[inline(always)]
pub fn jmpnotcnd(vm: &mut UnpackVM, target: usize, value: isize, delta: isize) -> OpResult {
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
    Ok(())
}

#[inline(always)]
#[cfg_attr(feature = "debug_vm", allow(unused_variables))]
pub fn raise(vm: &UnpackVM, e: &Exception) -> OpResult {
    debug_log!(
        vm,
        "raise",
        "({:?})", e
    );
    Err(packer_error!("raise exception: {:?}", e))
}

#[inline(always)]
#[cfg_attr(feature = "debug_vm", allow(unused_variables))]
pub fn exit(vm: &mut UnpackVM, status: u8) -> Result<u8, PackerError> {
    debug_log!(
        vm,
        "exit",
        "({})", status
    );
    Ok(status)
}

#[tailcall]
pub fn exec(vm: &mut UnpackVM, decoder: &mut Decoder) -> Result<u8, PackerError> {
    match &vm.program[vm.ip] {
        Instruction::Bool => { boolean(vm, decoder)?; exec(vm, decoder) }

        Instruction::UInt(1) => { uint8(vm, decoder)?; exec(vm, decoder) }
        Instruction::UInt(2) => { uint16(vm, decoder)?; exec(vm, decoder) }
        Instruction::UInt(4) => { uint32(vm, decoder)?; exec(vm, decoder) }
        Instruction::UInt(8) => { uint64(vm, decoder)?; exec(vm, decoder) }
        Instruction::UInt(16) => { uint128(vm, decoder)?; exec(vm, decoder) }

        Instruction::Int(1) => { int8(vm, decoder)?; exec(vm, decoder) }
        Instruction::Int(2) => { int16(vm, decoder)?; exec(vm, decoder) }
        Instruction::Int(4) => { int32(vm, decoder)?; exec(vm, decoder) }
        Instruction::Int(8) => { int64(vm, decoder)?; exec(vm, decoder) }
        Instruction::Int(16) => { int128(vm, decoder)?; exec(vm, decoder) }

        Instruction::VarUInt => { varuint32(vm, decoder)?; exec(vm, decoder) }
        // Instruction::VarInt => unreachable!(),

        Instruction::Float(4) => { float32(vm, decoder)?; exec(vm, decoder) }
        Instruction::Float(8) => { float64(vm, decoder)?; exec(vm, decoder) }
        Instruction::Float(16) => { float128(vm, decoder)?; exec(vm, decoder) }

        Instruction::Bytes => { bytes(vm, decoder)?; exec(vm, decoder) }
        Instruction::BytesRaw(l) => { bytes_raw(vm, *l, decoder)?; exec(vm, decoder) }

        Instruction::Optional(s) => { optional(vm, *s, decoder)?; exec(vm, decoder) }
        Instruction::Extension(s) => { extension(vm, *s, decoder)?; exec(vm, decoder) }

        Instruction::PushCND => { pushcnd(vm, decoder)?; exec(vm, decoder) }
        Instruction::PopCND => { popcnd(vm)?; exec(vm, decoder) }
        Instruction::Jmp(ptr) => { jmp(vm, *ptr)?; exec(vm, decoder) }
        Instruction::JmpCND(t, v, d) => { jmpcnd(vm, *t, *v, *d)?; exec(vm, decoder) }
        Instruction::JmpNotCND(t, v, d) => { jmpnotcnd(vm, *t, *v, *d)?; exec(vm, decoder) }
        Instruction::Raise(e) => { raise(vm, e)?; exec(vm, decoder) }
        Instruction::Exit(s) => { exit(vm, *s) }
        _ => unreachable!()
    }
}