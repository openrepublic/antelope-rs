use tailcall::tailcall;
use crate::chain::varint::VarUint32;
use crate::packer_error;
use crate::serializer::{
    Packer,
    PackerError,
    packer::Float128,
    vm::{
        isa_impl::common::OpResult,
        Value,
        Instruction,
        Exception,
        PackVM
    }
};

macro_rules! type_mismatch {
    ($expected:expr, $self:ident) => {
        Err(packer_error!("Expected {}, got {}", $expected, &$self.stack[$self.sp]))
    };
}

#[cfg(feature = "debug_vm")]
macro_rules! debug_log {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{
        println!(
            "ip({:4}) sp({:4}) csp({:4}) cnd({:4}) | {:80} | s: {:?}",
            $vm.ip,
            $vm.sp,
            $vm.csp,
            $vm.cndstack.last().unwrap_or(&-1),
            &format!("{}{}", $instr, format_args!($($args)*)),
            $vm.stack.get($vm.sp),
        );
    }};
}

#[cfg(not(feature = "debug_vm"))]
macro_rules! debug_log {
    ($vm:expr, $instr:expr, $($args:tt)*) => {{}};
}

#[inline(always)]
pub fn step(vm: &mut PackVM) -> () {
    vm.ip += 1;
    vm.sp += 1;
}

macro_rules! impl_pack_op {
    ($( ($fname:ident, $variant:ident, $dbg:literal) ),* $(,)?) => {$(
        #[inline(always)]
        pub fn $fname(vm: &mut PackVM) -> OpResult {
            match vm.stack[vm.sp] {
                Value::$variant(v) => {
                    v.pack(&mut vm.encoder);
                    step(vm);
                }
                _ => return type_mismatch!(stringify!($variant), vm),
            }
            debug_log!(vm, $dbg, "()");
            Ok(())
        }
    )*};
}

impl_pack_op!(
    (boolean,  Bool,    "bool"),

    (uint8,    Uint8,   "uint8"),
    (uint16,   Uint16,  "uint16"),
    (uint32,   Uint32,  "uint32"),
    (uint64,   Uint64,  "uint64"),
    (uint128,  Uint128, "uint128"),

    (int8,     Int8,    "int8"),
    (int16,    Int16,   "int16"),
    (int32,    Int32,   "int32"),
    (int64,    Int64,   "int64"),
    (int128,   Int128,  "int128"),

    // IEEE-754 floats
    (float32,  Float32, "float32"),
    (float64,  Float64, "float64"),
);

#[inline(always)]
pub fn varuint32(vm: &mut PackVM) -> OpResult {
    match vm.stack[vm.sp] {
        Value::VarUInt32(v) => {
            VarUint32::new(v).pack(&mut vm.encoder);
            step(vm);
        }
        _ => return type_mismatch!("VarUInt32", vm)
    }
    debug_log!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn float128(vm: &mut PackVM) -> OpResult {
    match vm.stack[vm.sp] {
        Value::Float128(v) => {
            Float128::new(v).pack(&mut vm.encoder);
            step(vm);
        }
        _ => return type_mismatch!("Float128", vm)
    }
    debug_log!(vm, "float128", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes(vm: &mut PackVM) -> OpResult {
    match &vm.stack[vm.sp] {
        Value::Bytes(v) => {
            v.pack(&mut vm.encoder);
            step(vm);
        }
        _ => return type_mismatch!("Bytes", vm)
    }
    debug_log!(vm, "bytes", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes_raw(vm: &mut PackVM, len: u8) -> OpResult {
    match &vm.stack[vm.sp] {
        Value::Bytes(v) => {
            if len > 0 && v.len() != len as usize {
                return Err(packer_error!("Raw bytes fixed size mistmatch: {} != {}", v.len(), len))
            }
            let target = vm.encoder.alloc(v.len());
            target.copy_from_slice(v);
            step(vm);
        }
        _ => return type_mismatch!("Bytes", vm)
    }
    debug_log!(vm, "bytes_raw", "({})", len);
    Ok(())
}

#[inline(always)]
pub fn optional(vm: &mut PackVM, stride: u8) -> OpResult {
    match &vm.stack[vm.sp] {
        Value::None => {
            0u8.pack(&mut vm.encoder);      // marker
            vm.sp += 1;                     // pop the None
            vm.ip += stride as usize + 1;   // jump over wrapped code
            debug_log!(vm, "optional none", "({})", stride);
        }
        _ => {
            1u8.pack(&mut vm.encoder);      // marker
            vm.ip += 1;                     // execute wrapped code next
            debug_log!(vm, "optional some", "({})", stride);
        }
    }
    Ok(())
}

#[inline(always)]
pub fn extension(vm: &mut PackVM, stride: u8) -> OpResult {
    match vm.stack.get(vm.sp) {
        Some(Value::None) => {
            vm.sp += 1;                         // pop the sentinel
            vm.ip += stride as usize + 1;       // jump over wrapped code
            debug_log!(vm, "extension none", "({})", stride);
        }

        Some(_) => {
            vm.ip += 1;
            debug_log!(vm, "extension", "({})", stride);
        }

        None => {
            vm.ip += stride as usize + 1;       // skip wrapped code
            debug_log!(vm, "extension stack empty", "({})", stride);
        }
    }
    Ok(())
}

#[inline(always)]
pub fn pushcnd(vm: &mut PackVM) -> OpResult {
    match vm.stack[vm.sp] {
        Value::Condition(cnd) => {
            vm.cndstack.push(cnd);
            vm.csp += 1;
            step(vm);
            VarUint32::new(cnd as u32).pack(&mut vm.encoder);
        }
        _ => return type_mismatch!("Condition", vm)
    }
    debug_log!(vm, "pushcnd", "io -> ({})", vm.cndstack[vm.cndstack.len() - 1]);
    Ok(())
}

#[inline(always)]
pub fn popcnd(vm: &mut PackVM) -> OpResult {
    vm.cndstack.pop();
    vm.csp -= 1;
    vm.ip += 1;
    debug_log!(vm, "popcnd", "()");
    Ok(())
}

pub fn jmp(vm: &mut PackVM, ptr: usize) -> OpResult {
    vm.ip = ptr;
    debug_log!(vm, "jmp", "({})", ptr);
    Ok(())
}

#[inline(always)]
pub fn jmpcnd(vm: &mut PackVM, target: usize, value: isize, delta: isize) -> OpResult {
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
pub fn jmpnotcnd(vm: &mut PackVM, target: usize, value: isize, delta: isize) -> OpResult {
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
pub fn raise(vm: &PackVM, e: &Exception) -> OpResult {
    debug_log!(
        vm,
        "raise",
        "({:?})", e
    );
    Err(packer_error!("raise exception: {:?}", e))
}

#[inline(always)]
#[cfg_attr(feature = "debug_vm", allow(unused_variables))]
pub fn exit(vm: &mut PackVM, status: u8) -> Result<u8, PackerError> {
    debug_log!(
        vm,
        "exit",
        "({})", status
    );
    Ok(status)
}

#[tailcall]
pub fn exec(vm: &mut PackVM, _z: ()) -> Result<u8, PackerError> {
    match &vm.program[vm.ip] {
        Instruction::Bool => { boolean(vm)?; exec(vm, _z) }

        Instruction::UInt(1) => { uint8(vm)?; exec(vm, _z) }
        Instruction::UInt(2) => { uint16(vm)?; exec(vm, _z) }
        Instruction::UInt(4) => { uint32(vm)?; exec(vm, _z) }
        Instruction::UInt(8) => { uint64(vm)?; exec(vm, _z) }
        Instruction::UInt(16) => { uint128(vm)?; exec(vm, _z) }

        Instruction::Int(1) => { int8(vm)?; exec(vm, _z) }
        Instruction::Int(2) => { int16(vm)?; exec(vm, _z) }
        Instruction::Int(4) => { int32(vm)?; exec(vm, _z) }
        Instruction::Int(8) => { int64(vm)?; exec(vm, _z) }
        Instruction::Int(16) => { int128(vm)?; exec(vm, _z) }

        Instruction::VarUInt => { varuint32(vm)?; exec(vm, _z) }
        // Instruction::VarInt => unreachable!(),

        Instruction::Float(4) => { float32(vm)?; exec(vm, _z) }
        Instruction::Float(8) => { float64(vm)?; exec(vm, _z) }
        Instruction::Float(16) => { float128(vm)?; exec(vm, _z) }

        Instruction::Bytes => { bytes(vm)?; exec(vm, _z) }
        Instruction::BytesRaw(l) => { bytes_raw(vm, *l)?; exec(vm, _z) }

        Instruction::Optional(s) => { optional(vm, *s)?; exec(vm, _z) }
        Instruction::Extension(s) => { extension(vm, *s)?; exec(vm, _z) }

        Instruction::PushCND => { pushcnd(vm)?; exec(vm, _z) }
        Instruction::PopCND => { popcnd(vm)?; exec(vm, _z) }
        Instruction::Jmp(ptr) => { jmp(vm, *ptr)?; exec(vm, _z) }
        Instruction::JmpCND(t, v, d) => { jmpcnd(vm, *t, *v, *d)?; exec(vm, _z) }
        Instruction::JmpNotCND(t, v, d) => { jmpnotcnd(vm, *t, *v, *d)?; exec(vm, _z) }
        Instruction::Raise(e) => { raise(vm, e)?; exec(vm, _z) }
        Instruction::Exit(s) => { exit(vm, *s) }
        _ => unreachable!()
    }
}