use crate::chain::varint::VarUint32;
use crate::packer_error;
use crate::serializer::{Packer, PackerError};
use crate::serializer::packer::Float128;
use crate::serializer::vm::{Exception, PackVM, Value};

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

pub type PackOpResult = Result<(), PackerError>;

#[inline(always)]
pub fn boolean(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Bool(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Bool", vm)
    }
    debug_log!(vm, "bool", "()");
    Ok(())
}

#[inline(always)]
pub fn uint8(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Uint8(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Uint8", vm)
    }
    debug_log!(vm, "uint8", "()");
    Ok(())
}

#[inline(always)]
pub fn uint16(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Uint16(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Uint16", vm)
    }
    debug_log!(vm, "uint16", "()");
    Ok(())
}

#[inline(always)]
pub fn uint32(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Uint32(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Uint32", vm)
    }
    debug_log!(vm, "uint32", "()");
    Ok(())
}

#[inline(always)]
pub fn uint64(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Uint64(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Uint64", vm)
    }
    debug_log!(vm, "uint64", "()");
    Ok(())
}

#[inline(always)]
pub fn uint128(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Uint128(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Uint128", vm)
    }
    debug_log!(vm, "uint128", "()");
    Ok(())
}

#[inline(always)]
pub fn int8(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Int8(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Int8", vm)
    }
    debug_log!(vm, "int8", "()");
    Ok(())
}

#[inline(always)]
pub fn int16(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Int16(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Int16", vm)
    }
    debug_log!(vm, "int16", "()");
    Ok(())
}

#[inline(always)]
pub fn int32(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Int32(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Int32", vm)
    }
    debug_log!(vm, "int32", "()");
    Ok(())
}

#[inline(always)]
pub fn int64(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Int64(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Int64", vm)
    }
    debug_log!(vm, "int64", "()");
    Ok(())
}

#[inline(always)]
pub fn int128(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Int128(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Int128", vm)
    }
    debug_log!(vm, "int128", "()");
    Ok(())
}

#[inline(always)]
pub fn varuint32(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::VarUInt32(v) => {
            VarUint32::new(v).pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("VarUInt32", vm)
    }
    debug_log!(vm, "varuint32", "()");
    Ok(())
}

#[inline(always)]
pub fn float32(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Float32(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Float32", vm)
    }
    debug_log!(vm, "float32", "()");
    Ok(())
}

#[inline(always)]
pub fn float64(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Float64(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Float64", vm)
    }
    debug_log!(vm, "float64", "()");
    Ok(())
}

#[inline(always)]
pub fn float128(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Float128(v) => {
            Float128::new(v).pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Float128", vm)
    }
    debug_log!(vm, "float128", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes(vm: &mut PackVM) -> PackOpResult {
    match &vm.stack[vm.sp] {
        Value::Bytes(v) => {
            v.pack(&mut vm.encoder);
            vm.step();
        }
        _ => return type_mismatch!("Bytes", vm)
    }
    debug_log!(vm, "bytes", "()");
    Ok(())
}

#[inline(always)]
pub fn bytes_raw(vm: &mut PackVM, len: u8) -> PackOpResult {
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
    Ok(())
}

#[inline(always)]
pub fn optional(vm: &mut PackVM, stride: u8) -> PackOpResult {
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
pub fn extension(vm: &mut PackVM, stride: u8) -> PackOpResult {
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
pub fn pushcnd(vm: &mut PackVM) -> PackOpResult {
    match vm.stack[vm.sp] {
        Value::Condition(cnd) => {
            vm.cndstack.push(cnd);
            vm.csp += 1;
            vm.step();
            VarUint32::new(cnd as u32).pack(&mut vm.encoder);
        }
        _ => return type_mismatch!("Condition", vm)
    }
    debug_log!(vm, "pushcnd", "io -> ({})", vm.cndstack[vm.cndstack.len() - 1]);
    Ok(())
}

#[inline(always)]
pub fn popcnd(vm: &mut PackVM) -> PackOpResult {
    vm.cndstack.pop();
    vm.csp -= 1;
    vm.ip += 1;
    debug_log!(vm, "popcnd", "()");
    Ok(())
}

pub fn jmp(vm: &mut PackVM, ptr: usize) -> PackOpResult {
    vm.ip = ptr;
    debug_log!(vm, "jmp", "({})", ptr);
    Ok(())
}

#[inline(always)]
pub fn jmpcnd(vm: &mut PackVM, target: usize, value: isize, delta: isize) -> PackOpResult {
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
pub fn jmpnotcnd(vm: &mut PackVM, target: usize, value: isize, delta: isize) -> PackOpResult {
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
pub fn raise(vm: &PackVM, e: &Exception) -> PackOpResult {
    #[allow(unused_variables)]
    debug_log!(
        vm,
        "raise",
        "({:?})", e
    );
    Err(packer_error!("raise exception: {:?}", e))
}

#[inline(always)]
pub fn exit(vm: &mut PackVM, status: u8) -> Result<u8, PackerError> {
    #[allow(unused_variables)]
    debug_log!(
        vm,
        "exit",
        "({})", status
    );
    Ok(status)
}