use tailcall::tailcall;
use crate::serializer::vm::isa::{Instruction, Value};
use crate::serializer::{Encoder, PackerError};
use crate::serializer::vm::isa_impl::{
    boolean,
    uint8, uint16, uint32, uint64, uint128,
    int8, int16, int32, int64, int128,
    varuint32,
    float32, float64, float128,
    bytes, bytes_raw,
    optional,
    extension,
    pushcnd, popcnd,
    jmp, jmpcnd, jmpnotcnd,
    raise, exit
};

pub struct PackVM {
    pub(crate) ip:  usize,
    pub(crate) sp:  usize,
    pub(crate) csp: usize,

    pub(crate) stack:      Vec<Value>,
    pub(crate) cndstack:   Vec<isize>,

    pub(crate) encoder: Encoder,

    pub(crate) program: Vec<Instruction>
}

impl Default for PackVM {
    fn default() -> Self {
        Self {
            ip: 0,
            sp: 0,
            csp: 0,

            stack: Vec::new(),
            cndstack: vec![0],

            encoder: Encoder::new(0),

            program: Vec::new(),
        }
    }
}

#[tailcall]
fn exec(vm: &mut PackVM, _z: ()) -> Result<u8, PackerError> {
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

impl PackVM {

    pub fn new(stack: Vec<Value>) -> Self {
        let mut vm = PackVM::default();
        vm.stack = stack;
        vm
    }

    /// advance ip and sp by one — the single most-typed line in every handler
    #[inline(always)]
    pub(crate) fn step(&mut self) {
        self.ip += 1;
        self.sp += 1;
    }

    pub fn pack(&mut self, program: &[Instruction]) -> Result<Vec<u8>, PackerError> {
        self.program = program.to_vec();
        exec(self, ())?;                                 // <-- tail-recursion starts here
        Ok(self.encoder.get_bytes().to_vec())
    }
}