use crate::serializer::vm::isa::{Instruction, Value};
use crate::serializer::{Decoder, Encoder, PackerError};
use crate::serializer::vm::isa_impl::{pack, unpack};

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

impl PackVM {
    pub fn run(
        program: &[Instruction],
        stack: &[Value]
    ) -> Result<Vec<u8>, PackerError> {
        let mut vm = PackVM::default();
        vm.program = program.to_vec();
        vm.stack = stack.to_vec();

        pack::exec(&mut vm, ())?;

        Ok(vm.encoder.get_bytes().to_vec())
    }
}

pub struct UnpackVM {
    pub(crate) ip:  usize,
    pub(crate) csp: usize,

    pub(crate) stack: Vec<Value>,
    pub(crate) cndstack:   Vec<isize>,

    pub(crate) program: Vec<Instruction>
}

impl Default for UnpackVM {
    fn default() -> Self {
        Self {
            ip: 0,
            csp: 0,

            stack: Vec::new(),
            cndstack: vec![0],

            program: Vec::new(),
        }
    }
}

impl UnpackVM {
    pub fn run(
        program: &[Instruction],
        buffer: &[u8]
    ) -> Result<Vec<Value>, PackerError> {
        let mut vm = UnpackVM::default();
        vm.program = program.to_vec();

        let mut decoder = Decoder::new(buffer);

        unpack::exec(&mut vm, &mut decoder)?;

        Ok(vm.stack)
    }
}
