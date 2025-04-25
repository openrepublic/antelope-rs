use crate::chain::varint::VarUint32;
use crate::packer_error;
use crate::serializer::vm::isa::{Instruction, Value};
use crate::serializer::{Encoder, Packer, PackerError};
use crate::serializer::packer::Float128;

#[derive(Debug)]
pub struct PackerVM {
    // instruction ptr
    ip: usize,

    // io stack
    stack: Vec<Value>,
    sp: usize,

    // cnd stack
    cndstack: Vec<isize>,
}

impl Default for PackerVM {
    fn default() -> Self {
        Self {
            ip: 0,

            stack: Vec::new(),
            sp: 0,

            cndstack: vec![0],
        }
    }
}

impl PackerVM {

    pub fn new(stack: Vec<Value>) -> Self {
        let mut vm = PackerVM::default();
        vm.stack = stack;
        vm
    }

    #[inline(always)]
    fn stack_top(&self) -> &Value {
        &self.stack[self.sp]
    }

    fn debug_log(&self, msg: &str) {
        println!(
            "ip({:3}), sp({:3}), cnd({:3}) | {:32} | {:?}",
            self.ip, self.sp, self.cndstack.get(self.cndstack.len() - 1).unwrap(),
            msg,
            self.stack.get(self.sp)
        );
    }

    #[inline(always)]
    fn run_jmp(&mut self, target: usize) -> Result<(), PackerError> {
        let prev_ip = self.ip;
        self.ip = target;
        self.debug_log(&format!("jmp {} -> {}", prev_ip, self.ip));
        Ok(())
    }

    #[inline(always)]
    fn run_pushcnd(&mut self) -> Result<(), PackerError> {
        match self.stack_top() {
            Value::Condition(cnd) => {
                self.cndstack.push(*cnd);
                self.ip += 1;
                self.sp += 1;
                self.debug_log("push cnd");
                Ok(())
            }
            _ => Err(packer_error!("Expected Value::Condition but got {}", &self.stack[self.sp]))
        }
    }

    #[inline(always)]
    fn run_popcnd(&mut self) -> Result<(), PackerError> {
        self.cndstack.pop();
        self.ip += 1;
        self.debug_log("pop cnd");
        Ok(())
    }

    #[inline(always)]
    fn run_jmpcnd(&mut self, target: usize, value: isize, delta: isize) -> Result<(), PackerError> {
        let cnd = self.cndstack.last_mut().unwrap();
        *cnd += delta;
        if *cnd == value {
            self.ip = target;
            self.debug_log(&format!("jmp cnd triggered: {}, {}, {}", target, value, delta));
            return Ok(());
        }
        self.ip += 1;
        self.debug_log(&format!("jmp cnd: {}, {}, {}", target, value, delta));
        Ok(())
    }

    #[inline(always)]
    fn run_jmpnotcnd(&mut self, target: usize, value: isize, delta: isize) -> Result<(), PackerError> {
        let cnd = self.cndstack.last_mut().unwrap();
        *cnd += delta;
        if *cnd != value {
            self.ip = target;
            self.debug_log(&format!("jmp not cnd triggered: {}, {}, {}", target, value, delta));
            return Ok(());
        }
        self.ip += 1;
        self.debug_log(&format!("jmp not cnd: {}, {}, {}", target, value, delta));
        Ok(())
    }

    pub fn pack(
        &mut self,
        program: &Vec<Instruction>
    ) -> Result<Vec<u8>, PackerError> {
        for (i, op) in program.iter().enumerate() {
            println!("{}: {:?}", i, op);
        }
        self.debug_log("Running pack program:");

        let mut encoder = Encoder::new(0);

        while self.ip < program.len() {
            match &program[self.ip] {
                Instruction::Bool => {
                    match &self.stack[self.sp] {
                        Value::Bool(val) => {
                            val.pack(&mut encoder);
                            self.sp += 1;
                            self.ip += 1;
                            self.debug_log("packed bool");
                            Ok(())
                        },
                        _ => Err(packer_error!("Expected Value::Bool but got {}", &self.stack[self.sp]))
                    }
                }
                Instruction::UInt(len) => {
                    match &self.stack[self.sp] {
                        Value::Int(buf, signed) => {
                            if *signed {
                                return Err(packer_error!("Expected Value::Int to be unsigned"));
                            }
                            if *len as usize != buf.len() {
                                return Err(packer_error!("Expected Value::Int to be of size {} but is {}", len, buf.len()));
                            }
                            let len = *len as usize;
                            match len {
                                1 => Ok(buf[0].pack(&mut encoder)),
                                2 => Ok(u16::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                4 => Ok(u32::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                8 => Ok(u64::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                16 => Ok(u128::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                _ => Err(packer_error!("Expected Value::Int to be of size {} but is {}", len, buf.len()))
                            }?;
                            self.sp += 1;
                            self.ip += 1;
                            self.debug_log("packed uint");
                            Ok(())
                        },
                        _ => Err(packer_error!("Expected Value::UInt but got {}", &self.stack[self.sp]))
                    }
                }
                Instruction::Int(len) => {
                    match &self.stack[self.sp] {
                        Value::Int(buf, signed) => {
                            if !*signed {
                                return Err(packer_error!("Expected Value::Int to be signed"));
                            }
                            if *len as usize != buf.len() {
                                return Err(packer_error!("Expected Value::Int to be of size {} but is {}", len, buf.len()));
                            }
                            match len {
                                1 => Ok((buf[0] as i8).pack(&mut encoder)),
                                2 => Ok(i16::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                4 => Ok(i32::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                8 => Ok(i64::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                16 => Ok(i128::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                _ => Err(packer_error!("Expected Value::Int to be of size {} but is {}", len, buf.len()))
                            }?;
                            self.sp += 1;
                            self.ip += 1;
                            self.debug_log("packed int");
                            Ok(())
                        },
                        _ => Err(packer_error!("Expected Value::Int but got {}", &self.stack[self.sp]))
                    }
                }
                Instruction::VarUInt => {
                    match &self.stack[self.sp] {
                        Value::Int(buf, signed) => {
                            if *signed {
                                return Err(packer_error!("Expected Value::Int to be unsigned"));
                            }
                            if buf.len() != 4 {
                                return Err(packer_error!("Expected Value::Int to be of size 4 but is {}", buf.len()));
                            }
                            let num = u32::from_le_bytes(buf.as_slice().try_into().unwrap());
                            VarUint32::new(num).pack(&mut encoder);
                            self.sp += 1;
                            self.ip += 1;
                            self.debug_log("packed varuint");
                            Ok(())
                        },
                        _ => Err(packer_error!("Expected Value::UInt but got {}", &self.stack[self.sp]))
                    }
                }
                Instruction::VarInt => {
                    Err(packer_error!("DataOp::VarInt32 not implemented!"))
                }
                Instruction::Float(len) => {
                    match &self.stack[self.sp] {
                        Value::Float(buf) => {
                            if *len as usize != buf.len() {
                                return Err(packer_error!("Expected Value::Float to be of size {} but is {}", len, buf.len()));
                            }
                            match len {
                                4 => Ok(f32::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                8 => Ok(f64::from_le_bytes(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                16 => Ok(Float128::new(buf.as_slice().try_into().unwrap()).pack(&mut encoder)),
                                _ => Err(packer_error!("Expected Value::Float to be of size {} but is {}", len, buf.len()))
                            }?;
                            self.sp += 1;
                            self.ip += 1;
                            self.debug_log("packed float");
                            Ok(())
                        },
                        _ => Err(packer_error!("Expected Value::Float but got {}", &self.stack[self.sp]))
                    }
                }
                Instruction::Bytes => {
                    match &self.stack[self.sp] {
                        Value::Bytes(buf) => {
                            buf.pack(&mut encoder);
                            self.sp += 1;
                            self.ip += 1;
                            self.debug_log("packed bytes");
                            Ok(())
                        }
                        _ => Err(packer_error!("Expected Value::Bytes but got {}", &self.stack[self.sp]))
                    }
                }
                Instruction::BytesRaw(len) => {
                    match &self.stack[self.sp] {
                        Value::Bytes(buf) => {
                            if *len > 0 && buf.len() != *len as usize {
                                return Err(packer_error!("Expected Value::Bytes with length {} but is {}", len, buf.len()));
                            }
                            let target = encoder.alloc(buf.len());
                            target.copy_from_slice(buf);
                            self.sp += 1;
                            self.ip += 1;
                            self.debug_log(&format!("packed raw bytes {}", len));
                            Ok(())
                        }
                        _ => Err(packer_error!("Expected Value::Bytes but got {}", &self.stack[self.sp]))
                    }
                }
                Instruction::Optional(stride) => {
                    match &self.stack[self.sp] {
                        Value::None => {
                            0u8.pack(&mut encoder);
                            self.sp += 1;
                            self.ip += *stride as usize + 1;
                            self.debug_log("packed none");
                            Ok(())
                        },
                        _ => {
                            1u8.pack(&mut encoder);
                            self.ip += 1;
                            self.debug_log("packed some");
                            Ok(())
                        }
                    }
                }
                Instruction::Extension(stride) => {
                    if let Some(val) = self.stack.get(self.sp) {
                        match val {
                            Value::None => {
                                0u8.pack(&mut encoder);
                                self.sp += 1;
                                self.ip += *stride as usize + 1;
                                self.debug_log("packed none ext");
                                Ok(())
                            },
                            _ => {
                                1u8.pack(&mut encoder);
                                self.ip += 1;
                                self.debug_log("packed some ext");
                                Ok(())
                            }
                        }
                    } else {
                        self.ip += *stride as usize + 1;
                        self.debug_log("packed none ext with no value");
                        Ok(())
                    }
                }
                Instruction::Jmp(ptr) => {
                    self.run_jmp(*ptr)
                }
                Instruction::PushCND => {
                    self.run_pushcnd()
                }
                Instruction::PopCND => {
                    self.run_popcnd()
                }
                Instruction::JmpCND(target, cnd, delta) => {
                    self.run_jmpcnd(*target, *cnd, *delta)
                }
                Instruction::JmpNotCND(target, cnd, delta) => {
                    self.run_jmpnotcnd(*target, *cnd, *delta)
                }
                Instruction::Raise(e) => Err(packer_error!("{:?}", e)),
                _ => {
                    self.ip += 1;
                    self.debug_log("skip debug");
                    Ok(())
                }
            }?;
        }

        Ok(encoder.get_bytes().to_vec())
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
    use crate::serializer::vm::compiler::compile_type;

    const EOSIO_JSON: &str = include_str!("eosio.json");
    const TEST_JSON: &str = include_str!("test.json");

    #[test]
    fn test_custom_type() {
        let abi: ABI = from_str(TEST_JSON).expect("failed to parse ABI JSON");

        let mut program = Vec::new();
        compile_type(&abi, "test_types", &mut program, false)
            .expect("failed to compile type");

        let bigfloat: [u8; 16] = [
            6, 9, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 4, 2, 0,
        ];

        let quanitity = Asset::from_string("420.6900 TLOS");

        let stack = vec![
            Value::Condition(0),
            Value::Bool(true),
            Value::Int(69u8.to_le_bytes().to_vec(), false),
            Value::Int(69u16.to_le_bytes().to_vec(), false),
            Value::Int(69u32.to_le_bytes().to_vec(), false),
            Value::Int(69u64.to_le_bytes().to_vec(), false),
            Value::Int(69u128.to_le_bytes().to_vec(), false),
            Value::Int((-69i8).to_le_bytes().to_vec(), true),
            Value::Int((-69i16).to_le_bytes().to_vec(), true),
            Value::Int((-69i32).to_le_bytes().to_vec(), true),
            Value::Int((-69i64).to_le_bytes().to_vec(), true),
            Value::Int((-69i128).to_le_bytes().to_vec(), true),
            Value::Int(420u32.to_le_bytes().to_vec(), false),
            Value::Float(4.20f32.to_le_bytes().to_vec()),
            Value::Float(4.20f64.to_le_bytes().to_vec()),
            Value::Bytes(bigfloat.to_vec()),
            Value::Int(
                Name::new_from_str("eosio").value().to_le_bytes().to_vec(),
                false
            ),
            Value::Bytes(bigfloat.to_vec()),
            Value::Bytes("this is a test".as_bytes().to_vec()),
            Value::Condition(3),
            Value::Int(42u32.to_le_bytes().to_vec(), false),
            Value::Int(42u32.to_le_bytes().to_vec(), false),
            Value::Int(42u32.to_le_bytes().to_vec(), false),
            Value::None,
            Value::Int(
                Name::new_from_str("eosio").value().to_le_bytes().to_vec(),
                false
            ),
            // asset
            Value::Int(quanitity.amount().to_le_bytes().to_vec(), true),
            Value::Int(quanitity.symbol().value().to_le_bytes().to_vec(), false),
        ];

        let mut vm = PackerVM::new(stack);

        let result = vm.pack(&program)
            .expect("failed to pack value");

        println!("{:?}", result);

        let stack = vec![
            Value::Condition(1),
            Value::Bool(true),
            Value::Int(69u8.to_le_bytes().to_vec(), false),
            Value::Int(69u16.to_le_bytes().to_vec(), false),
            Value::Int(69u32.to_le_bytes().to_vec(), false),
            Value::Int(69u64.to_le_bytes().to_vec(), false),
            Value::Int(69u128.to_le_bytes().to_vec(), false),
            Value::Int((-69i8).to_le_bytes().to_vec(), true),
            Value::Int((-69i16).to_le_bytes().to_vec(), true),
            Value::Int((-69i32).to_le_bytes().to_vec(), true),
            Value::Int((-69i64).to_le_bytes().to_vec(), true),
            Value::Int((-69i128).to_le_bytes().to_vec(), true),
            Value::Int(420u32.to_le_bytes().to_vec(), false),
            Value::Float(4.20f32.to_le_bytes().to_vec()),
            Value::Float(4.20f64.to_le_bytes().to_vec()),
            Value::Bytes(bigfloat.to_vec()),
            Value::Int(
                Name::new_from_str("eosio").value().to_le_bytes().to_vec(),
                false
            ),
            Value::Bytes(bigfloat.to_vec()),
            Value::Bytes("this is a test".as_bytes().to_vec()),
            Value::Condition(3),
            Value::Int(42u32.to_le_bytes().to_vec(), false),
            Value::Int(42u32.to_le_bytes().to_vec(), false),
            Value::Int(42u32.to_le_bytes().to_vec(), false),
            Value::None,
            Value::Int(
                Name::new_from_str("eosio").value().to_le_bytes().to_vec(),
                false
            ),
            // asset
            Value::Bytes(bigfloat.to_vec()),
            Value::Bool(false),
        ];

        let mut vm = PackerVM::new(stack);

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

        let mut program = Vec::new();
        compile_type(&abi, "variant_block_signing_authority_v0", &mut program, false).expect("failed to compile type");

        let stack = vec![
            Value::Condition(0),
            Value::Int(420u32.to_le_bytes().to_vec(), false),
            Value::Condition(1),
            Value::Bytes(pkey_bytes),
            Value::Int(69u16.to_le_bytes().to_vec(), false),
        ];

        let mut vm = PackerVM::new(stack);

        let result = vm.pack(&program)
            .expect("failed to pack value");

        println!("{:?}", result);
    }
}
