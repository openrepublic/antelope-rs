use crate::chain::abi::{AbiStruct, AbiTable, AbiTypeDef, AbiVariant, ShipABI, ShipAbiTable, ABI};
use crate::define_error;
use crate::serializer::vm::{
    isa::{instruction_sequence_for, Exception, Instruction}
};

define_error!(crate::serializer::generic::value, TypeCompileError);

pub trait HasNameAndType {
    fn name_str(&self) -> String;
    fn type_str(&self) -> String;
}

pub trait ABIView {
    fn types(&self) -> &[AbiTypeDef];
    fn structs(&self) -> &[AbiStruct];
    fn variants(&self) -> &[AbiVariant];
    fn tables(&self) -> &[impl HasNameAndType];
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

fn compile_optional<T: ABIView>(
    abi: &T,
    type_name: &str,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    let mut opt_stack = Vec::new();
    compile_type(abi, &type_name, &mut opt_stack)?;

    code.push(Instruction::Optional(opt_stack.len() as u8));
    compile_type(abi, &type_name, code)?;
    Ok(())
}

fn compile_extension<T: ABIView>(
    abi: &T,
    type_name: &str,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    let mut ext_stack = Vec::new();
    compile_type(abi, &type_name, &mut ext_stack)?;

    code.push(Instruction::Extension(ext_stack.len() as u8));
    compile_type(abi, &type_name, code)?;
    Ok(())
}

fn compile_array<T: ABIView>(
    abi: &T,
    type_name: &str,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    let mut arr_stack = Vec::new();
    compile_type(abi, &type_name, &mut arr_stack)?;

    code.push(Instruction::PushCND);
    // first instruction of array loop
    let array_ptr = code.len();
    compile_type(abi, &type_name, code)?;
    code.push(Instruction::JmpNotCND(array_ptr, 0, -1));
    code.push(Instruction::PopCND);
    Ok(())
}

fn compile_variants<T: ABIView>(
    abi: &T,
    var_meta: &AbiVariant,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    let mut variants = Vec::new();
    for var_type in &var_meta.types {
        let mut var_stack = Vec::new();
        compile_type(abi, &var_type, &mut var_stack)?;
        variants.push((var_type.clone(), var_stack));
    }

    let vars_count = variants.len();
    // location of PopCND, the first op in the structure
    let header_start_ptr = code.len();

    // one JmpCND for each var + initial PopCND + Raise post jump table
    let header_jmp_ops_count = vars_count + 1 + 1;
    // location of first var definition instruction
    let jmp_table_end_ptr = header_start_ptr + header_jmp_ops_count;

    // pre-calculate start ptr of each structure
    let mut current_ptr = jmp_table_end_ptr;
    let mut var_start_ptrs = Vec::new();
    // pre-calculate location of first instruction post variants code
    let mut end_ptr = jmp_table_end_ptr;
    for (i, (_, var_code)) in variants.iter().enumerate() {
        var_start_ptrs.push(current_ptr);
        current_ptr += var_code.len();
        end_ptr += var_code.len();
        // all but last variant impl have extra Jmp
        if i < vars_count - 1 {
            end_ptr += 1;
            current_ptr += 1;
        }
    }

    // finally build variant definition full code
    // set condition to the length of the array from the stack
    code.push(Instruction::PushCND);

    // variant index based jump table
    for (i, var_start_ptr) in var_start_ptrs.iter().enumerate() {
        code.push(Instruction::JmpCND(*var_start_ptr, i as isize, 0));
    }

    // add a raise immediately after jump table to guard against wrong var indexes on the stack
    code.push(Instruction::Raise(Exception::VariantIndexNotInJumpTable));

    // finally add each of the variant implementations code and their Jmp to post definition
    for (i, (var_name, _)) in variants.iter_mut().enumerate() {
        // recompile actual var code in order to get correct jump ptrs
        compile_type(abi, &var_name, code)?;
        if i < vars_count - 1 {
            code.push(Instruction::Jmp(end_ptr));
        }
    }

    code.push(Instruction::PopCND);

    Ok(())
}

pub fn compile_type<T: ABIView>(
    abi: &T,
    type_name: &str,
    code: &mut Vec<Instruction>,
) -> Result<(), TypeCompileError> {
    if let Some(mut std_op) = instruction_sequence_for(type_name) {
        code.append(&mut std_op);
        return Ok(());
    }

    let mut _type = type_name.to_string();

    // Handle modifiers
    if _type.ends_with("?") {
        _type.pop();
        return compile_optional(abi, &_type, code);
    }

    if _type.ends_with("[]") {
        _type.truncate(_type.len().saturating_sub(2));
        return compile_array(abi, &_type, code);
    }
    if _type.ends_with("$") {
        _type.pop();
        return compile_extension(abi, &_type, code);
    }

    if let Some(type_meta) = abi.types().iter().find(|t| t.new_type_name == type_name) {
        _type = type_meta.r#type.clone();
    }

    if let Some(var_meta) = abi.variants().iter().find(|v| v.name == _type) {
        return compile_variants(abi, var_meta, code);
    }

    if let Some(table) = abi.tables().iter().find(|t| t.name_str() == _type) {
        compile_type(abi, &table.name_str(), code)?;
        return Ok(());
    }

    if let Some(struct_meta) = abi.structs().iter().find(|s| s.name == _type) {
        if !struct_meta.base.is_empty() {
            compile_type(abi, &struct_meta.base, code)?;
        }
        for field in &struct_meta.fields {
            compile_type(abi, &field.r#type, code)?;
        }
        return Ok(());
    }

    Err(TypeCompileError::new(format_args!("Could not compile type '{}'", _type)))
}

pub fn compile_program<T: ABIView>(
    abi: &T,
    type_name: &str,
) -> Result<Vec<Instruction>, TypeCompileError> {
    let mut code = Vec::new();
    compile_type(abi, type_name, &mut code)?;
    code.push(Instruction::Exit(0));
    Ok(code)
}