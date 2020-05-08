use super::{InnerJumpTable, OperandPatches};
use crate::binary::Symbol;
use crate::errors::WCapstoneError;
use capstone::arch::x86::X86OperandType;
use capstone::prelude::*;
use capstone::Insn;

pub fn analyze_instructions_amd64<'i, 's>(
    symbols: &'s [Symbol<'s>],
    cs: &Capstone,
    instrs: &[Insn<'i>],
    jumps: &mut InnerJumpTable,
    op_patches: &mut OperandPatches<'s>,
) -> anyhow::Result<()> {
    use capstone::arch::x86::X86InsnGroup;

    for (idx, instr) in instrs.iter().enumerate() {
        let detail = cs.insn_detail(&instr).map_err(WCapstoneError)?;

        let mut target: Option<u64> = None;

        if detail
            .groups()
            .any(|g| g == InsnGroupId(X86InsnGroup::X86_GRP_JUMP as u8))
        {
            target = amd64_get_jump_target(instr, &detail);
        } else if detail
            .groups()
            .any(|g| g == InsnGroupId(X86InsnGroup::X86_GRP_CALL as u8))
        {
            target = amd64_get_call_target(instr, &detail);
        }

        if target.is_none() {
            continue;
        }
        let target: u64 = target.unwrap();

        // If it's a regular inner jump, then we just display the address and move on.
        if let Ok(target_index) = instrs.binary_search_by(|rhs| rhs.address().cmp(&target)) {
            jumps.insert(idx, target_index);
        } else if let Some(symbol) = symbols.iter().find(|sym| sym.addr == target) {
            op_patches.insert(idx, symbol);
        }
    }

    Ok(())
}

fn amd64_is_call_opcode(opcode: &[u8]) -> bool {
    if opcode.is_empty() {
        return false;
    }

    match opcode[0] {
        0xE8 | 0xFF | 0x9A => true,
        _ => false,
    }
}

fn amd64_is_jump_opcode(opcode: &[u8]) -> bool {
    if opcode.is_empty() {
        return false;
    }

    match opcode[0] {
        0xEB | 0xE9 | 0xFF | 0xEA | 0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x75 | 0x76 | 0x77
        | 0x78 | 0x79 | 0x7A | 0x7B | 0x7C | 0x7D | 0x7E | 0x7F | 0xE3 => {
            return true;
        }

        _ => { /* NOP */ }
    }

    if opcode.len() < 2 {
        return false;
    }

    match (opcode[0], opcode[1]) {
        (0x0F, 0x80)
        | (0x0F, 0x81)
        | (0x0F, 0x82)
        | (0x0F, 0x83)
        | (0x0F, 0x84)
        | (0x0F, 0x85)
        | (0x0F, 0x86)
        | (0x0F, 0x87)
        | (0x0F, 0x88)
        | (0x0F, 0x89)
        | (0x0F, 0x8A)
        | (0x0F, 0x8B)
        | (0x0F, 0x8C)
        | (0x0F, 0x8D)
        | (0x0F, 0x8E)
        | (0x0F, 0x8F) => true,

        _ => false,
    }
}

fn amd64_get_jump_target(instr: &Insn<'_>, detail: &InsnDetail<'_>) -> Option<u64> {
    let x86_detail = match detail.arch_detail() {
        capstone::arch::ArchDetail::X86Detail(d) => d,
        _ => return None,
    };

    if amd64_is_jump_opcode(&x86_detail.opcode()[0..]) {
        let mut operands = x86_detail.operands();

        let jump_operand = operands.next()?;

        // If there is more than one operand for some reason, bail.
        if operands.next().is_some() {
            return None;
        }

        get_operand_value(instr, jump_operand.op_type)
    } else {
        None
    }
}

fn amd64_get_call_target(instr: &Insn<'_>, detail: &InsnDetail<'_>) -> Option<u64> {
    let x86_detail = match detail.arch_detail() {
        capstone::arch::ArchDetail::X86Detail(d) => d,
        _ => return None,
    };

    if amd64_is_call_opcode(&x86_detail.opcode()[0..]) {
        let mut operands = x86_detail.operands();

        let call_operand = operands.next()?;

        // If there is more than one operand for some reason, bail.
        if operands.next().is_some() {
            return None;
        }

        get_operand_value(instr, call_operand.op_type)
    } else {
        None
    }
}

fn get_operand_value(instr: &Insn<'_>, operand: X86OperandType) -> Option<u64> {
    use capstone::arch::x86::X86Reg::{X86_REG_EIP, X86_REG_INVALID, X86_REG_RIP};

    match operand {
        X86OperandType::Imm(offset) => Some(offset as u64),
        X86OperandType::Mem(op_mem) => {
            // Scale is ignored because we don't use the index register.
            if op_mem.segment() == 0
                && (op_mem.base() == RegId(X86_REG_RIP as _)
                    || op_mem.base() == RegId(X86_REG_EIP as _))
                && op_mem.index() == RegId(X86_REG_INVALID as _)
            {
                let current_rip = instr.address() + instr.bytes().len() as u64;
                Some(current_rip.wrapping_add(op_mem.disp() as u64))
            } else {
                None
            }
        }
        _ => None,
    }
}
