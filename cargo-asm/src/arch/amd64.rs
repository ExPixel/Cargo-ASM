use super::InnerJumpTable;
use crate::errors::WCapstoneError;
use capstone::prelude::*;
use capstone::Insn;

pub fn find_inner_jumps_amd64<'a>(
    cs: &Capstone,
    instrs: &[Insn<'a>],
) -> anyhow::Result<InnerJumpTable> {
    use capstone::arch::x86::X86InsnGroup;

    let mut jumps = InnerJumpTable::new();
    for (idx, instr) in instrs.iter().enumerate() {
        let detail = cs.insn_detail(&instr).map_err(WCapstoneError)?;
        let is_jump = detail.groups().any(|g| {
            g == InsnGroupId(X86InsnGroup::X86_GRP_CALL as u8)
                || g == InsnGroupId(X86InsnGroup::X86_GRP_JUMP as u8)
        });

        if is_jump {
            let target = amd64_get_jump_target(&detail);
            if let Some(target_index) =
                target.and_then(|t| instrs.binary_search_by(|rhs| rhs.address().cmp(&t)).ok())
            {
                jumps.push(idx, target_index);
            }
        }
    }
    Ok(jumps)
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

fn amd64_get_jump_target(detail: &InsnDetail<'_>) -> Option<u64> {
    use capstone::arch::x86::X86OperandType;

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

        match jump_operand.op_type {
            X86OperandType::Imm(offset) => Some(offset as u64),

            _ => None,
        }
    } else {
        None
    }
}
