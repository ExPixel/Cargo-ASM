use crate::arch::JumpTable;
use crate::binary::Symbol;
use crate::errors::WCapstoneError;
use capstone::Instructions;
use std::io::Write;

pub fn write_symbol_and_instructions<'i>(
    symbol: &Symbol,
    instrs: Instructions<'i>,
    jumps: &JumpTable,
    config: &OutputConfig,
    output: &mut dyn Write,
) -> anyhow::Result<()> {
    writeln!(output, "{}:", symbol.demangled_name)?;

    let m = measure(&config, instrs.iter(), &jumps);
    let jum_arrows_buffer = if config.display_jumps {
        create_jump_arrows_buffer(symbol.addr_range(), jumps, output)
    } else {
        String::new()
    };

    for instr in instrs.iter() {
        if config.display_address {
            write!(
                output,
                "  {:0width$x}:    ",
                instr.address(),
                width = m.address_width
            )?;
        }

        if config.display_bytes {
            write_hex_string(instr.bytes(), m.bytes_width + 4, output)?;
        }

        if config.display_jumps {
            // FIXME todo
        }

        if config.display_instr {
            write!(
                output,
                "{:<width$}    ",
                instr.mnemonic().unwrap_or(""),
                width = m.mnemonic_width
            )?;

            write!(
                output,
                "{:<width$}    ",
                instr.op_str().unwrap_or(""),
                width = m.operands_width
            )?;
        }

        writeln!(output)?;
    }

    Ok(())
}

fn create_jump_arrows_buffer(
    addr_range: std::ops::Range<u64>,
    jumps: &JumpTable,
    output: &mut dyn Write,
) -> String {
    let mut arrows = String::new();

    for addr in addr_range {
        // FIXME
    }

    arrows
}

fn write_hex_string(bytes: &[u8], min_size: usize, output: &mut dyn Write) -> anyhow::Result<()> {
    const NIBBLES_UP: [u8; 16] = [
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E',
        b'F',
    ];

    let mut chars_written = 0;
    for b in bytes.iter() {
        let lo = (*b & 0xF) as usize;
        let hi = (*b >> 4) as usize;

        if chars_written > 0 {
            output.write_all(&[b' ', NIBBLES_UP[hi], NIBBLES_UP[lo]])?;
            chars_written += 3;
        } else {
            output.write_all(&[NIBBLES_UP[hi], NIBBLES_UP[lo]])?;
            chars_written += 2;
        }
    }

    while chars_written < min_size {
        output.write_all(&[b' '])?;
        chars_written += 1;
    }

    Ok(())
}

#[derive(Default)]
pub struct OutputMeasure {
    pub address_width: usize,
    pub bytes_width: usize,
    pub jumps_width: usize,
    pub mnemonic_width: usize,
    pub operands_width: usize,
}

pub fn measure<'i>(
    config: &OutputConfig,
    instrs: impl 'i + Iterator<Item = capstone::Insn<'i>>,
    jumps: &JumpTable,
) -> OutputMeasure {
    use std::cmp::max;

    let mut measure = OutputMeasure::default();

    if config.display_jumps {
        let mut overlaps = 0;

        for (idx, (src, maybe_dest)) in jumps.iter().enumerate() {
            let dest = if let Some(d) = maybe_dest {
                d
            } else {
                continue;
            };

            let range = src..=dest;

            // This counts the number of jumps with destinations that have a source that is
            // contained within the range src..=dest. This works for counting overlaps because we
            // always sort the array of jump pairs.
            let cur_overlaps = jumps.addrs()[idx..]
                .iter()
                .filter_map(|(osrc, odst)| odst.map(|_| *osrc))
                .filter(|osrc| range.contains(osrc))
                .count();

            overlaps = std::cmp::max(overlaps, cur_overlaps);
        }

        if !jumps.addrs().is_empty() {
            measure.jumps_width = overlaps + 1;
        }
    }

    for instr in instrs {
        if config.display_address {
            measure.address_width = max(measure.address_width, addr_len(instr.address()));
        }

        if config.display_bytes {
            measure.bytes_width = max(measure.bytes_width, hex_len(instr.bytes()));
        }

        if config.display_instr {
            measure.mnemonic_width = max(
                measure.mnemonic_width,
                instr.mnemonic().map(|m| m.len()).unwrap_or(0),
            );
            measure.operands_width = max(
                measure.operands_width,
                instr.op_str().map(|ops| ops.len()).unwrap_or(0),
            );
        }
    }

    measure
}
/// Returns the number of characters required to display an address in hexidecimal.
/// This assumes that all of the bytes will be packed together.
fn addr_len(mut addr: u64) -> usize {
    let mut len = 0;
    while addr > 0 {
        len += 1;
        addr >>= 4;
    }
    len
}

/// Returns the number of characters required to display an array of bytes in hexidecimal.
/// This assumes that there will be a space separating each byte.
fn hex_len(bytes: &[u8]) -> usize {
    if bytes.is_empty() {
        0
    } else {
        bytes.len() * 3 - 1
    }
}

#[derive(Default)]
pub struct OutputConfig {
    pub display_address: bool,
    pub display_bytes: bool,
    pub display_jumps: bool,
    pub display_instr: bool,
}
