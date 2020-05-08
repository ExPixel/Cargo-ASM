use crate::arch::InnerJumpTable;
use crate::disasm::{DisasmConfig, DisasmContext};
use capstone::Insn;
use std::io::Write;

/*
 * Our imaginary arrow pixels are arranged like so:
 *
 *     0
 *   3   1
 *     2
 *
 * Or
 *
 *           ARROW_TOP
 *  ARROW_LEFT      ARROW_RIGHT
 *          ARROW_BOT
 */

const ARROW_NONE: u8 = 0b0000;
const ARROW_TOP: u8 = 0b0001;
const ARROW_RIGHT: u8 = 0b0010;
const ARROW_TOP_RIGHT: u8 = 0b0011;
const ARROW_BOT: u8 = 0b0100;
const ARROW_TOP_BOT: u8 = 0b0101;
const ARROW_RIGHT_BOT: u8 = 0b0110;
const ARROW_TOP_RIGHT_BOT: u8 = 0b0111;
const ARROW_LEFT: u8 = 0b1000;
const ARROW_TOP_LEFT: u8 = 0b1001;
const ARROW_RIGHT_LEFT: u8 = 0b1010;
const ARROW_TOP_RIGHT_LEFT: u8 = 0b1011;
const ARROW_BOT_LEFT: u8 = 0b1100;
const ARROW_TOP_BOT_LEFT: u8 = 0b1101;
const ARROW_RIGHT_BOT_LEFT: u8 = 0b1110;
const ARROW_TOP_RIGHT_BOT_LEFT: u8 = 0b1111;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ArrowPiece {
    None,
    End(u8),
    Dir(u8),
}

pub fn write_arrow_pieces_for_line(
    output: &mut dyn Write,
    pieces: &[ArrowPiece],
    width: usize,
    line: usize,
) -> anyhow::Result<()> {
    let off = line * width;
    for p in (&pieces[off..(off + width)]).iter() {
        let c = match p {
            ArrowPiece::End(bits) if *bits == ARROW_LEFT => '◀',
            ArrowPiece::End(bits) if *bits == ARROW_RIGHT => '▶',
            ArrowPiece::End(bits) if *bits == ARROW_LEFT | ARROW_RIGHT => '◆',

            ArrowPiece::Dir(bits) => match *bits {
                ARROW_NONE => '?',
                ARROW_TOP => '│',
                ARROW_RIGHT => '─',
                ARROW_TOP_RIGHT => '└',
                ARROW_BOT => '│',
                ARROW_TOP_BOT => '│',
                ARROW_RIGHT_BOT => '┌',
                ARROW_TOP_RIGHT_BOT => '├',
                ARROW_LEFT => '─',
                ARROW_TOP_LEFT => '┘',
                ARROW_RIGHT_LEFT => '─',
                ARROW_TOP_RIGHT_LEFT => '┴',
                ARROW_BOT_LEFT => '┐',
                ARROW_TOP_BOT_LEFT => '┤',
                ARROW_RIGHT_BOT_LEFT => '┬',
                ARROW_TOP_RIGHT_BOT_LEFT => '┼',
                _ => unreachable!("out of range arrow bits"),
            },
            ArrowPiece::None => ' ',
            _ => '?',
        };
        write!(output, "{}", c)?;
    }
    Ok(())
}

pub fn create_jump_arrows_buffer(
    width: usize,
    height: usize,
    jumps: &InnerJumpTable,
) -> Vec<ArrowPiece> {
    let mut pieces: Vec<ArrowPiece> = Vec::with_capacity(width * height);
    pieces.resize(width * height, ArrowPiece::None);

    for jump in jumps.iter() {
        let from_y = jump.source;
        let to_y = jump.target;

        if from_y == to_y {
            continue;
        }

        draw_arrow_to(
            &mut pieces,
            width,
            (width - (jump.display_offset)).saturating_sub(1),
            from_y,
            to_y,
        );
    }

    pieces
}

fn draw_arrow_to(
    pieces: &mut [ArrowPiece],
    width: usize,
    extend_x: usize,
    from_y: usize,
    to_y: usize,
) {
    let mut push = |piece: ArrowPiece, x: usize, y: usize| {
        let off = y * width + x;

        match pieces[off] {
            ArrowPiece::End(bits) => {
                match piece {
                    ArrowPiece::End(new_bits) => pieces[off] = ArrowPiece::End(bits | new_bits),
                    ArrowPiece::Dir(_) => { /* NOP */ }
                    ArrowPiece::None => { /* NOP */ }
                }
            }

            ArrowPiece::Dir(bits) => {
                match piece {
                    ArrowPiece::End(new_bits) => pieces[off] = ArrowPiece::End(new_bits),
                    ArrowPiece::Dir(new_bits) => pieces[off] = ArrowPiece::Dir(bits | new_bits),
                    ArrowPiece::None => { /* NOP */ }
                }
            }

            ArrowPiece::None => {
                pieces[off] = piece;
            }
        }
    };

    push(ArrowPiece::End(ARROW_LEFT), width - 1, from_y);

    let mut cur_x = width - 1;
    let mut cur_y = from_y;

    while cur_x > extend_x {
        push(ArrowPiece::Dir(ARROW_LEFT | ARROW_RIGHT), cur_x, cur_y);
        cur_x -= 1;
    }

    if cur_y > to_y {
        push(ArrowPiece::Dir(ARROW_RIGHT | ARROW_TOP), cur_x, cur_y);
        cur_y -= 1;
        while cur_y > to_y {
            push(ArrowPiece::Dir(ARROW_TOP | ARROW_BOT), cur_x, cur_y);
            cur_y -= 1;
        }
        push(ArrowPiece::Dir(ARROW_BOT | ARROW_RIGHT), cur_x, cur_y);
    } else {
        push(ArrowPiece::Dir(ARROW_RIGHT | ARROW_BOT), cur_x, cur_y);
        cur_y += 1;
        while cur_y < to_y {
            push(ArrowPiece::Dir(ARROW_TOP | ARROW_BOT), cur_x, cur_y);
            cur_y += 1;
        }
        push(ArrowPiece::Dir(ARROW_TOP | ARROW_RIGHT), cur_x, cur_y);
    }

    if width > 1 {
        while cur_x < (width - 2) {
            cur_x += 1;
            push(ArrowPiece::Dir(ARROW_LEFT | ARROW_RIGHT), cur_x, cur_y);
        }
    }

    cur_x += 1;
    push(ArrowPiece::End(ARROW_RIGHT), cur_x, cur_y);
}

pub fn write_hex_string(
    bytes: &[u8],
    min_size: usize,
    output: &mut dyn Write,
) -> anyhow::Result<()> {
    const NIBBLES_TOP: [u8; 16] = [
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'A', b'B', b'C', b'D', b'E',
        b'F',
    ];

    let mut chars_written = 0;
    for b in bytes.iter() {
        let lo = (*b & 0xF) as usize;
        let hi = (*b >> 4) as usize;

        if chars_written > 0 {
            output.write_all(&[b' ', NIBBLES_TOP[hi], NIBBLES_TOP[lo]])?;
            chars_written += 3;
        } else {
            output.write_all(&[NIBBLES_TOP[hi], NIBBLES_TOP[lo]])?;
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
    instrs: &'i [Insn<'i>],
    config: &DisasmConfig,
    context: &DisasmContext,
) -> OutputMeasure {
    use std::cmp::max;

    let mut measure = OutputMeasure::default();

    if config.display_jumps {
        measure.jumps_width = context.jumps.max_display_offset() + 1;
    }

    for (idx, instr) in instrs.iter().enumerate() {
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

            if let (true, Some(patch)) = (config.display_patches, context.op_patches.get(idx)) {
                measure.operands_width = max(measure.operands_width, patch.len());
            } else {
                measure.operands_width = max(
                    measure.operands_width,
                    instr.op_str().map(|ops| ops.len()).unwrap_or(0),
                );
            }
        }
    }

    measure
}

/// Returns the number of digits required to display an offset in decimal.
/// This assumes that all of the digits are packed together with no spaces or punctuation.
pub fn off_len(mut off: usize) -> usize {
    let mut len = 0;
    while off > 0 {
        len += 1;
        off /= 10;
    }
    len
}

/// Returns the number of characters required to display an address in hexidecimal.
/// This assumes that all of the bytes will be packed together.
pub fn addr_len(mut addr: u64) -> usize {
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
    pub display_patches: bool,
    pub display_bytes: bool,
    pub display_jumps: bool,
    pub display_instr: bool,
    pub display_source: bool,
}
