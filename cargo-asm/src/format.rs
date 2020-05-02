use crate::arch::InnerJumpTable;
use crate::binary::Symbol;
use crate::errors::WCapstoneError;
use capstone::Insn;
use std::io::Write;

pub fn write_symbol_and_instructions<'i>(
    symbol: &Symbol,
    instrs: &[Insn<'i>],
    jumps: &InnerJumpTable,
    config: &OutputConfig,
    output: &mut dyn Write,
) -> anyhow::Result<()> {
    writeln!(output, "{}:", symbol.demangled_name)?;

    let m = measure(&config, instrs, &jumps);
    let jump_arrow_pieces = if config.display_jumps {
        create_jump_arrows_buffer(
            symbol.addr_range(),
            m.jumps_width,
            instrs.len(),
            jumps,
            output,
        )
    } else {
        Vec::new()
    };

    for (line_idx, instr) in instrs.iter().enumerate() {
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
            write_arrow_pieces_for_line(output, &jump_arrow_pieces, m.jumps_width, line_idx)?;
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ArrowPiece {
    None,
    Left,
    Right,
    Up,
    Down,
    Cross,
    BeginLeft,
    EndRight,
    BeginEnd,
    LeftDownJoint,
    LeftUpJoint,
    DownRightJoint,
    UpRightJoint,
    VerticalRightJoint,
    HorizontalDownJoint,
    HorizontalUpJoint,
}

impl ArrowPiece {
    pub fn is_horizontal(self) -> bool {
        match self {
            ArrowPiece::Left | ArrowPiece::Right => true,
            _ => false,
        }
    }

    pub fn is_vertical(self) -> bool {
        match self {
            ArrowPiece::Up | ArrowPiece::Down => true,
            _ => false,
        }
    }

    pub fn is_joint(self) -> bool {
        match self {
            ArrowPiece::Cross
            | ArrowPiece::LeftDownJoint
            | ArrowPiece::DownRightJoint
            | ArrowPiece::VerticalRightJoint
            | ArrowPiece::HorizontalDownJoint
            | ArrowPiece::HorizontalUpJoint
            | ArrowPiece::UpRightJoint => true,
            _ => false,
        }
    }
}

fn write_arrow_pieces_for_line(
    output: &mut dyn Write,
    pieces: &[ArrowPiece],
    width: usize,
    line: usize,
) -> anyhow::Result<()> {
    let off = line * width;
    for p in (&pieces[off..(off + width)]).iter() {
        let c = match p {
            ArrowPiece::BeginLeft => '←',
            ArrowPiece::Left => '─',
            ArrowPiece::Right => '─',
            ArrowPiece::LeftDownJoint => '┌',
            ArrowPiece::LeftUpJoint => '└',
            ArrowPiece::DownRightJoint => '└',
            ArrowPiece::UpRightJoint => '┌',
            ArrowPiece::Up => '│',
            ArrowPiece::Down => '│',
            ArrowPiece::EndRight => '→',
            ArrowPiece::BeginEnd => '↔',
            ArrowPiece::Cross => '┼',
            ArrowPiece::VerticalRightJoint => '├',
            ArrowPiece::HorizontalDownJoint => '┬',
            ArrowPiece::HorizontalUpJoint => '┴',
            ArrowPiece::None => ' ',
        };
        write!(output, "{}", c)?;
    }
    Ok(())
}

fn create_jump_arrows_buffer(
    addr_range: std::ops::Range<u64>,
    width: usize,
    height: usize,
    jumps: &InnerJumpTable,
    output: &mut dyn Write,
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

#[allow(clippy::if_same_then_else)]
fn draw_arrow_to(
    pieces: &mut [ArrowPiece],
    width: usize,
    extend_x: usize,
    from_y: usize,
    to_y: usize,
) {
    let mut push = |piece: ArrowPiece, x: usize, y: usize| {
        let off = y * width + x;

        // FIXME This is kind of a mess. At the moment I just find corner cases that cause weird
        // discontinuity in the arrows and add an if statement to fix them. I'm sure there are
        // better ways but I haven't thought of a good one yet that doesn't just move the
        // complexity somewhere else.

        let cur = pieces[off];

        if cur == ArrowPiece::BeginEnd {
            return;
        }

        if (cur == ArrowPiece::VerticalRightJoint && piece.is_horizontal())
            || (cur.is_horizontal() && piece == ArrowPiece::VerticalRightJoint)
        {
            pieces[off] = ArrowPiece::Cross;
        } else if (cur == ArrowPiece::HorizontalDownJoint && piece.is_vertical())
            || (cur.is_vertical() && piece == ArrowPiece::HorizontalDownJoint)
        {
            pieces[off] = ArrowPiece::Cross;
        } else if (cur == ArrowPiece::HorizontalUpJoint && piece.is_vertical())
            || (cur.is_vertical() && piece == ArrowPiece::HorizontalUpJoint)
        {
            pieces[off] = ArrowPiece::Cross;
        } else if (cur == ArrowPiece::LeftDownJoint && piece.is_vertical())
            || (cur.is_vertical() && piece == ArrowPiece::LeftDownJoint)
        {
            pieces[off] = ArrowPiece::VerticalRightJoint;
        } else if (cur == ArrowPiece::DownRightJoint && piece.is_vertical())
            | (cur.is_vertical() && piece == ArrowPiece::DownRightJoint)
        {
            pieces[off] = ArrowPiece::VerticalRightJoint;
        } else if (cur == ArrowPiece::LeftUpJoint && piece.is_vertical())
            | (cur.is_vertical() && piece == ArrowPiece::LeftUpJoint)
        {
            pieces[off] = ArrowPiece::VerticalRightJoint;
        } else if (cur == ArrowPiece::UpRightJoint && piece.is_vertical())
            | (cur.is_vertical() && piece == ArrowPiece::UpRightJoint)
        {
            pieces[off] = ArrowPiece::VerticalRightJoint;
        } else if (cur == ArrowPiece::UpRightJoint && piece.is_horizontal())
            || (cur.is_horizontal() && piece == ArrowPiece::UpRightJoint)
        {
            pieces[off] = ArrowPiece::HorizontalDownJoint;
        } else if (cur == ArrowPiece::LeftDownJoint && piece.is_horizontal())
            || (cur.is_horizontal() && piece == ArrowPiece::LeftDownJoint)
        {
            pieces[off] = ArrowPiece::HorizontalDownJoint;
        } else if (cur == ArrowPiece::DownRightJoint && piece.is_horizontal())
            || (cur.is_horizontal() && piece == ArrowPiece::DownRightJoint)
        {
            pieces[off] = ArrowPiece::HorizontalUpJoint;
        } else if (cur == ArrowPiece::LeftUpJoint && piece.is_horizontal())
            || (cur.is_horizontal() && piece == ArrowPiece::LeftUpJoint)
        {
            pieces[off] = ArrowPiece::HorizontalUpJoint;
        } else if (cur == ArrowPiece::BeginLeft && piece == ArrowPiece::EndRight)
            || (cur == ArrowPiece::EndRight && piece == ArrowPiece::BeginLeft)
        {
            pieces[off] = ArrowPiece::BeginEnd
        } else if (cur.is_horizontal() && piece.is_vertical())
            || (cur.is_vertical() && piece.is_horizontal())
        {
            pieces[off] = ArrowPiece::Cross
        } else if cur == ArrowPiece::None || (!cur.is_joint() && piece.is_joint()) {
            pieces[off] = piece;
        }
    };

    push(ArrowPiece::BeginLeft, width - 1, from_y);

    let mut cur_x = width - 1;
    let mut cur_y = from_y;

    while cur_x > extend_x {
        push(ArrowPiece::Left, cur_x, cur_y);
        cur_x -= 1;
    }

    if cur_y > to_y {
        push(ArrowPiece::LeftUpJoint, cur_x, cur_y);
        cur_y -= 1;
        while cur_y > to_y {
            push(ArrowPiece::Up, cur_x, cur_y);
            cur_y -= 1;
        }
        push(ArrowPiece::UpRightJoint, cur_x, cur_y);
    } else {
        push(ArrowPiece::LeftDownJoint, cur_x, cur_y);
        cur_y += 1;
        while cur_y < to_y {
            push(ArrowPiece::Up, cur_x, cur_y);
            cur_y += 1;
        }
        push(ArrowPiece::DownRightJoint, cur_x, cur_y);
    }

    if width > 1 {
        while cur_x < (width - 2) {
            cur_x += 1;
            push(ArrowPiece::Right, cur_x, cur_y);
        }
    }

    cur_x += 1;
    push(ArrowPiece::EndRight, cur_x, cur_y);
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
    instrs: &[Insn<'i>],
    jumps: &InnerJumpTable,
) -> OutputMeasure {
    use std::cmp::max;

    let mut measure = OutputMeasure::default();

    if config.display_jumps {
        measure.jumps_width = jumps.max_display_offset() + 1;
    }

    for instr in instrs.iter() {
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
