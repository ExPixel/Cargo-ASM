pub mod format;

use crate::arch::{analyze_instructions, InnerJumpTable, OperandPatches};
use crate::binary::{Binary, FileResolveStrategy, LineMappings, Symbol};
use crate::errors::WCapstoneError;
use crate::line_cache::FileLineCache;
use capstone::prelude::*;
use capstone::Insn;
use std::io::Write;
use std::path::PathBuf;

pub struct SymbolMatcher<'a> {
    original_needle: &'a str,
    tokens: Vec<&'a str>,
}

impl<'a> SymbolMatcher<'a> {
    pub fn new(needle: &'a str) -> SymbolMatcher<'a> {
        let mut tokens = Vec::new();
        Self::tokenize(needle, &mut tokens);
        SymbolMatcher {
            original_needle: needle,
            tokens,
        }
    }

    pub fn needle(&self) -> &str {
        self.original_needle
    }

    pub fn matches(&self, mut name: &str) -> bool {
        for token in self.tokens.iter() {
            if let Some((_found_idx, found_end_idx)) = Self::find_ignore_case(name, token) {
                name = &name[found_end_idx..];
            } else {
                return false;
            }
        }
        true
    }

    fn find_ignore_case(haystack: &str, needle: &str) -> Option<(usize, usize)> {
        if haystack.len() < needle.len() {
            return None;
        }

        let mut needle_idx = 0;
        for (idx, haystack_ch) in haystack.char_indices() {
            let ch_len = haystack_ch.len_utf8();

            if needle_idx + ch_len <= needle.len() && needle.is_char_boundary(needle_idx) {
                if let Some(needle_ch) = (&needle[needle_idx..]).chars().next() {
                    if needle_ch.eq_ignore_ascii_case(&haystack_ch) {
                        needle_idx += ch_len;
                        if needle_idx == needle.len() {
                            return Some((idx + ch_len - needle.len(), idx + ch_len));
                        }
                        continue;
                    }
                }
            }

            needle_idx = 0;
        }

        None
    }

    fn tokenize<'s>(needle: &'s str, tokens: &mut Vec<&'s str>) {
        let mut ident_start = needle.len();

        for (idx, ch) in needle.char_indices() {
            if ident_start >= needle.len() {
                if Self::is_ident_start(ch) {
                    ident_start = idx;
                }
            } else if !Self::is_ident_part(ch) {
                tokens.push(&needle[ident_start..idx]);
                ident_start = needle.len();
            }
        }

        if ident_start < needle.len() {
            tokens.push(&needle[ident_start..needle.len()]);
        }
    }

    fn is_ident_start(ch: char) -> bool {
        ch == '_' || ch.is_ascii_alphabetic()
    }

    fn is_ident_part(ch: char) -> bool {
        ch == '_' || ch.is_ascii_alphanumeric()
    }
}

#[derive(Default)]
pub struct DisasmConfig {
    pub display_address: bool,
    pub display_patches: bool,
    pub display_bytes: bool,
    pub display_jumps: bool,
    pub display_instr: bool,
    pub display_source: bool,
    pub source_file_resolve: FileResolveStrategy,
    pub source_base_directory: PathBuf,
    pub load_debug_info: bool,
    pub display_length: bool,
    pub display_instr_count: bool,
}

pub fn disassemble<'a>(
    symbol: &Symbol<'a>,
    context: &mut DisasmContext<'a>,
    output: &mut dyn Write,
) -> anyhow::Result<()> {
    context.clear();

    let symbol_code = &context.binary.data[symbol.offset_range()];

    // FIXME support other ISAs
    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .map_err(WCapstoneError)?;
    let instrs = cs
        .disasm_all(symbol_code, symbol.addr)
        .map_err(WCapstoneError)?;

    analyze_instructions(
        &context.binary.symbols,
        context.binary.arch,
        &cs,
        &instrs,
        &mut context.jumps,
        &mut context.op_patches,
    )?;

    write_disasm_output(symbol, &instrs, context, output)
}

fn write_disasm_output<'a, 'i>(
    symbol: &Symbol<'a>,
    instrs: &'i [Insn<'i>],
    context: &mut DisasmContext<'a>,
    output: &mut dyn Write,
) -> anyhow::Result<()> {
    let m = format::measure(instrs, &context.config, &context);

    writeln!(output, "{}:", symbol.demangled_name)?;

    let jump_arrow_pieces = if context.config.display_jumps {
        format::create_jump_arrows_buffer(m.jumps_width, instrs.len(), &context.jumps)
    } else {
        Vec::new()
    };

    for (instr_idx, instr) in instrs.iter().enumerate() {
        if context.config.display_source {
            let line_mappings = &context.line_mappings;
            let line_cache = &mut context.line_cache;
            if let Some(line) = line_mappings
                .get(instr.address())?
                .and_then(|(path, line)| line_cache.get_line(path, line))
            {
                writeln!(output, "{}", line)?;
            }
        }

        // Left padding
        write!(output, "  ")?;

        if context.config.display_address {
            write!(
                output,
                "{:0width$x}:    ",
                instr.address(),
                width = m.address_width
            )?;
        }

        if context.config.display_bytes {
            format::write_hex_string(instr.bytes(), m.bytes_width + 4, output)?;
        }

        if context.config.display_jumps {
            format::write_arrow_pieces_for_line(
                output,
                &jump_arrow_pieces,
                m.jumps_width,
                instr_idx,
            )?;
        }

        if context.config.display_instr {
            write!(
                output,
                "{:<width$}    ",
                instr.mnemonic().unwrap_or(""),
                width = m.mnemonic_width
            )?;

            if let (true, Some(patch)) = (
                context.config.display_patches,
                context.op_patches.get(instr_idx),
            ) {
                write!(output, "{:<width$}", patch, width = m.operands_width)?;
            } else {
                write!(
                    output,
                    "{:<width$}",
                    instr.op_str().unwrap_or(""),
                    width = m.operands_width
                )?;
            }
        }

        writeln!(output)?;
    }

    Ok(())
}

pub struct DisasmContext<'a> {
    binary: &'a Binary<'a>,
    line_cache: FileLineCache,
    jumps: InnerJumpTable,
    op_patches: OperandPatches<'a>,
    config: DisasmConfig,
    line_mappings: LineMappings<'a>,
}

impl<'a> DisasmContext<'a> {
    pub fn new(config: DisasmConfig, binary: &'a Binary<'a>) -> anyhow::Result<DisasmContext<'a>> {
        let line_mappings = if config.display_source {
            binary.line_mapper(&config.source_base_directory, config.source_file_resolve)?
        } else {
            crate::binary::no_op_line_mapper()
        };

        Ok(DisasmContext {
            binary,
            config,
            line_cache: FileLineCache::new(),
            jumps: InnerJumpTable::new(),
            op_patches: OperandPatches::new(),
            line_mappings,
        })
    }

    fn clear(&mut self) {
        self.jumps.clear();
        self.op_patches.clear();
    }
}
