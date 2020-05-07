use crate::arch::{analyze_jumps, InnerJumpTable, OperandPatches};
use crate::binary::analyze_binary;
use crate::errors::{CargoAsmError, WCapstoneError};
use crate::format::{write_symbol_and_instructions, OutputConfig};
use crate::line_cache::FileLineCache;
use capstone::prelude::*;
use std::io::Write;

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
    pub sym_output: OutputConfig,

    /// If this is true, the length of the symbol in bytes will be displayed.
    pub display_length: bool,

    /// If this is true, the number of instructions will be displayed.
    pub display_instr_count: bool,

    /// If this is true, debugging information will be loaded and source code will be shown
    /// alongside assembly.
    pub display_source: bool,

    /// If this is true this will load debug information like DWARF.
    pub load_debug_info: bool,
}

pub fn disassemble_binary(
    binary: &[u8],
    matcher: SymbolMatcher,
    output: &mut dyn Write,
    config: &DisasmConfig,
) -> anyhow::Result<()> {
    let binary_info = analyze_binary(binary, config.load_debug_info)?;

    let test_symbol = binary_info
        .symbols
        .iter()
        .find(|sym| matcher.matches(&sym.demangled_name))
        .ok_or_else(|| CargoAsmError::NoSymbolMatch(matcher.original_needle.to_string()))?;

    let symbol_code = &binary[test_symbol.offset_range()];

    let cs = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()
        .map_err(WCapstoneError)?;
    let instrs = cs
        .disasm_all(symbol_code, test_symbol.addr)
        .map_err(WCapstoneError)?;

    let (jumps, op_patches) = if config.sym_output.display_jumps | config.sym_output.display_patches
    {
        analyze_jumps(&binary_info.symbols, binary_info.arch, &cs, &instrs)?
    } else {
        (InnerJumpTable::new(), OperandPatches::new())
    };

    let mut file_line_cache = FileLineCache::new();

    write_symbol_and_instructions(
        &test_symbol,
        &instrs,
        &jumps,
        &op_patches,
        &binary_info.line_mappings,
        &mut file_line_cache,
        &config.sym_output,
        output,
    )?;

    Ok(())
}
