use crate::arch::find_inner_jumps;
use crate::binary::analyze_binary;
use crate::errors::{CargoAsmError, WCapstoneError};
use crate::format::{measure, write_symbol_and_instructions, OutputConfig};
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
            if let Some((found_idx, found_end_idx)) = Self::find_ignore_case(name, token) {
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
                            return Some((idx - needle.len(), idx + ch_len));
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

pub fn disassemble_binary(
    binary: &[u8],
    matcher: SymbolMatcher,
    output: &mut dyn Write,
) -> anyhow::Result<()> {
    let binary_info = analyze_binary(binary)?;

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

    let jumps = find_inner_jumps(binary_info.arch, &cs, &instrs)?;

    let config = OutputConfig {
        display_address: true,
        display_bytes: true,
        display_jumps: true,
        display_instr: true,
    };

    write_symbol_and_instructions(&test_symbol, &instrs, &jumps, &config, output)?;

    Ok(())
}
