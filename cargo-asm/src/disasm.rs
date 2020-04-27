use crate::arch::analyze_jumps;
use crate::binary::analyze_binary;
use crate::errors::WCapstoneError;
use crate::format::{measure, write_symbol_and_instructions, OutputConfig};
use capstone::prelude::*;
use std::io::Write;

pub struct SymbolMatcher<'a> {
    search_strings: &'a [&'a str],
}

impl<'a> SymbolMatcher<'a> {
    pub fn new(search_strings: &'a [&'a str]) -> SymbolMatcher<'a> {
        SymbolMatcher { search_strings }
    }

    pub fn matches(&self, name: &str) -> bool {
        for needle in self.search_strings.iter() {
            if name.contains(*needle) {
                return true;
            }
        }
        false
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
        .expect("failed to find test symbol");

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

    let jumps = analyze_jumps(binary_info.arch, &cs, instrs.iter())?;

    let config = OutputConfig {
        display_address: true,
        display_bytes: true,
        display_jumps: true,
        display_instr: true,
    };

    write_symbol_and_instructions(&test_symbol, instrs, &jumps, &config, output)?;

    Ok(())
}
