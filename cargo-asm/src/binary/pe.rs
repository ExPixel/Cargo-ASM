use super::{demangle_name, Binary, BinaryArch, BinaryBits, BinaryEndian, Symbol};
use goblin::pe::PE;
use std::borrow::Cow;

pub fn analyze_pe<'a>(
    pe: PE<'a>,
    data: &'a [u8],
    _load_debug_info: bool,
) -> anyhow::Result<Binary<'a>> {
    let endian = BinaryEndian::Little;
    let bits = if pe.is_64 {
        BinaryBits::Bits64
    } else {
        BinaryBits::Bits32
    };
    let arch = BinaryArch::from_coff_machine(pe.header.coff_header.machine, bits)
        .expect("[FIXME] unrecognized arch");

    let mut symbols = Vec::new();

    // We check a few places for symbols when analyzing PE files.
    // The exports list (FIXME), the COFF symbol table, DLL exports (FIXME), and
    // PDB debug information (FIXME).

    // FIXME I'm not sure if I should be using these actually if its for DLLs. I'm also not sure if
    // it has the same problem as the COFF symbols and some of the fields aren't reliable.  For now,
    // just parsing COFF symbol tables and PDBs.
    //
    // for export in pe.exports.iter() {
    //     let sym_name = if let Some(name) = export.name {
    //         name
    //     } else {
    //         continue;
    //     };
    //     let sym_name_demangled = demangle_name(sym_name);

    //     symbols.push(Symbol {
    //         original_name: Cow::from(sym_name),
    //         demangled_name: sym_name_demangled,
    //         short_demangled_name: Default::default(),

    //         addr: export.rva as u64,
    //         offset: export.offset,
    //         size: export.size,
    //     });
    // }

    parse_coff_symbols(&pe, data, &mut symbols)?;

    Ok(Binary {
        data,
        bits,
        arch,
        endian,
        symbols,
        object: goblin::Object::PE(pe),
    })
}

fn parse_coff_symbols<'a>(
    pe: &PE<'a>,
    data: &'a [u8],
    symbols: &mut Vec<Symbol<'a>>,
) -> anyhow::Result<()> {
    let maybe_symtab = pe.header.coff_header.symbols(data).ok();
    let maybe_strtab = pe.header.coff_header.strings(data).ok();

    let first_symbol_index = symbols.len();

    if let Some(symtab) = maybe_symtab {
        for (_sym_index, inline_name, symbol) in symtab.iter() {
            if !symbol.is_function_definition() && symbol.typ != 0x20 {
                continue;
            }

            // FIXME for now we skip symbols that are sections, but I think the sections can also
            // actually just contain the function (???) and in this the entire section should be
            // used. I'm not sure if that is the case though.
            if symbol.value == 0 {
                continue;
            }

            let sym_name = if let Some(name) = inline_name {
                name
            } else if let Some(ref strtab) = maybe_strtab {
                if let Some(Ok(name)) = symbol
                    .name_offset()
                    .and_then(|off| strtab.get(off as usize))
                {
                    name
                } else {
                    continue;
                }
            } else {
                continue;
            };

            if sym_name.is_empty() {
                continue;
            }

            let (sym_addr, sym_offset) = if symbol.section_number >= 1 {
                let section = &pe.sections[symbol.section_number as usize - 1];

                if symbol.storage_class == goblin::pe::symbol::IMAGE_SYM_CLASS_STATIC
                    || symbol.storage_class == goblin::pe::symbol::IMAGE_SYM_CLASS_EXTERNAL
                    || symbol.storage_class == goblin::pe::symbol::IMAGE_SYM_CLASS_LABEL
                {
                    (
                        (section.virtual_address + symbol.value) as u64,
                        (section.pointer_to_raw_data + symbol.value) as usize,
                    )
                } else {
                    continue;
                }
            } else {
                continue;
            };
            let sym_name_demangled = demangle_name(sym_name);

            symbols.push(Symbol {
                original_name: Cow::from(sym_name),
                demangled_name: sym_name_demangled,
                short_demangled_name: Default::default(),

                addr: sym_addr,
                offset: sym_offset,
                size: 0,
            });
        }
    }

    // Using the information in the COFF like AuxFunctionDefinition::total_size is unreliable, so
    // instead we just sort the functions by address and guess that the size of the function is its
    // start address subtracted from the start address of the next function. This works for the
    // most part :P.

    (&mut symbols[first_symbol_index..]).sort_by_key(|sym| sym.addr);
    if symbols.len() - first_symbol_index > 1 {
        for idx in first_symbol_index..(symbols.len() - 1) {
            symbols[idx].size = (symbols[idx + 1].addr - symbols[idx].addr) as usize;
        }
    }

    Ok(())
}
