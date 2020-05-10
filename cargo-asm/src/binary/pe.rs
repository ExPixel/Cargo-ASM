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
    // The exports list, the COFF symbol table, DLL exports (FIXME), and
    // PDB debug information (FIXME).

    for export in pe.exports.iter() {
        let sym_name = if let Some(name) = export.name {
            name
        } else {
            continue;
        };
        let sym_name_demangled = demangle_name(sym_name);

        symbols.push(Symbol {
            original_name: Cow::from(sym_name),
            demangled_name: sym_name_demangled,
            short_demangled_name: Default::default(),

            addr: export.rva as u64,
            offset: export.offset,
            size: export.size,
        });
    }

    let maybe_strtab = pe.header.coff_header.strings(data).ok();

    for (_, inline_name, symbol) in pe.header.coff_header.symbols(data)?.iter() {
        let sym_name = if let Some(name) = inline_name {
            name
        } else if let Some(ref strtab) = maybe_strtab {
            if let Ok(name) = symbol.name(strtab) {
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
        let sym_name_demangled = demangle_name(sym_name);

        println!("{} -> {}", sym_name, sym_name_demangled);

        // symbols.push(Symbol {
        //     original_name: Cow::from(sym_name),
        //     demangled_name: sym_name_demangled,
        //     short_demangled_name: Default::default(),

        //     addr: export.rva as u64,
        //     offset: export.offset,
        //     size: export.size,
        // });
    }

    Ok(Binary {
        data,
        bits,
        arch,
        endian,
        symbols,
        object: goblin::Object::PE(pe),
    })
}
