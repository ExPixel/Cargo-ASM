use super::{
    demangle_name, Binary, BinaryArch, BinaryBits, BinaryData, BinaryEndian, ObjectExt, Symbol,
};
use goblin::mach::symbols;
use goblin::mach::{Mach, MachO};
use std::borrow::Cow;
use std::path::{Path, PathBuf};

pub fn analyze_mach<'a>(
    mach: Mach<'a>,
    data: &'a BinaryData,
    binary_path: &Path,
    load_debug_info: bool,
) -> anyhow::Result<Binary<'a>> {
    match mach {
        goblin::mach::Mach::Fat(multi) => {
            analyze_mach_object(multi.get(0)?, data, binary_path, load_debug_info)
        }
        goblin::mach::Mach::Binary(obj) => {
            analyze_mach_object(obj, data, binary_path, load_debug_info)
        }
    }
}

pub fn analyze_mach_object<'a>(
    mach: MachO<'a>,
    data: &'a BinaryData,
    binary_path: &Path,
    _load_debug_info: bool,
) -> anyhow::Result<Binary<'a>> {
    let bits = if mach.is_64 {
        BinaryBits::Bits64
    } else {
        BinaryBits::Bits32
    };

    let endian = if mach.little_endian {
        BinaryEndian::Little
    } else {
        BinaryEndian::Big
    };

    let arch = BinaryArch::from_mach_cpu_types(mach.header.cputype, mach.header.cpusubtype)
        .expect("[FIXME] unknown mach cpu type");

    let mut section_offsets: Vec<(u64, usize)> = Vec::new();
    for segment in mach.segments.iter() {
        for s in segment.into_iter() {
            let (section, _) = s?;
            section_offsets.push((section.addr as u64, section.offset as usize));
        }
    }

    let mut symbols = Vec::new();
    let mut symbol_addresses: Vec<u64> = Vec::new();
    let mut symbols_it = mach.symbols();
    while let Some(Ok((sym_name, sym))) = symbols_it.next() {
        if sym.n_sect == symbols::NO_SECT as usize || !sym.is_stab() {
            continue;
        }

        let sym_addr = sym.n_value;
        symbol_addresses.push(sym_addr);

        if sym.n_type != MACH_TYPE_FUNC || sym_name.len() < 1 {
            continue;
        }

        let sym_offset = if let Some((sec_addr, sec_off)) = section_offsets.get(sym.n_sect - 1) {
            (sym_addr - sec_addr) as usize + sec_off
        } else {
            continue;
        };

        let sym_name_demangled = demangle_name(sym_name);

        symbols.push(Symbol {
            original_name: Cow::from(sym_name),
            demangled_name: sym_name_demangled,
            short_demangled_name: Default::default(),

            addr: sym_addr,
            offset: sym_offset as usize,
            size: 0,
        });
    }

    symbol_addresses.sort_unstable();
    symbol_addresses.dedup();

    for symbol in symbols.iter_mut() {
        if let Ok(idx) = symbol_addresses.binary_search(&symbol.addr) {
            if let Some(next_addr) = symbol_addresses.get(idx + 1) {
                symbol.size = (next_addr - symbol.addr) as usize;
                continue;
            }
        };
        symbol.addr = 0;
    }

    let ext = if let Some(external_dwarf) = find_external_dwarf(binary_path) {
        MachExt {
            mach,
            debug: MachDebug::External(external_dwarf),
        }
    } else {
        MachExt {
            mach,
            debug: MachDebug::Internal,
        }
    };

    Ok(Binary {
        data,
        bits,
        arch,
        endian,
        symbols,
        object: ObjectExt::Mach(ext),
    })
}

// FIXME this is a very bad way to search for DWARF debug information. The path to the separate
// DWAF binary is actually stored somewhere in the Mach-O file (If you run `strings` on it the path
// can be found), I just have no idea where exactly in the Mach-O it's stored and I can't find
// information on it either. I'll just have to dig through all of the load commands at some point
// to find where the string is placed.
fn find_external_dwarf(binary_path: &Path) -> Option<PathBuf> {
    let directory = binary_path.parent()?;
    let dsym_name = {
        let mut n = binary_path.file_stem()?.to_os_string();
        n.push(".dSYM");
        n
    };
    let dsym_path = directory.join(dsym_name);
    let dwarf_path = {
        let mut p = dsym_path;
        p.push("Contents");
        p.push("Resources");
        p.push("DWARF");
        p.push(binary_path.file_name()?);
        p
    };

    if dwarf_path.is_file() {
        Some(dwarf_path)
    } else {
        None
    }
}

const MACH_TYPE_FUNC: u8 = 0x24;

#[derive(Debug)]
pub struct MachExt<'a> {
    mach: MachO<'a>,
    debug: MachDebug,
}

#[derive(Debug)]
pub enum MachDebug {
    /// DWARF debug information is in the Mach-O itself.
    Internal,

    /// DWARF debug information is in some separate binary (usually in [binary].dSYM somewhere)
    External(PathBuf),
}

fn get_section_by_name<'a>(
    mach: &MachO<'a>,
    binary: &'a [u8],
    name: &str,
) -> anyhow::Result<&'a [u8]> {
    for segment in mach.segments.iter() {
        for s in segment.into_iter() {
            let (section, section_data) = s?;
            return Ok(section_data);
        }
    }
    Ok(&[])
}
