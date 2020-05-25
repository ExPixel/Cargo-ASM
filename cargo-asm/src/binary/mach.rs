use super::{
    demangle_name, Binary, BinaryArch, BinaryBits, BinaryData, BinaryEndian, ObjectExt, Symbol,
};
use goblin::mach::symbols;
use goblin::mach::{Mach, MachO};
use std::borrow::Cow;

pub fn analyze_mach<'a>(
    mach: Mach<'a>,
    data: &'a BinaryData,
    load_debug_info: bool,
) -> anyhow::Result<Binary<'a>> {
    match mach {
        goblin::mach::Mach::Fat(multi) => analyze_mach_object(multi.get(0)?, data, load_debug_info),
        goblin::mach::Mach::Binary(obj) => analyze_mach_object(obj, data, load_debug_info),
    }
}

pub fn analyze_mach_object<'a>(
    mach: MachO<'a>,
    data: &'a BinaryData,
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
        for &(ref section, _) in segment.sections()?.iter() {
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

    Ok(Binary {
        data,
        bits,
        arch,
        endian,
        symbols,
        object: ObjectExt::Mach(mach),
    })
}

const MACH_TYPE_FUNC: u8 = 0x24;
