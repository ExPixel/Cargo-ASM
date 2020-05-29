use super::dwarf::DwarfLineMapper;
use super::{
    demangle_name, Binary, BinaryArch, BinaryBits, BinaryData, BinaryEndian, FileResolveStrategy,
    LineMapper, ObjectExt, Symbol,
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

pub(super) fn mach_line_mapper<'a>(
    mach: &'a MachExt<'a>,
    endian: BinaryEndian,
    binary_data: &'a BinaryData,
    base_directory: &Path,
    resolve_strategy: FileResolveStrategy,
) -> anyhow::Result<Box<dyn 'a + LineMapper>> {
    match &mach.debug {
        MachDebug::Internal => {
            mach_internal_line_mapper(&mach.mach, endian, base_directory, resolve_strategy)
        }
        MachDebug::External(ref dwarf_file) => {
            mach_external_line_mapper(&binary_data, dwarf_file, base_directory, resolve_strategy)
        }
    }
}

fn mach_internal_line_mapper<'a>(
    mach: &'a MachO<'a>,
    endian: BinaryEndian,
    base_directory: &Path,
    resolve_strategy: FileResolveStrategy,
) -> anyhow::Result<Box<dyn 'a + LineMapper>> {
    let mapper: Box<dyn LineMapper> = if endian == BinaryEndian::Little {
        let loader = |section: gimli::SectionId| {
            get_section_by_name(mach, section.name())
                .map(|d| gimli::EndianSlice::new(d, gimli::LittleEndian))
        };
        let sup_loader =
            |_section: gimli::SectionId| Ok(gimli::EndianSlice::new(&[], gimli::LittleEndian));

        Box::new(DwarfLineMapper::new(
            loader,
            sup_loader,
            base_directory,
            resolve_strategy,
        )?)
    } else {
        let loader = move |section: gimli::SectionId| {
            get_section_by_name(&mach, section.name())
                .map(|d| gimli::EndianSlice::new(d, gimli::BigEndian))
        };
        let sup_loader =
            |_section: gimli::SectionId| Ok(gimli::EndianSlice::new(&[], gimli::BigEndian));

        Box::new(DwarfLineMapper::new(
            loader,
            sup_loader,
            base_directory,
            resolve_strategy,
        )?)
    };

    Ok(mapper)
}

fn mach_external_line_mapper<'a>(
    binary_data: &'a BinaryData,
    dwarf_path: &Path,
    base_directory: &Path,
    resolve_strategy: FileResolveStrategy,
) -> anyhow::Result<Box<dyn 'a + LineMapper>> {
    use goblin::Object;

    let dwarf_data = std::fs::read(dwarf_path)?;
    binary_data.set_dwarf_data(dwarf_data);

    let dwarf_data_ref = binary_data.dwarf_data();

    // Once again, I must sadly cast away lifetimes. I would rather do this than try to use Pin or
    // some other method of creating a self referential struct. So that the Ref doesn't get
    // dropped, I also move dwarf_data_ref into the loader closure.
    let dwarf_data_slice = unsafe { std::mem::transmute::<&'_ [u8], &'a [u8]>(&*dwarf_data_ref) };

    let dwarf_mach = if let Object::Mach(mach) = Object::parse(dwarf_data_slice)? {
        match mach {
            goblin::mach::Mach::Fat(multi) => multi.get(0)?,
            goblin::mach::Mach::Binary(obj) => obj,
        }
    } else {
        return Ok(Box::new(super::NoOpLineMapper));
    };

    let endian = if dwarf_mach.little_endian {
        BinaryEndian::Little
    } else {
        BinaryEndian::Big
    };

    let mapper: Box<dyn LineMapper> = if endian == BinaryEndian::Little {
        let loader = move |section: gimli::SectionId| {
            let _ = dwarf_data_ref;
            get_section_by_name(&dwarf_mach, section.name())
                .map(|d| gimli::EndianSlice::new(d, gimli::LittleEndian))
        };
        let sup_loader =
            |_section: gimli::SectionId| Ok(gimli::EndianSlice::new(&[], gimli::LittleEndian));

        Box::new(DwarfLineMapper::new(
            loader,
            sup_loader,
            base_directory,
            resolve_strategy,
        )?)
    } else {
        let loader = move |section: gimli::SectionId| {
            let _ = dwarf_data_ref;
            get_section_by_name(&dwarf_mach, section.name())
                .map(|d| gimli::EndianSlice::new(d, gimli::BigEndian))
        };
        let sup_loader =
            |_section: gimli::SectionId| Ok(gimli::EndianSlice::new(&[], gimli::BigEndian));

        Box::new(DwarfLineMapper::new(
            loader,
            sup_loader,
            base_directory,
            resolve_strategy,
        )?)
    };

    Ok(mapper)
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

    let dwarf_dir = {
        let mut p = dsym_path;
        p.push("Contents");
        p.push("Resources");
        p.push("DWARF");
        p
    };

    let dwarf_path = dwarf_dir.join(binary_path.file_name()?);

    if dwarf_path.is_file() {
        return Some(dwarf_path);
    }

    // If we can't find the exact file name, we just use the first file that is found in the DWARF
    // directory. I'm not sure if there are ever multiple in there :P, I do know that sometimes the
    // file has a hash at the end.
    for entry in std::fs::read_dir(&dwarf_dir).ok()? {
        let entry = entry.ok()?;
        let path = entry.path();
        if path.is_file() {
            return Some(path);
        }
    }

    return None;
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

fn get_section_by_name<'a>(mach: &MachO<'a>, mut name: &str) -> anyhow::Result<&'a [u8]> {
    name = fix_section_name(name);

    for segment in mach.segments.iter() {
        for s in segment.into_iter() {
            let (section, section_data) = s?;
            if section
                .name()
                .map(|n| fix_section_name(n) == name)
                .unwrap_or(false)
            {
                return Ok(section_data);
            }
        }
    }
    Ok(&[])
}

/// Mach-O section names use __ instead of ., so I just remove those from section names to make
/// things simpler.
fn fix_section_name(name: &str) -> &str {
    if name.starts_with(".") {
        &name[1..]
    } else if name.starts_with("__") {
        &name[2..]
    } else {
        name
    }
}
