use super::dwarf::DwarfLineMapper;
use super::{
    demangle_name, Binary, BinaryArch, BinaryBits, BinaryEndian, FileResolveStrategy, LineMapper,
    ObjectExt, Symbol,
};
use anyhow::Context as _;
use goblin::pe::PE;
use std::borrow::Cow;
use std::path::{Path, PathBuf};

pub fn analyze_pe<'a>(
    pe: PE<'a>,
    data: &'a [u8],
    binary_path: &Path,
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

    get_coff_symbols(&pe, data, &mut symbols)?;

    let debug_data_pdb = pe
        .debug_data
        .as_ref()
        .and_then(|data| data.codeview_pdb70_debug_info.as_ref())
        .and_then(|codeview| std::str::from_utf8(codeview.filename).ok())
        .map(|pdb_str| PathBuf::from(pdb_str));

    // FIXME allow passing PDB file as an argument somehow which would override this:
    let pdb_path = if Some(true) == debug_data_pdb.as_ref().map(|p| p.exists()) {
        debug_data_pdb
    } else {
        find_pdb_path(binary_path)
    };

    let pe_ext = if let Some(ref pdb_path) = pdb_path {
        let pdb_data = std::fs::read(pdb_path)
            .with_context(|| format!("failed to read file `{}`", pdb_path.display()))?;
        let pdb_vec = PDBVecSource::new(pdb_data);
        let pdb = pdb::PDB::open(pdb_vec)?;

        PEExt {
            pe,
            debug: PEDebug::PDB(pdb),
        }
    } else {
        PEExt {
            pe,
            debug: PEDebug::Dwarf,
        }
    };

    Ok(Binary {
        data,
        bits,
        arch,
        endian,
        symbols,
        object: ObjectExt::PE(pe_ext),
    })
}

/// Attempts to find the PDB file for the binary.
/// This will just search for a file in the same directory as binary_path with the same filename
/// but with the .pdb extension.
fn find_pdb_path(binary_path: &Path) -> Option<PathBuf> {
    let binary_stem = binary_path.file_stem()?;

    if let Some(directory) = binary_path.parent() {
        for maybe_pdb in directory.read_dir().ok()? {
            let maybe_pdb = if let Ok(maybe_pdb) = maybe_pdb {
                maybe_pdb
            } else {
                continue;
            };

            // FIXME ther might (should) be a better wayto do this :|
            if Path::new(&maybe_pdb.file_name())
                .file_stem()
                .map(|s| s == binary_stem)
                .unwrap_or(false)
                && Path::new(&maybe_pdb.file_name())
                    .extension()
                    .map(|s| s == "pdb")
                    .unwrap_or(false)
            {
                let maybe_pdb_path = maybe_pdb.path();
                if maybe_pdb_path.is_file() {
                    return Some(maybe_pdb_path);
                }
            }
        }
    }

    None
}

fn get_coff_symbols<'a>(
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
                        pe.image_base as u64 + (section.virtual_address + symbol.value) as u64,
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

pub(super) fn pe_line_mapper<'a>(
    pe: &PEExt<'a>,
    endian: BinaryEndian,
    data: &'a [u8],
    base_directory: &Path,
    resolve_strategy: FileResolveStrategy,
) -> anyhow::Result<Box<dyn 'a + LineMapper>> {
    match &pe.debug {
        PEDebug::Dwarf => pe_dwarf_line_mapper(pe, endian, data, base_directory, resolve_strategy),
        PEDebug::PDB(ref _pdb) => {
            pe_pdb_line_mapper(pe, endian, data, base_directory, resolve_strategy)
        }
    }
}

fn pe_pdb_line_mapper<'a>(
    _pe: &PEExt<'a>,
    _endian: BinaryEndian,
    _data: &'a [u8],
    _base_directory: &Path,
    _resolve_strategy: FileResolveStrategy,
) -> anyhow::Result<Box<dyn 'a + LineMapper>> {
    anyhow::bail!("not yet implemented")
}

fn pe_dwarf_line_mapper<'a>(
    pe: &PEExt<'a>,
    endian: BinaryEndian,
    data: &'a [u8],
    base_directory: &Path,
    resolve_strategy: FileResolveStrategy,
) -> anyhow::Result<Box<dyn 'a + LineMapper>> {
    let mapper: Box<dyn LineMapper> = if endian == BinaryEndian::Little {
        let loader = |section: gimli::SectionId| {
            get_section_by_name(pe, data, section.name())
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
            get_section_by_name(&pe, data, section.name())
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

fn get_section_by_name<'a>(
    pe: &PEExt<'a>,
    binary: &'a [u8],
    name: &str,
) -> anyhow::Result<&'a [u8]> {
    for section in pe.pe.sections.iter() {
        if let Ok(section_name) = section.name() {
            if section_name == name {
                // FIXME figure out why section.size_of_raw_data is wrong here and why
                // section.virtual_size works. I suspect it's because of some kind of padding
                // being added onto the end of sections, but why does that cause gimli
                // to display an error???

                let section_start = section.pointer_to_raw_data as usize;
                let section_end = section_start + section.virtual_size as usize;
                return Ok(&binary[section_start..section_end]);
            }
        }
    }
    Ok(&[])
}

#[derive(Debug)]
pub struct PEExt<'a> {
    pe: PE<'a>,
    debug: PEDebug<'a>,
}

#[derive(Debug)]
pub enum PEDebug<'a> {
    Dwarf,
    PDB(pdb::PDB<'a, PDBVecSource<'a>>),
}

pub struct PDBVecSource<'a> {
    data: Vec<u8>,
    _phantom: std::marker::PhantomData<&'a ()>,
}

impl<'a> std::fmt::Debug for PDBVecSource<'a> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!();
    }
}

impl<'a> PDBVecSource<'a> {
    fn new(data: Vec<u8>) -> PDBVecSource<'a> {
        PDBVecSource {
            data,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'a> pdb::Source<'a> for PDBVecSource<'a> {
    fn view(
        &mut self,
        slices: &[pdb::SourceSlice],
    ) -> Result<Box<dyn pdb::SourceView<'a>>, std::io::Error> {
        todo!();
    }
}
