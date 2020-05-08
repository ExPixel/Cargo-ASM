use super::dwarf::DwarfLineMapper;
use super::{
    demangle_name, Binary, BinaryArch, BinaryBits, BinaryEndian, LineMapper, LineMappings,
    NoOpLineMapper, Symbol,
};
use goblin::elf::Elf;
use std::borrow::Cow;

pub fn analyze_elf<'a>(
    elf: Elf<'a>,
    data: &'a [u8],
    load_debug_info: bool,
) -> anyhow::Result<Binary<'a>> {
    use goblin::elf::header;

    let bits = BinaryBits::from_elf_class(elf.header.e_ident[header::EI_CLASS])
        .expect("[FIXME] unrecognized bits value");

    let endian = BinaryEndian::from(elf.header.endianness()?);

    let arch =
        BinaryArch::from_elf_machine(elf.header.e_machine).expect("[FIXME] unrecognized arch");

    let mut symbols = Vec::new();

    for sym in elf.syms.iter().filter(|sym| sym.is_function()) {
        // FIXME handle these symbols with a size of 0 (external symbols usually).
        if sym.st_size == 0 {
            continue;
        }

        let sym_name = elf
            .strtab
            .get(sym.st_name)
            .transpose()?
            .unwrap_or("<< UNKNOWN >>");
        let sym_name_demangled = demangle_name(sym_name);

        let (section_offset, section_addr) = {
            let sym_section = elf
                .section_headers
                .get(sym.st_shndx)
                .expect("[FIXME] no matching section header");
            (sym_section.sh_offset, sym_section.sh_addr)
        };

        // FIXME clamp values to section bounds.
        // FIXME This works for executable and shared objects that use st_value as a virtual
        // address to the symbol, but I also want to handle relocatable files, in which case
        // st_value would hold a section offset for the symbol.
        let sym_addr = sym.st_value;
        let sym_offset = (sym_addr - section_addr) + section_offset;

        symbols.push(Symbol {
            original_name: Cow::from(sym_name),
            demangled_name: sym_name_demangled,
            short_demangled_name: Default::default(),

            addr: sym_addr,
            offset: sym_offset as usize,
            size: sym.st_size as usize,
        });
    }

    let line_mapper: Box<dyn LineMapper> = if load_debug_info {
        if endian == BinaryEndian::Little {
            let loader = move |section: gimli::SectionId| {
                get_section_by_name(&elf, data, section.name())
                    .map(|d| gimli::EndianSlice::new(d, gimli::LittleEndian))
            };
            let sup_loader =
                |_section: gimli::SectionId| Ok(gimli::EndianSlice::new(&[], gimli::LittleEndian));
            Box::new(DwarfLineMapper::new(loader, sup_loader)?)
        } else {
            let loader = move |section: gimli::SectionId| {
                get_section_by_name(&elf, data, section.name())
                    .map(|d| gimli::EndianSlice::new(d, gimli::BigEndian))
            };
            let sup_loader =
                |_section: gimli::SectionId| Ok(gimli::EndianSlice::new(&[], gimli::BigEndian));
            Box::new(DwarfLineMapper::new(loader, sup_loader)?)
        }
    } else {
        Box::new(NoOpLineMapper)
    };

    let line_mappings = LineMappings::new(line_mapper);

    Ok(Binary {
        data,
        bits,
        arch,
        endian,
        symbols,
        line_mappings,
    })
}

fn get_section_by_name<'a>(
    elf: &Elf<'a>,
    binary: &'a [u8],
    name: &str,
) -> anyhow::Result<&'a [u8]> {
    for section in elf.section_headers.iter() {
        if let Some(section_name) = elf.shdr_strtab.get(section.sh_name).transpose()? {
            if section_name == name {
                return Ok(&binary[section.file_range()]);
            }
        }
    }
    Ok(&[])
}
