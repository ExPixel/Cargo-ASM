use super::{demangle_name, BinaryArch, BinaryBits, BinaryEndian, BinaryInfo, Symbol};
use goblin::elf::Elf;
use std::borrow::Cow;

pub fn analyze_elf<'a>(elf: &Elf<'a>) -> anyhow::Result<BinaryInfo<'a>> {
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

            addr: sym_addr,
            offset: sym_offset as usize,
            size: sym.st_size as usize,
        });
    }

    Ok(BinaryInfo {
        bits,
        arch,
        endian,
        symbols,
    })
}
