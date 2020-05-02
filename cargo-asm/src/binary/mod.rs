pub mod elf;

use goblin::Object;
use std::borrow::Cow;
use std::ops::Range;

#[derive(Debug, Clone)]
pub struct BinaryInfo<'a> {
    pub arch: BinaryArch,
    pub bits: BinaryBits,
    pub endian: BinaryEndian,
    pub symbols: Vec<Symbol<'a>>,
}

pub fn analyze_binary(binary: &[u8]) -> anyhow::Result<BinaryInfo> {
    match Object::parse(binary)? {
        Object::Elf(elf) => elf::analyze_elf(&elf),

        Object::PE(_pe) => {
            todo!("find_symbols for PE");
        }

        Object::Mach(_mach) => {
            todo!("find_symbols for Mach");
        }

        Object::Archive(_archive) => {
            todo!("find_symbols for Archive");
        }

        Object::Unknown(unknown) => {
            unimplemented!("unknown binary format {:#x}", unknown);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BinaryEndian {
    Little,
    Big,
}

impl From<goblin::container::Endian> for BinaryEndian {
    fn from(goblin_endian: goblin::container::Endian) -> Self {
        match goblin_endian {
            goblin::container::Endian::Little => BinaryEndian::Little,
            goblin::container::Endian::Big => BinaryEndian::Big,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BinaryArch {
    SPARC,
    X86,
    MIPS,
    PowerPC,
    PowerPC64,
    ARM,
    AMD64,
    AArch64,
    RiscV,
    M68K,

    Unknown,
}

impl BinaryArch {
    /// Creates a binary arch using the value of `e_machine` found an an ELF header.
    pub fn from_elf_machine(machine: u16) -> Option<Self> {
        use goblin::elf::header;

        match machine {
            0x00 => None,
            header::EM_SPARC => Some(BinaryArch::SPARC),
            header::EM_386 => Some(BinaryArch::X86),
            header::EM_MIPS => Some(BinaryArch::MIPS),
            header::EM_PPC => Some(BinaryArch::PowerPC),
            header::EM_PPC64 => Some(BinaryArch::PowerPC64),
            header::EM_ARM => Some(BinaryArch::ARM),
            header::EM_X86_64 => Some(BinaryArch::AMD64),
            header::EM_AARCH64 => Some(BinaryArch::AArch64),
            header::EM_RISCV => Some(BinaryArch::RiscV),
            header::EM_68K => Some(BinaryArch::M68K),
            _ => Some(BinaryArch::Unknown),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BinaryBits {
    Bits32,
    Bits64,
}

impl BinaryBits {
    pub fn from_elf_class(class: u8) -> Option<BinaryBits> {
        use goblin::elf::header;

        match class {
            header::ELFCLASS32 => Some(BinaryBits::Bits32),
            header::ELFCLASS64 => Some(BinaryBits::Bits64),
            _ => None,
        }
    }
}

impl<'a> BinaryInfo<'a> {}

fn demangle_name(name: &str) -> Cow<'_, str> {
    if let Ok(demangled) = rustc_demangle::try_demangle(&name) {
        Cow::from(demangled.to_string())
    } else {
        Cow::from(name)
    }
}

#[derive(Debug, Clone)]
pub struct Symbol<'a> {
    /// Original possibly mangled name.
    pub original_name: Cow<'a, str>,

    /// Demangled name if this is not mangled or if it couldn't be demangled,
    /// this will be the same string as `original_name`.
    pub demangled_name: Cow<'a, str>,

    /// Virtual address of the symbol during execution.
    pub addr: u64,

    /// File offset of the symbol.
    pub offset: usize,

    /// The size of teh symbol's data or code in bytes.
    pub size: usize,
}

impl<'a> Symbol<'a> {
    // pub fn addr_range(&self) -> Range<u64> {
    //     self.addr..(self.addr + self.size as u64)
    // }

    pub fn offset_range(&self) -> Range<usize> {
        self.offset..(self.offset + self.size)
    }
}
