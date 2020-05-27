mod arena;
pub mod dwarf;
pub mod elf;
pub mod mach;
pub mod pdb_lines;
pub mod pe;

use crate::errors::CargoAsmError;
use crate::platform::{path_converter_from, NativePathConverter, PathConverter, Platform};
use arena::StringArena;
use goblin::Object;
use once_cell::unsync::OnceCell;
use std::borrow::Cow;
use std::cell::{Ref, RefCell, RefMut};
use std::ops::Range;
use std::path::Path;

pub type FilePDB<'a> = pdb::PDB<'a, std::fs::File>;

#[derive(Debug)]
pub struct BinaryData {
    data: Box<[u8]>,
    syms: RefCell<StringArena<'static>>,
    debug: RefCell<Option<DebugInfo<'static>>>,
}

impl BinaryData {
    pub fn load(data: Vec<u8>) -> BinaryData {
        BinaryData {
            data: data.into_boxed_slice(),
            syms: RefCell::new(StringArena::new()),
            debug: RefCell::new(None),
        }
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    // pub fn data_mut(&mut self) -> &mut [u8] {
    //     &mut self.data
    // }

    fn sym_arena_mut<'a>(&'a self) -> RefMut<StringArena<'a>> {
        // Casting away lifetimes :)
        unsafe {
            std::mem::transmute::<RefMut<StringArena<'_>>, RefMut<StringArena<'a>>>(
                self.syms.borrow_mut(),
            )
        }
    }

    fn dwarf_data<'a>(&'a self) -> Ref<'a, [u8]> {
        // Casting away lifetimes :)
        // I don't move any of the data in this struct if that makes you feel better.
        unsafe {
            std::mem::transmute::<Ref<'_, [u8]>, Ref<'a, [u8]>>(Ref::map(
                self.debug.borrow(),
                |d| {
                    if let Some(DebugInfo::DwarfData(ref data)) = d {
                        data as &[u8]
                    } else {
                        panic!("debug info is not dwarf data")
                    }
                },
            ))
        }
    }

    fn pdb_mut<'a>(&'a self) -> RefMut<'a, FilePDB<'a>> {
        // Casting away lifetimes :)
        // I don't move any of the data in this struct if that makes you feel better.
        unsafe {
            std::mem::transmute::<RefMut<'_, FilePDB<'_>>, RefMut<'a, FilePDB<'a>>>(RefMut::map(
                self.debug.borrow_mut(),
                |d| {
                    if let Some(DebugInfo::PDB(ref mut pdb)) = d {
                        pdb
                    } else {
                        panic!("debug info is not a PDB")
                    }
                },
            ))
        }
    }

    fn set_dwarf_data(&self, data: Vec<u8>) {
        assert!(self.debug.borrow().is_none(), "cannot reassign debug info");
        *self.debug.borrow_mut() = Some(DebugInfo::DwarfData(data));
    }

    fn set_pdb(&self, pdb: FilePDB<'static>) {
        assert!(self.debug.borrow().is_none(), "cannot reassign debug info");
        *self.debug.borrow_mut() = Some(DebugInfo::PDB(pdb));
    }
}

#[derive(Debug)]
enum DebugInfo<'a> {
    PDB(FilePDB<'a>),
    DwarfData(Vec<u8>),
}

#[derive(Debug)]
pub struct Binary<'a> {
    pub data: &'a BinaryData,
    pub arch: BinaryArch,
    pub bits: BinaryBits,
    pub endian: BinaryEndian,
    pub symbols: Vec<Symbol<'a>>,
    pub object: ObjectExt<'a>,
}

impl<'a> Binary<'a> {
    pub fn load(
        data: &'a BinaryData,
        binary_path: &Path,
        debug_info: bool,
    ) -> anyhow::Result<Binary<'a>> {
        match Object::parse(data.data())? {
            Object::Elf(elf) => elf::analyze_elf(elf, data, debug_info),

            Object::PE(pe) => pe::analyze_pe(pe, data, binary_path, debug_info),

            Object::Mach(mach) => mach::analyze_mach(mach, data, binary_path, debug_info),

            Object::Archive(_archive) => {
                Err(CargoAsmError::UnsupportedBinaryFormat("Archive").into())
            }

            Object::Unknown(_unknown) => {
                Err(CargoAsmError::UnsupportedBinaryFormat("<< UNKNOWN >>").into())
            }
        }
    }

    // FIXME the name on these is kind of consuing...it's called line_mapper but it returns a
    // LineMappings, which contains a LineMapper.
    pub fn line_mapper(
        &'a self,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
    ) -> anyhow::Result<LineMappings<'a>> {
        let mapper;
        let convert_path: Box<dyn 'a + PathConverter>;

        match &self.object {
            ObjectExt::Elf(ref elf) => {
                mapper = elf::elf_line_mapper(
                    elf,
                    self.endian,
                    &self.data.data(),
                    base_directory,
                    resolve_strategy,
                )?;
                convert_path = path_converter_from(Platform::Unix);
            }

            ObjectExt::PE(ref pe) => {
                mapper = pe::pe_line_mapper(
                    pe,
                    self.data.pdb_mut(),
                    self.endian,
                    &self.data.data(),
                    base_directory,
                    resolve_strategy,
                )?;
                convert_path = path_converter_from(Platform::Windows);
            }

            ObjectExt::Mach(ref mach) => {
                mapper = mach::mach_line_mapper(
                    mach,
                    self.endian,
                    &self.data,
                    base_directory,
                    resolve_strategy,
                )?;
                convert_path = path_converter_from(Platform::Unix);
            }
        };

        Ok(LineMappings::new(mapper, convert_path))
    }

    pub fn data(&self) -> &[u8] {
        self.data.data()
    }
}

#[derive(Debug)]
pub enum ObjectExt<'a> {
    Elf(goblin::elf::Elf<'a>),
    PE(pe::PEExt<'a>),
    Mach(mach::MachExt<'a>),
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

    pub fn from_coff_machine(machine: u16, bits: BinaryBits) -> Option<Self> {
        use goblin::pe::header;

        match machine {
            header::COFF_MACHINE_UNKNOWN => None,
            header::COFF_MACHINE_X86 => Some(BinaryArch::X86),
            header::COFF_MACHINE_X86_64 => Some(BinaryArch::AMD64),
            header::COFF_MACHINE_MIPS16
            | header::COFF_MACHINE_MIPSFPU
            | header::COFF_MACHINE_MIPSFPU16
            | header::COFF_MACHINE_R4000 => Some(BinaryArch::MIPS),
            header::COFF_MACHINE_POWERPC | header::COFF_MACHINE_POWERPCFP => {
                if bits == BinaryBits::Bits32 {
                    Some(BinaryArch::PowerPC)
                } else {
                    Some(BinaryArch::PowerPC64)
                }
            }
            header::COFF_MACHINE_ARM => Some(BinaryArch::ARM),
            header::COFF_MACHINE_ARM64 => Some(BinaryArch::AArch64),
            header::COFF_MACHINE_RISCV32
            | header::COFF_MACHINE_RISCV64
            | header::COFF_MACHINE_RISCV128 => Some(BinaryArch::RiscV),

            // FIXME this is wrong, I should introduce something separate for THUMB mode. I will
            // probably forget for a while.
            header::COFF_MACHINE_THUMB => Some(BinaryArch::ARM),

            _ => Some(BinaryArch::Unknown),
        }
    }

    pub fn from_mach_cpu_types(cpu_type: u32, _cpu_subtype: u32) -> Option<Self> {
        use goblin::mach::constants::cputype;

        match cpu_type {
            cputype::CPU_TYPE_ARM => Some(BinaryArch::ARM),
            cputype::CPU_TYPE_ARM64 => Some(BinaryArch::AArch64),
            cputype::CPU_TYPE_ARM64_32 => Some(BinaryArch::AArch64),
            cputype::CPU_TYPE_MIPS => Some(BinaryArch::MIPS),
            cputype::CPU_TYPE_POWERPC => Some(BinaryArch::PowerPC),
            cputype::CPU_TYPE_POWERPC64 => Some(BinaryArch::PowerPC64),
            cputype::CPU_TYPE_SPARC => Some(BinaryArch::SPARC),
            cputype::CPU_TYPE_X86 => Some(BinaryArch::X86),
            cputype::CPU_TYPE_X86_64 => Some(BinaryArch::AMD64),
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

fn demangle_name(name: &str) -> Cow<'_, str> {
    if let Ok(demangled) = rustc_demangle::try_demangle(&name) {
        let demangled_string = format!("{:#}", demangled);
        Cow::from(demangled_string)
    } else if let Ok(demangled) = cpp_demangle::Symbol::new(name) {
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

    short_demangled_name: OnceCell<String>,

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

    /// Returns a shorter version of a symbols name (removes trait information)
    pub fn short_demangled_name(&self) -> &str {
        self.short_demangled_name.get_or_init(|| {
            let mut short_name = String::new();

            for (is_impl, frag) in
                rust_symbol_fragments(&self.demangled_name).map(rust_impl_fragment)
            {
                if is_impl {
                    // We simplify all of the impl conversion stuff and just use the impl type
                    // as the root type. e.g.
                    //      anyhow::context::<impl anyhow::Context<T,E> for core::result::Result<T,E>>::with_context
                    // becomes
                    //      anyhow::Context::with_context
                    short_name.clear();
                }

                if !short_name.is_empty() {
                    short_name.push_str("::");
                }
                short_name.push_str(&frag);
            }

            short_name
        })
    }
}

/// Preferred method for a line mapper to resolve paths.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum FileResolveStrategy {
    PreferRelative,
    PreferAbsolute,
}

impl FileResolveStrategy {
    pub fn other(self) -> FileResolveStrategy {
        match self {
            FileResolveStrategy::PreferRelative => FileResolveStrategy::PreferAbsolute,
            FileResolveStrategy::PreferAbsolute => FileResolveStrategy::PreferRelative,
        }
    }
}

impl Default for FileResolveStrategy {
    fn default() -> Self {
        FileResolveStrategy::PreferRelative
    }
}

pub struct LineMappings<'a> {
    mapper: Box<dyn 'a + LineMapper>,
    convert_path: Box<dyn 'a + PathConverter>,
}

pub fn no_op_line_mapper() -> LineMappings<'static> {
    LineMappings::new(Box::new(NoOpLineMapper), Box::new(NativePathConverter))
}

impl<'a> LineMappings<'a> {
    fn new(mapper: Box<dyn 'a + LineMapper>, convert_path: Box<dyn 'a + PathConverter>) -> Self {
        LineMappings {
            mapper,
            convert_path,
        }
    }

    pub fn get(&mut self, address: u64) -> anyhow::Result<Option<(&Path, u32)>> {
        self.mapper
            .map_address_to_line(address, self.convert_path.as_ref())
    }
}

impl<'a> std::fmt::Debug for LineMappings<'a> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "LineMappings {{}}")
    }
}

trait LineMapper {
    fn map_address_to_line(
        &mut self,
        address: u64,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Option<(&Path, u32)>>;
}

struct NoOpLineMapper;

impl LineMapper for NoOpLineMapper {
    fn map_address_to_line(
        &mut self,
        _address: u64,
        _convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Option<(&Path, u32)>> {
        Ok(None)
    }
}

fn rust_impl_fragment(impl_str: &str) -> (/* is_impl */ bool, &'_ str) {
    let impl_start_index = if let Some(index) = impl_str.find("impl ") {
        index + 5
    } else {
        return (false, impl_str);
    };

    let mut impl_end_index = impl_str.len();
    for (idx, ch) in impl_str.char_indices().skip(impl_start_index) {
        if !(ch.is_ascii_alphanumeric() || ch == '_' || ch == ':') {
            impl_end_index = idx;
            break;
        }
    }

    let impl_main_type = &impl_str[impl_start_index..impl_end_index];

    (true, impl_main_type)
}

fn rust_symbol_fragments(symbol: &str) -> RustSymFragmentIter<'_> {
    RustSymFragmentIter { symbol, offset: 0 }
}

pub struct RustSymFragmentIter<'s> {
    symbol: &'s str,
    offset: usize,
}

impl<'s> Iterator for RustSymFragmentIter<'s> {
    type Item = &'s str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.symbol.len() {
            return None;
        }

        let mut depth = 0;
        let mut last_was_colon = false;

        for (idx, ch) in (&self.symbol[self.offset..]).char_indices() {
            if depth > 0 {
                if ch == '>' {
                    depth -= 1;
                } else if ch == '<' {
                    depth += 1;
                }
            } else if ch == ':' {
                if last_was_colon {
                    if depth == 0 {
                        let ret = &self.symbol[self.offset..(self.offset + idx - 1)];
                        self.offset += idx + 1; // colon is 1 byte
                        return Some(ret);
                    }
                } else {
                    last_was_colon = true;
                }
            } else if ch == '<' {
                last_was_colon = false;
                depth += 1;
            } else {
                last_was_colon = false;
            }
        }

        let ret = &self.symbol[self.offset..];
        self.offset = self.symbol.len();
        Some(ret)
    }
}
