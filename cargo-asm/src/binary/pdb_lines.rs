use super::{FileResolveStrategy, LineMapper};
use crate::platform::PathConverter;
use once_cell::unsync::OnceCell;
use pdb::FallibleIterator as _;
use std::cell::RefMut;
use std::ops::Range;
use std::path::{Path, PathBuf};

pub struct PDBLineMapper<'a> {
    section_addresses: Vec<u64>,
    strings: pdb::StringTable<'a>,
    modules: Vec<LazyModule<'a>>,
    base_directory: PathBuf,
    resolve_strategy: FileResolveStrategy,
    previous_module_index: usize,
}

impl<'a> PDBLineMapper<'a> {
    pub fn new<S: 'a + pdb::Source<'a>>(
        section_addresses: Vec<u64>,
        mut pdb: RefMut<'a, pdb::PDB<'a, S>>,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
    ) -> anyhow::Result<Self> {
        let debug_information = pdb.debug_information()?;
        let strings = pdb.string_table()?;
        let mut modules = Vec::new();

        let mut modules_iter = debug_information.modules()?;
        while let Some(module) = modules_iter.next()? {
            if let Some(module_info) = pdb.module_info(&module)? {
                modules.push(LazyModule::new(module_info));
            }
        }

        Ok(PDBLineMapper {
            section_addresses,
            strings,
            modules,
            base_directory: PathBuf::from(base_directory),
            resolve_strategy,
            previous_module_index: 0,
        })
    }
}

impl<'a> LineMapper for PDBLineMapper<'a> {
    fn map_address_to_line(
        &mut self,
        address: u64,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Option<(&Path, u32)>> {
        if let Some(mapping) = self.modules.get(self.previous_module_index).map(|module| {
            module.addr2line(
                &self.section_addresses,
                &self.strings,
                address,
                &self.base_directory,
                self.resolve_strategy,
                convert_path,
            )
        }) {
            if matches!(mapping, Ok(Some(_))) {
                return mapping;
            }
        }

        for (idx, module) in self.modules.iter().enumerate() {
            if idx == self.previous_module_index {
                continue;
            }

            let mapping = module.addr2line(
                &self.section_addresses,
                &self.strings,
                address,
                &self.base_directory,
                self.resolve_strategy,
                convert_path,
            );

            if matches!(mapping, Ok(Some(_))) {
                self.previous_module_index = idx;
                return mapping;
            }
        }

        return Ok(None);
    }
}

struct LazyModule<'a> {
    module: pdb::ModuleInfo<'a>,
    lines: OnceCell<Lines>,
}

impl<'a> LazyModule<'a> {
    pub fn new(module: pdb::ModuleInfo<'a>) -> LazyModule<'a> {
        LazyModule {
            module,
            lines: OnceCell::default(),
        }
    }

    fn load_lines(
        &self,
        section_addresses: &[u64],
        string_table: &pdb::StringTable,
        _base_directory: &Path,
        _resolve_strategy: FileResolveStrategy,
        _convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Lines> {
        let line_program = self.module.line_program()?;

        let mut sequences = Vec::new();
        let mut line_prog_it = line_program.lines();
        while let Some(line_info) = line_prog_it.next()? {
            if line_info.offset.section == 0 {
                continue;
            }

            let addr_start = if let Some(section_addr) =
                section_addresses.get(line_info.offset.section as usize - 1)
            {
                *section_addr as u64 + line_info.offset.offset as u64
            } else {
                continue;
            };
            let addr_end = addr_start + std::cmp::max(line_info.length.unwrap_or(1) as u64, 1);

            sequences.push(Sequence {
                addr_range: addr_start..addr_end,
                line_range: line_info.line_start..(line_info.line_end + 1),
                file_index: line_info.file_index.0,
            });
        }
        sequences.sort_by_key(|seq| seq.addr_range.start);

        let mut files = Vec::new();
        let mut files_it = line_program.files();
        while let Some(file_info) = files_it.next()? {
            // FIXME for now the base_directory and preferred resolve stretegy is ignored because I
            // have not idea how I should get relative paths out of here. Going to have to find
            // some way of guessing.
            let file_name = string_table.get(file_info.name)?.to_string();
            files.push(PathBuf::from(file_name.as_ref()));
        }

        Ok(Lines {
            sequences: sequences.into_boxed_slice(),
            files: files.into_boxed_slice(),
        })
    }

    pub fn addr2line(
        &self,
        section_addresses: &[u64],
        string_table: &pdb::StringTable,
        addr: u64,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Option<(&Path, u32)>> {
        self.lines
            .get_or_try_init(|| {
                self.load_lines(
                    section_addresses,
                    string_table,
                    base_directory,
                    resolve_strategy,
                    convert_path,
                )
            })
            .map(|lines| lines.lines_for_addr(addr))
    }
}

struct Lines {
    sequences: Box<[Sequence]>,
    files: Box<[PathBuf]>,
}

impl Lines {
    fn lines_for_addr(&self, addr: u64) -> Option<(&Path, u32)> {
        let sequence = self
            .sequences
            .binary_search_by(|probe| {
                if probe.addr_range.start > addr {
                    std::cmp::Ordering::Greater
                } else if probe.addr_range.end <= addr {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
            .and_then(|seq_idx| self.sequences.get(seq_idx))?;

        let line = sequence.line_range.start;

        // FIXME sometimes multiple lines map to a range, I should handle that at some point but
        // this is okay for now.
        self.files
            .get(sequence.file_index as usize)
            .map(|f| (f.as_path(), line))
    }
}

/// Maps a contiguous region of bytes to lines.
struct Sequence {
    addr_range: Range<u64>,
    line_range: Range<u32>,
    file_index: u32,
}
