use super::lines::{Line, Lines, Sequence};
use super::{FileResolveStrategy, LineMapper};
use crate::platform::PathConverter;
use once_cell::unsync::OnceCell;
use pdb::FallibleIterator as _;
use std::cell::{Cell, RefCell, RefMut};
use std::collections::HashMap;
use std::ops::Range;
use std::path::{Path, PathBuf};

pub struct PDBLineMapper<'a> {
    section_addresses: Vec<u64>,
    modules: Vec<pdb::ModuleInfo<'a>>,
    base_directory: PathBuf,
    resolve_strategy: FileResolveStrategy,
    previous_module_index: usize,
    module_files: HashMap<(usize, pdb::FileIndex), PathBuf>,
}

impl<'a> PDBLineMapper<'a> {
    pub fn new<S: 'a + pdb::Source<'a>>(
        section_addresses: Vec<u64>,
        mut pdb: RefMut<'a, pdb::PDB<'a, S>>,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
    ) -> anyhow::Result<Self> {
        let debug_information = pdb.debug_information()?;
        let mut modules = Vec::new();

        let mut modules_iter = debug_information.modules()?;
        while let Some(module) = modules_iter.next()? {
            if let Some(module_info) = pdb.module_info(&module)? {
                modules.push(module_info);
            }
        }

        Ok(PDBLineMapper {
            section_addresses,
            modules,
            base_directory: PathBuf::from(base_directory),
            resolve_strategy,
            previous_module_index: 0,
            module_files: HashMap::new(),
        })
    }

    fn path_and_line<'c>(
        cache: &'c mut HashMap<(usize, pdb::FileIndex), PathBuf>,
        module_index: usize,
        line_program: &pdb::LineProgram,
        info: pdb::LineInfo,
    ) -> (&'c Path, u32) {
        let key = (module_index, info.file_index);

        let path = cache.entry(key).or_insert_with(|| {
            todo!();
        });

        (path, info.line_start)
    }
}

impl<'a> LineMapper for PDBLineMapper<'a> {
    fn map_address_to_line(
        &mut self,
        address: u64,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Option<(&Path, u32)>> {
        if self.previous_module_index != 0 {
            let line_program = self.modules[self.previous_module_index].line_program()?;
            if let Some(line_info) =
                find_address_in_line_program(address, &self.section_addresses, &line_program)?
            {
                print!("%% PREV %%  ");
                return Ok(Some(Self::path_and_line(
                    &mut self.module_files,
                    self.previous_module_index,
                    &line_program,
                    line_info,
                )));
            }
        }

        for (idx, module) in self.modules.iter().enumerate() {
            let line_program = module.line_program()?;
            if let Some(line_info) =
                find_address_in_line_program(address, &self.section_addresses, &line_program)?
            {
                self.previous_module_index = idx;
                print!("%% NEW  %%  ");
                return Ok(Some(Self::path_and_line(
                    &mut self.module_files,
                    idx,
                    &line_program,
                    line_info,
                )));
            }
        }
        self.previous_module_index = 0;

        return Ok(None);
    }
}

fn find_address_in_line_program<'a>(
    address: u64,
    section_addresses: &[u64],
    line_program: &pdb::LineProgram<'a>,
) -> anyhow::Result<Option<pdb::LineInfo>> {
    let mut lines = line_program.lines();
    while let Some(line_info) = lines.next()? {
        if line_info.offset.section == 0 {
            continue;
        }

        let line_start_address = if let Some(section_addr) =
            section_addresses.get(line_info.offset.section as usize - 1)
        {
            *section_addr as u64 + line_info.offset.offset as u64
        } else {
            continue;
        };
        let line_end_address =
            line_start_address + std::cmp::max(line_info.length.unwrap_or(1) as u64, 1);

        if (line_start_address..line_end_address).contains(&address) {
            return Ok(Some(line_info));
        }
    }
    Ok(None)
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
        addr: u64,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Lines> {
        let line_program = self.module.line_program()?;

        let mut sequences = Vec::new();
        let mut lines = Vec::new();

        let mut seq_start_addr = 0;
        let mut seq_end_addr = 0; // the previous end address

        let mut line_prog_it = line_program.lines();
        while let Some(line_info) = line_prog_it.next()? {
            if line_info.offset.section == 0 {
                continue;
            }

            let address_start = if let Some(section_addr) =
                section_addresses.get(line_info.offset.section as usize - 1)
            {
                *section_addr as u64 + line_info.offset.offset as u64
            } else {
                continue;
            };
            let address_end =
                address_start + std::cmp::max(line_info.length.unwrap_or(1) as u64, 1) - 1;

            let file = line_info.file_index;
            if !lines.is_empty() {
                todo!();
            } else {
                seq_start_addr = address_start;
                seq_end_addr = address_end;
            }

            for n in (line_info.line_start..=line_info.line_end) {
                todo!(); // #TODO
                         // lines.push(Line {
                         // });
            }
        }

        todo!();
    }

    pub fn addr2line(
        &self,
        section_addresses: &[u64],
        addr: u64,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Option<(&Path, u32)>> {
        self.lines
            .get_or_try_init(|| {
                self.load_lines(
                    section_addresses,
                    addr,
                    base_directory,
                    resolve_strategy,
                    convert_path,
                )
            })
            .map(|lines| lines.lines_for_addr(addr))
    }
}
