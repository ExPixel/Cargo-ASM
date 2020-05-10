use super::{FileResolveStrategy, LineMapper};
use crate::platform::PathConverter;
use once_cell::unsync::OnceCell;
use std::ops::Range;
use std::path::{Path, PathBuf};

pub type UnitRange = (Range<u64>, usize);

pub struct DwarfLineMapper<R: gimli::Reader> {
    dwarf: gimli::Dwarf<R>,
    /// Maps ranges of addresses to compilation units. Each range is associated with an index into
    /// the `units` vector.
    unit_ranges: Vec<UnitRange>,
    units: Vec<LazyUnit<R>>,

    base_directory: PathBuf,
    resolve_strategy: FileResolveStrategy,
}

impl<R: gimli::Reader> DwarfLineMapper<R> {
    pub fn new<L, S>(
        loader: L,
        sup_loader: S,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
    ) -> anyhow::Result<Self>
    where
        L: Fn(gimli::SectionId) -> Result<R, anyhow::Error>,
        S: Fn(gimli::SectionId) -> Result<R, anyhow::Error>,
    {
        let dwarf = gimli::Dwarf::load(loader, sup_loader)?;

        // FIXME make loading compilation units lazy so that there is no penalty
        //       if DWARF life mappings are not requested.
        let (units, unit_ranges) = Self::find_compilation_units(&dwarf)?;

        Ok(DwarfLineMapper {
            dwarf,
            unit_ranges,
            units,
            base_directory: PathBuf::from(base_directory),
            resolve_strategy,
        })
    }

    fn unit_index_for_address(&self, seek_addr: u64) -> Option<usize> {
        self.unit_ranges
            .binary_search_by(|probe| {
                if probe.0.start > seek_addr {
                    std::cmp::Ordering::Greater
                } else if probe.0.end <= seek_addr {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .map(|range_index| self.unit_ranges[range_index].1)
            .ok()
    }

    fn find_compilation_units(
        dwarf: &gimli::Dwarf<R>,
    ) -> anyhow::Result<(Vec<LazyUnit<R>>, Vec<UnitRange>)> {
        let mut lazy_units = Vec::new();
        let mut unit_ranges = Vec::new();

        let mut unit_headers = dwarf.units();
        while let Some(unit_header) = unit_headers.next()? {
            let unit = if let Ok(unit) = dwarf.unit(unit_header) {
                unit
            } else {
                continue;
            };

            Self::add_compilation_unit(dwarf, unit, &mut lazy_units, &mut unit_ranges)?;
        }

        unit_ranges.sort_unstable_by_key(|r| r.0.start);

        Ok((lazy_units, unit_ranges))
    }

    fn add_compilation_unit(
        dwarf: &gimli::Dwarf<R>,
        unit: gimli::Unit<R>,
        lazy_units: &mut Vec<LazyUnit<R>>,
        unit_ranges: &mut Vec<UnitRange>,
    ) -> anyhow::Result<()> {
        let mut entries = unit.entries_raw(None)?;

        let abbrev = match entries.read_abbreviation()? {
            Some(abbrev) if abbrev.tag() == gimli::DW_TAG_compile_unit => abbrev,
            _ => return Ok(()),
        };

        let mut start_addr = None;
        let mut end_addr = None;
        let mut size = None;
        let mut ranges = None;
        let mut lang = None;

        for spec in abbrev.attributes() {
            let attr = entries.read_attribute(*spec)?;

            match attr.name() {
                gimli::DW_AT_low_pc => {
                    if let gimli::AttributeValue::Addr(val) = attr.value() {
                        start_addr = Some(val);
                    }
                }

                gimli::DW_AT_high_pc => {
                    if let gimli::AttributeValue::Addr(val) = attr.value() {
                        end_addr = Some(val);
                    } else if let Some(val) = attr.udata_value() {
                        size = Some(val);
                    }
                }

                gimli::DW_AT_ranges => {
                    ranges = dwarf.attr_ranges_offset(&unit, attr.value())?;
                }

                gimli::DW_AT_language => {
                    if let gimli::AttributeValue::Language(val) = attr.value() {
                        lang = Some(val);
                    }
                }

                _ => { /* NOP */ }
            }
        }

        let unit_index = lazy_units.len();
        if let Some(offset) = ranges {
            let mut ranges = dwarf.ranges(&unit, offset)?;
            while let Some(range) = ranges.next()? {
                unit_ranges.push((range.begin..range.end, unit_index));
            }
        } else if let (Some(begin), Some(end)) = (start_addr, end_addr) {
            unit_ranges.push((begin..end, unit_index));
        } else if let (Some(begin), Some(size)) = (start_addr, size) {
            unit_ranges.push((begin..(begin + size), unit_index));
        }

        lazy_units.push(LazyUnit::new(unit, lang));

        Ok(())
    }
}

impl<R: gimli::Reader> LineMapper for DwarfLineMapper<R> {
    fn map_address_to_line(
        &self,
        address: u64,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Option<(&Path, u32)>> {
        if let Some(unit_index) = self.unit_index_for_address(address) {
            self.units[unit_index].addr2line(
                &self.dwarf,
                address,
                &self.base_directory,
                self.resolve_strategy,
                convert_path,
            )
        } else {
            Ok(None)
        }
    }
}

pub struct LazyUnit<R: gimli::Reader> {
    unit: gimli::Unit<R>,

    // FIXME use this for syntax hilighting maybe...or just remove it.
    #[allow(dead_code)]
    lang: Option<gimli::DwLang>,

    lines: OnceCell<Lines>,
}

impl<R: gimli::Reader> LazyUnit<R> {
    pub fn new(unit: gimli::Unit<R>, lang: Option<gimli::DwLang>) -> LazyUnit<R> {
        LazyUnit {
            unit,
            lang,
            lines: OnceCell::default(),
        }
    }

    fn lines(
        &self,
        dwarf: &gimli::Dwarf<R>,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<&Lines> {
        self.lines.get_or_try_init(|| {
            self.load_lines(dwarf, base_directory, resolve_strategy, convert_path)
        })
    }

    fn load_lines(
        &self,
        dwarf: &gimli::Dwarf<R>,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Lines> {
        let inc_line_program = match self.unit.line_program {
            Some(ref line_prog) => line_prog,
            None => return Ok(Lines::empty()),
        };

        let mut sequences = Vec::new();
        let mut rows = inc_line_program.clone().rows();
        let mut lines = Vec::new();

        let mut seq_start_addr = 0;
        let mut seq_prev_addr = 0;

        while let Some((_, row)) = rows.next_row()? {
            let address = row.address();

            if row.end_sequence() {
                if seq_start_addr != 0 && !lines.is_empty() {
                    // FIXME lines should be sorted by address I think but I'm not sure. If not I
                    //       should sort them here.
                    sequences.push(Sequence {
                        range: seq_start_addr..address,
                        lines: std::mem::replace(&mut lines, Vec::new()).into_boxed_slice(),
                    });
                } else {
                    // FIXME I'm not sure why it's not okay for the start address to be 0 (???)
                    //       It doesn't SEEM valid anyway.
                    lines.clear();
                }
            }

            let file = row.file_index() as usize;
            let line = row.line().unwrap_or(0) as u32;

            if !lines.is_empty() {
                if seq_prev_addr == address {
                    let last_line = lines.last_mut().unwrap();
                    last_line.file = file as usize;
                    last_line.line = line;
                    continue;
                } else {
                    seq_prev_addr = address;
                }
            } else {
                seq_start_addr = address;
                seq_prev_addr = address;
            }

            lines.push(Line {
                addr: address,
                file,
                line,
            });
        }

        sequences.sort_by_key(|seq| seq.range.start);

        let mut files = Vec::new();
        let header = inc_line_program.header();
        let mut idx = 0;
        while let Some(file) = header.file(idx) {
            files.push(self.render_file(
                file,
                &header,
                dwarf,
                base_directory,
                resolve_strategy,
                convert_path,
            )?);
            idx += 1;
        }

        Ok(Lines {
            sequences: sequences.into_boxed_slice(),
            files: files.into_boxed_slice(),
        })
    }

    fn render_file(
        &self,
        file: &gimli::FileEntry<R, R::Offset>,
        header: &gimli::LineProgramHeader<R, R::Offset>,
        dwarf: &gimli::Dwarf<R>,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<PathBuf> {
        let preferred_path = self.subrender_file(
            file,
            header,
            dwarf,
            base_directory,
            resolve_strategy,
            convert_path,
        )?;

        if preferred_path.is_file() {
            Ok(preferred_path)
        } else {
            // FIXME reuse the preferred path when the `clear` is stabilized for PathBuf.
            self.subrender_file(
                file,
                header,
                dwarf,
                base_directory,
                resolve_strategy.other(),
                convert_path,
            )
        }
    }

    pub fn addr2line(
        &self,
        dwarf: &gimli::Dwarf<R>,
        addr: u64,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<Option<(&Path, u32)>> {
        self.lines(dwarf, base_directory, resolve_strategy, convert_path)
            .map(|lines| lines.lines_for_addr(addr))
    }

    /// This should only be called by `render_file`
    fn subrender_file(
        &self,
        file: &gimli::FileEntry<R, R::Offset>,
        header: &gimli::LineProgramHeader<R, R::Offset>,
        dwarf: &gimli::Dwarf<R>,
        base_directory: &Path,
        resolve_strategy: FileResolveStrategy,
        convert_path: &dyn PathConverter,
    ) -> anyhow::Result<PathBuf> {
        let mut path = if resolve_strategy == FileResolveStrategy::PreferRelative {
            PathBuf::from(base_directory)
        } else {
            PathBuf::new()
        };

        if let Some(ref comp_dir) = self.unit.comp_dir {
            let comp_dir = comp_dir.to_string_lossy()?;

            if resolve_strategy == FileResolveStrategy::PreferAbsolute
                || convert_path.is_relative(comp_dir.as_ref())
            {
                let comp_dir = convert_path.convert(comp_dir.as_ref());
                path.push(comp_dir.as_ref());
            }
        }

        if let Some(directory) = file.directory(header) {
            let directory_raw = dwarf.attr_string(&self.unit, directory)?;
            let directory = directory_raw.to_string_lossy()?;

            if resolve_strategy == FileResolveStrategy::PreferAbsolute
                || convert_path.is_relative(directory.as_ref())
            {
                let directory = convert_path.convert(directory.as_ref());
                path.push(directory.as_ref());
            }
        }

        path.push(
            dwarf
                .attr_string(&self.unit, file.path_name())?
                .to_string_lossy()?
                .as_ref(),
        );

        Ok(path)
    }
}

struct Lines {
    sequences: Box<[Sequence]>,
    files: Box<[PathBuf]>,
}

impl Lines {
    pub fn empty() -> Lines {
        Lines {
            sequences: Box::new([] as [Sequence; 0]),
            files: Box::new([] as [PathBuf; 0]),
        }
    }

    fn lines_for_addr(&self, addr: u64) -> Option<(&Path, u32)> {
        let sequence = self
            .sequences
            .binary_search_by(|probe| {
                if probe.range.start > addr {
                    std::cmp::Ordering::Greater
                } else if probe.range.end <= addr {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .ok()
            .and_then(|seq_idx| self.sequences.get(seq_idx))?;

        sequence
            .lines
            .binary_search_by(|probe| probe.addr.cmp(&addr))
            .ok()
            .and_then(|line_idx| sequence.lines.get(line_idx))
            .map(|line| (self.files[line.file].as_path(), line.line))
    }
}

/// Contiguous sequence of bytes and their associated lines.
struct Sequence {
    range: Range<u64>,
    lines: Box<[Line]>,
}

struct Line {
    addr: u64,
    file: usize,
    line: u32,
}
