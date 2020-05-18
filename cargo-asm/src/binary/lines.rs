use std::ops::Range;
use std::path::{Path, PathBuf};

pub struct Lines {
    pub sequences: Box<[Sequence]>,
    pub files: Box<[PathBuf]>,
}

impl Lines {
    pub fn empty() -> Lines {
        Lines {
            sequences: Box::new([] as [Sequence; 0]),
            files: Box::new([] as [PathBuf; 0]),
        }
    }

    pub fn lines_for_addr(&self, addr: u64) -> Option<(&Path, u32)> {
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
pub struct Sequence {
    pub range: Range<u64>,
    pub lines: Box<[Line]>,
}

pub struct Line {
    pub addr: u64,
    pub file: usize,
    pub line: u32,
}
