use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub struct FileLineCache {
    lines_for_path: HashMap<PathBuf, Lines>,
}

impl FileLineCache {
    pub fn new() -> FileLineCache {
        FileLineCache {
            lines_for_path: HashMap::new(),
        }
    }

    pub fn get_line<P: AsRef<Path>>(&mut self, path: P, line: u32) -> Option<&str> {
        let path = path.as_ref();

        // FIXME can't use this until I have raw entries from nightly.
        // self.lines_for_path.entry(&path).or_insert_with(|| {
        //     Lines::load(path).unwrap_or_else(
        // }).get_line(line)

        // It's okay, I promise.
        let lines_for_path_ref: &'static HashMap<PathBuf, Lines> =
            unsafe { std::mem::transmute(&self.lines_for_path) };

        if let Some(ref lines) = lines_for_path_ref.get(path) {
            lines.get_line(line)
        } else {
            let lines = Lines::load(path).unwrap_or_else(|_| Lines::empty());
            self.lines_for_path
                .entry(PathBuf::from(path))
                .or_insert(lines)
                .get_line(line)
        }
    }
}

struct Lines {
    contents: String,

    // FIXME I don't respect files larger than 4GB >:(
    line_map: Vec<(u32, u32)>,
}

impl Lines {
    fn empty() -> Lines {
        Lines {
            contents: String::new(),
            line_map: Vec::new(),
        }
    }

    fn get_line(&self, line_index: u32) -> Option<&str> {
        if line_index == 0 || line_index as usize > self.line_map.len() {
            None
        } else {
            let (start, end) = self.line_map[line_index as usize - 1];
            Some(&self.contents[(start as usize)..(end as usize)])
        }
    }

    fn load(path: &Path) -> anyhow::Result<Lines> {
        use std::fs::File;
        use std::io::{BufRead, BufReader};

        let mut contents = String::new();
        let mut line_map = Vec::new();

        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        let mut start = 0;
        while let Ok(bytes_read) = reader.read_line(&mut contents) {
            if bytes_read == 0 {
                break;
            }
            contents.truncate(contents.trim_end().len());
            let end = contents.len() as u32;
            line_map.push((start, end));
            start = end;
        }

        Ok(Lines { contents, line_map })
    }
}
