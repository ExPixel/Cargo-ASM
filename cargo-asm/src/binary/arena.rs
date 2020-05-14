use std::marker::PhantomData;

pub const CHUNK_SIZE: usize = 1024;

#[derive(Debug)]
pub struct SymbolArena<'a> {
    chunks: Vec<SymbolsChunk>,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> SymbolArena<'a> {
    pub fn new() -> SymbolArena<'static> {
        SymbolArena {
            chunks: Vec::new(),
            _phantom: PhantomData,
        }
    }

    pub unsafe fn alloc(&mut self, data: &str) -> &'a str {
        if let Some(ref mut chunk) = self.chunks.last_mut() {
            if chunk.remaining >= data.len() {
                return std::mem::transmute(chunk.push(data));
            }
        }

        let mut chunk = SymbolsChunk::new(std::cmp::max(CHUNK_SIZE, data.len()));
        let allocated = std::mem::transmute(chunk.push(data));
        self.chunks.push(chunk);
        allocated
    }
}

#[derive(Debug)]
struct SymbolsChunk {
    data: Box<[u8]>,
    remaining: usize,
}

impl SymbolsChunk {
    fn new(size: usize) -> SymbolsChunk {
        let mut chunk = Vec::with_capacity(size);
        chunk.resize_with(size, || 0xCE);

        SymbolsChunk {
            data: chunk.into_boxed_slice(),
            remaining: size,
        }
    }

    fn push<'s>(&'s mut self, s: &str) -> &'s str {
        let start = self.data.len() - self.remaining;
        self.remaining -= s.len();
        let end = start + s.len();
        (&mut self.data[start..end]).copy_from_slice(s.as_bytes());
        unsafe { std::str::from_utf8_unchecked(&self.data[start..end]) }
    }
}
