mod amd64;

use crate::binary::{BinaryArch, Symbol};
use amd64::*;
use capstone::prelude::*;
use capstone::Insn;
use std::ops::RangeInclusive;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct InnerJump {
    /// The index that we are jumping from.
    pub source: usize,

    /// The index that we are jumping to.
    pub target: usize,

    pub display_offset: usize,
}

impl PartialOrd for InnerJump {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for InnerJump {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.source.cmp(&other.source)
    }
}

pub struct InnerJumpTable {
    jumps: Vec<InnerJump>,
    max_display_offset: usize,
}

impl InnerJumpTable {
    pub fn new() -> InnerJumpTable {
        InnerJumpTable {
            jumps: Vec::new(),
            max_display_offset: 0,
        }
    }

    pub fn clear(&mut self) {
        self.jumps.clear();
        self.max_display_offset = 0;
    }

    pub fn insert(&mut self, source: usize, target: usize) {
        self.jumps.push(InnerJump {
            source,
            target,
            display_offset: 0,
        })
    }

    pub fn max_display_offset(&self) -> usize {
        self.max_display_offset
    }

    fn sort_and_calc_overlaps(&mut self) {
        self.jumps.sort();
        self.max_display_offset = 0;
        for idx in (0..self.jumps.len()).rev() {
            let range = self.jumps[idx].source..=self.jumps[idx].target;

            let mut display_offset = 0;

            // FIXME I can probably make this faster but It's not THAT with the considering the
            // number of jumps you're likely to find in any given function.
            let mut continue_search = true;
            while continue_search {
                continue_search = false;
                for lower_jump in self
                    .jumps
                    .iter()
                    .filter(|j| do_ranges_overlap(range.clone(), j.source..=j.target))
                {
                    if lower_jump.display_offset == display_offset {
                        display_offset += 2;
                        continue_search = true;
                    }
                }
            }

            self.jumps[idx].display_offset = display_offset;
            self.max_display_offset = std::cmp::max(self.max_display_offset, display_offset);
        }
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = &InnerJump> {
        self.jumps.iter()
    }
}

pub struct OperandPatches<'s> {
    patches: Vec<Option<&'s Symbol<'s>>>,
}

impl<'s> OperandPatches<'s> {
    pub fn new() -> OperandPatches<'s> {
        OperandPatches {
            patches: Vec::new(),
        }
    }

    pub fn clear(&mut self) {
        self.patches.clear();
    }

    pub fn insert(&mut self, index: usize, symbol: &'s Symbol<'s>) {
        if self.patches.len() <= index {
            self.patches.resize_with(index + 1, Default::default);
        }
        self.patches[index] = Some(symbol);
    }

    pub fn get(&self, index: usize) -> Option<&str> {
        // FIXME make using the short/long name configurable.
        self.patches
            .get(index)
            .and_then(|sym| sym.as_ref().map(|s| s.short_demangled_name()))
    }
}

fn do_ranges_overlap(a: RangeInclusive<usize>, b: RangeInclusive<usize>) -> bool {
    let a_top = std::cmp::min(*a.start(), *a.end());
    let b_bot = std::cmp::max(*b.start(), *b.end());
    if a_top >= b_bot {
        return false;
    }

    let a_bot = std::cmp::max(*a.start(), *a.end());
    let b_top = std::cmp::min(*b.start(), *b.end());
    if b_top >= a_bot {
        return false;
    }

    true
}

pub fn analyze_instructions<'i, 's>(
    symbols: &'s [Symbol<'s>],
    arch: BinaryArch,
    cs: &Capstone,
    instrs: &[Insn<'i>],
    jumps: &mut InnerJumpTable,
    op_patches: &mut OperandPatches<'s>,
) -> anyhow::Result<()> {
    #[allow(clippy::single_match)]
    match arch {
        BinaryArch::AMD64 => analyze_instructions_amd64(symbols, cs, instrs, jumps, op_patches)?,
        _ => { /* NOP */ }
    }

    jumps.sort_and_calc_overlaps();

    Ok(())
}
