mod amd64;

use crate::binary::BinaryArch;
use amd64::*;
use capstone::prelude::*;
use std::ops::RangeInclusive;

pub struct Jump {
    src: u64,
    dest: u64,
    overlaps: u32,
}

pub struct JumpTable {
    addrs: Vec<(u64, Option<u64>)>,
}

impl JumpTable {
    pub fn new() -> JumpTable {
        JumpTable { addrs: Vec::new() }
    }

    pub fn sort(&mut self) {
        use std::cmp::Ordering;

        self.addrs.sort_by(|lhs, rhs| match lhs.0.cmp(&rhs.0) {
            Ordering::Equal => match (lhs.1, rhs.1) {
                (Some(lt), Some(rt)) => lt.cmp(&rt),
                (None, Some(_rt)) => Ordering::Less,
                (Some(_lt), None) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            },
            other => other,
        });
    }

    pub fn push(&mut self, from: u64, dest: Option<u64>) {
        self.addrs.push((from, dest));
    }

    /// Returns true if the table contains the given jump source location.
    pub fn contains_src(&self, addr: u64) -> bool {
        self.addrs.iter().any(|(src, _)| *src == addr)
    }

    pub fn find_jump(&self, addr: u64) -> Option<u64> {
        self.iter_with_dest()
            .find(|(src, _)| *src == addr)
            .map(|(_, dst)| dst)
    }

    pub fn iter(&self) -> impl '_ + Iterator<Item = (u64, Option<u64>)> {
        self.addrs.iter().copied()
    }

    pub fn iter_with_dest(&self) -> impl '_ + Iterator<Item = (u64, u64)> {
        self.addrs
            .iter()
            .filter_map(|(src, dst)| dst.map(|d| (*src, d)))
    }

    pub fn addrs(&self) -> &[(u64, Option<u64>)] {
        &self.addrs
    }

    // pub fn ranges(&self) -> impl '_ + Iterator<Item = RangeInclusive<u64>> {
    //     self.iter_with_dest()
    //         .map(|(src, dst)| RangeInclusive::new(src, dst))
    // }
}

pub fn analyze_jumps<'a>(
    arch: BinaryArch,
    cs: &Capstone,
    instrs: impl 'a + Iterator<Item = capstone::Insn<'a>>,
) -> anyhow::Result<JumpTable> {
    let mut jumps = match arch {
        BinaryArch::AMD64 => analyze_jumps_amd64(cs, instrs),
        _ => {
            eprintln!("jump analysis for arch {:?} not yet supported", arch);
            Ok(JumpTable::new())
        }
    };

    if let Ok(ref mut j) = jumps {
        j.sort();
    }

    jumps
}
