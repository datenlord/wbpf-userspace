use std::fmt::Display;

use crate::types::FnvIndexMap;

use super::{ebpf::LD_DW_IMM, image::Image};

pub struct DisassembledImage<'a> {
  image: &'a Image,
}

impl<'a> DisassembledImage<'a> {
  pub fn new(image: &'a Image) -> Self {
    Self { image }
  }
}

impl<'a> Display for DisassembledImage<'a> {
  fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
    let offset_to_func = self
      .image
      .offset_table
      .as_ref()
      .map(|x| {
        x.func_offsets
          .iter()
          .map(|(name, offset)| (*offset as usize, name.as_str()))
          .collect::<FnvIndexMap<_, _>>()
      })
      .unwrap_or_default();
    let mut off = 0usize;
    while off < self.image.code.len() {
      if let Some(func_name) = offset_to_func.get(&off) {
        writeln!(f, "\n{}:", func_name)?;
      }
      let insn_len = if self.image.code[off] == LD_DW_IMM {
        16usize
      } else {
        8usize
      };
      let insn = super::ebpf_disassembler::to_insn_vec(&self.image.code[off..off + insn_len])
        .into_iter()
        .next()
        .unwrap();
      writeln!(f, "\t{}: {}", off, insn.desc)?;
      off += insn_len;
    }
    Ok(())
  }
}
