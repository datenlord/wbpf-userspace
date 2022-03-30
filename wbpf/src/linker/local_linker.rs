use std::{collections::BTreeMap, rc::Rc};

use crate::{
  linker::{
    ebpf::{get_insn, EXIT},
    elf_ext::{ElfExt, StrtabExt},
  },
  types::FnvIndexMap,
};
use anyhow::Result;
use bumpalo::Bump;
use goblin::{
  elf::{Elf, Reloc},
  elf64::{header::EM_BPF, sym::STB_GLOBAL},
};
use heapless::Vec as HVec;
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use super::ebpf::Insn;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LocalLinkerConfig {}

pub struct LocalLinker {
  config: LocalLinkerConfig,
}

#[derive(Clone)]
pub struct LocalObject<'a> {
  pub name: &'a str,
  pub elf: Rc<Elf<'a>>,
  pub raw: &'a [u8],
  pub functions: FnvIndexMap<&'a str, Vec<Function<'a>>>,
  pub reloc: FnvIndexMap<(usize, usize), Reloc>, // (func_idx, offset) -> reloc
}

#[derive(Clone, Default)]
pub struct Function<'a> {
  pub name: &'a str,
  pub section_index: usize,
  pub offset: usize,
  pub code: Vec<AnnotatedInsn>,
  pub global: bool,
  pub return_offset: Option<i32>,
}

impl<'a> Function<'a> {
  pub fn end_offset(&self) -> usize {
    self.offset + self.code.len() * 8
  }
}

#[derive(Clone)]
pub struct AnnotatedInsn {
  pub insn: Insn,
  pub call_target_function: Option<(usize, usize)>, // (object_index, func_index)
}

impl LocalLinker {
  pub fn new(config: LocalLinkerConfig) -> Self {
    Self { config }
  }

  pub fn link<'a>(
    &mut self,
    bump: &'a Bump,
    object_name: &'a str,
    object_file: &'a [u8],
  ) -> Result<LocalObject<'a>> {
    let elf = Elf::parse(object_file)?;
    if elf.header.e_machine != EM_BPF {
      return Err(anyhow::anyhow!("not a BPF image: {:?}", elf));
    }

    let mut obj = LocalObject {
      name: object_name,
      elf: Rc::new(elf),
      raw: object_file,
      functions: Default::default(),
      reloc: Default::default(),
    };
    obj.populate_functions(bump)?;
    obj.populate_reloc()?;
    Ok(obj)
  }
}

impl<'a> LocalObject<'a> {
  fn populate_functions(&mut self, _bump: &'a Bump) -> Result<()> {
    for sym in self.elf.syms.iter() {
      if !sym.is_function() {
        continue;
      }
      let name = self.elf.shdr_strtab.get_at_result(sym.st_name)?;
      let mut func = Function::default();
      func.global = sym.st_bind() == STB_GLOBAL;
      func.name = name;

      let shdr = self.elf.get_section_header_result(sym.st_shndx)?;
      let file_range = shdr
        .file_range()
        .ok_or_else(|| anyhow::anyhow!("missing file range"))?;
      let prog = self
        .raw
        .get(file_range)
        .ok_or_else(|| anyhow::anyhow!("file range out of bounds"))?;
      let subslice = prog
        .get(sym.st_value as usize..)
        .ok_or_else(|| anyhow::anyhow!("function out of range"))?;
      let subslice = subslice
        .iter()
        .chunks(8)
        .into_iter()
        .map(|x| x.into_iter().copied().collect::<HVec<u8, 8>>())
        .take_while(|x| x.len() == 8 && get_insn(x, 0).opc != EXIT)
        .chain(std::iter::once(
          HVec::<u8, 8>::from_slice(&[0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap(),
        )) // exit
        .flatten()
        .collect::<Vec<_>>();

      for i in 0..subslice.len() / 8 {
        let insn = get_insn(&subslice, i);
        let annotated = AnnotatedInsn {
          insn,
          call_target_function: None,
        };
        func.code.push(annotated);
      }

      func.section_index = sym.st_shndx;
      func.offset = sym.st_value as usize;

      self.functions.insert(name, vec![func]);
    }
    Ok(())
  }
  fn populate_reloc(&mut self) -> Result<()> {
    // (section_index, start_offset) -> func_index
    let function_lookup_table: BTreeMap<(usize, usize), usize> = self
      .functions
      .iter()
      .enumerate()
      .map(|(func_index, funcs)| {
        let func = funcs.1.first().unwrap();
        ((func.section_index, func.offset), func_index)
      })
      .collect();
    for (reloc_section_index, reloc) in &self.elf.shdr_relocs {
      let reloc_section = self.elf.get_section_header_result(*reloc_section_index)?;
      let link_section_index = reloc_section.sh_info;
      for reloc in reloc.iter() {
        let target_function = function_lookup_table
          .range(
            (link_section_index as usize, 0)
              ..=(link_section_index as usize, reloc.r_offset as usize),
          )
          .rev()
          .next()
          .and_then(|x| {
            if self.functions[*x.1][0].end_offset() > reloc.r_offset as usize {
              Some(*x.1)
            } else {
              None
            }
          });
        let target_function = if let Some(x) = target_function {
          x
        } else {
          log::warn!(
            "cannot resolve reloc for section {} offset {}",
            link_section_index,
            reloc.r_offset
          );
          continue;
        };
        let func = self.functions[target_function].first().unwrap();
        self.reloc.insert(
          (target_function, reloc.r_offset as usize - func.offset),
          reloc,
        );
      }
    }
    Ok(())
  }
}
