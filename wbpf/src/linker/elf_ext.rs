use anyhow::Result;
use goblin::{
  elf::{Elf, SectionHeader, Sym, Symtab},
  strtab::Strtab,
};

pub trait StrtabExt<'a> {
  fn get_at_result(&self, index: usize) -> Result<&'a str>;
}

impl<'a> StrtabExt<'a> for Strtab<'a> {
  fn get_at_result(&self, index: usize) -> Result<&'a str> {
    self
      .get_at(index)
      .ok_or_else(|| anyhow::anyhow!("invalid string index {}", index))
  }
}

pub trait SymtabExt {
  fn get_result(&self, index: usize) -> Result<Sym>;
}

impl<'a> SymtabExt for Symtab<'a> {
  fn get_result(&self, index: usize) -> Result<Sym> {
    self
      .get(index)
      .ok_or_else(|| anyhow::anyhow!("invalid symbol index {}", index))
  }
}

pub trait ElfExt<'a> {
  fn get_section_header_result(&self, index: usize) -> Result<&SectionHeader>;
}

impl<'a> ElfExt<'a> for Elf<'a> {
  fn get_section_header_result(&self, index: usize) -> Result<&SectionHeader> {
    self
      .section_headers
      .get(index)
      .ok_or_else(|| anyhow::anyhow!("invalid section index {}", index))
  }
}
