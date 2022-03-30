use anyhow::Result;
use bumpalo::Bump;
use serde::{Deserialize, Serialize};

use crate::{
  linker::{
    ebpf::CALL,
    elf_ext::{StrtabExt, SymtabExt},
  },
  types::FnvIndexMap,
};

use super::image::{HostPlatform, TargetMachine};
use super::{
  image::Image,
  local_linker::{LocalLinker, LocalObject},
};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GlobalLinkerConfig {
  pub target_machine: TargetMachine,
  pub host_platform: HostPlatform,
}

pub struct GlobalLinker<'a> {
  bump: &'a Bump,
  config: GlobalLinkerConfig,
  objects: Vec<LocalObject<'a>>,
  all_functions: FnvIndexMap<&'a str, (usize, usize)>, // name -> (obj_index, func_index)
}

impl<'a> GlobalLinker<'a> {
  pub fn new(bump: &'a Bump, config: GlobalLinkerConfig) -> Result<Self> {
    Ok(Self {
      bump,
      config,
      objects: vec![],
      all_functions: Default::default(),
    })
  }

  pub fn add_object(&mut self, name: &str, object_file: &[u8]) -> Result<()> {
    let mut local_linker = LocalLinker::new(Default::default());
    let obj = local_linker.link(
      self.bump,
      self.bump.alloc_str(name),
      self.bump.alloc_slice_copy(object_file),
    )?;
    self.objects.push(obj);
    Ok(())
  }

  pub fn emit(&mut self) -> Result<Image> {
    self.populate_all_functions()?;
    self.resolve_pseudo_calls()?;
    Ok(Image::default())
  }

  fn populate_all_functions(&mut self) -> Result<()> {
    for (obj_idx, obj) in self.objects.iter().enumerate() {
      for (func_idx, (func_name, _)) in obj.functions.iter().enumerate() {
        if let Some((obj_index, _)) = self.all_functions.get(func_name) {
          return Err(anyhow::anyhow!(
            "multiple definitions of function {} in {} and {}",
            func_name,
            self.objects[*obj_index].name,
            obj.name
          ));
        }
        self.all_functions.insert(func_name, (obj_idx, func_idx));
      }
    }
    Ok(())
  }

  fn resolve_pseudo_calls(&mut self) -> Result<()> {
    // (obj_index, section_index) -> (offset -> (func_name, func_index))
    let mut function_map: FnvIndexMap<(usize, usize), FnvIndexMap<usize, (&str, usize)>> =
      FnvIndexMap::default();
    for (name, (obj_index, func_index)) in self.all_functions.iter() {
      let func = &self.objects[*obj_index].functions[*func_index][0];
      function_map
        .entry((*obj_index, func.section_index))
        .or_default()
        .insert(func.offset, (*name, *func_index));
    }

    let objects_snapshot = self.objects.clone();
    for (obj_index, func_index) in self.all_functions.values() {
      let object = &mut self.objects[*obj_index];
      let elf = &*object.elf;
      let object_reloc = &object.reloc;
      let func = &mut object.functions[*func_index][0];
      for (idx, insn) in func.code.iter_mut().enumerate() {
        if insn.insn.opc == CALL {
          // BPF_PSEUDO_CALL
          if insn.insn.src == 1 {
            if let Some(reloc) = object_reloc.get(&(*func_index, idx * 8)) {
              let sym = elf.syms.get_result(reloc.r_sym)?;
              let sym_name = elf.shdr_strtab.get_at_result(sym.st_name)?;

              if let Some(&(obj_index, func_index)) = self.all_functions.get(sym_name) {
                insn.call_target_function = Some((obj_index, func_index));
                let target_object = &objects_snapshot[obj_index];
                let target_func = &target_object.functions[func_index][0];
                log::debug!(
                  "resolved relocated pseudo call from {}/{} to {}/{}",
                  object.name,
                  func.name,
                  target_object.name,
                  target_func.name,
                );
              } else {
                let mut ok = false;
                if sym.is_import() {
                  if let Some(helper_index) = self
                    .config
                    .host_platform
                    .helpers
                    .get(sym_name)
                    .or_else(|| self.config.target_machine.helpers.get(sym_name))
                  {
                    insn.insn.imm = *helper_index;
                    insn.insn.src = 0;
                    log::debug!(
                      "resolved helper call from {}/{} to {}",
                      object.name,
                      func.name,
                      helper_index,
                    );
                    ok = true;
                  }
                }
                if !ok {
                  return Err(anyhow::anyhow!(
                    "unresolved pseudo call from {}/{} to {}",
                    object.name,
                    func.name,
                    sym_name
                  ));
                }
              }
            } else {
              let target_offset =
                (func.offset as i32 + (idx as i32 + insn.insn.imm + 1) * 8) as usize;
              let (name, target_function_index) = *function_map
                .get(&(*obj_index, func.section_index))
                .unwrap()
                .get(&target_offset)
                .ok_or_else(|| anyhow::anyhow!("missing function at target offset"))?;
              insn.call_target_function = Some((*obj_index, target_function_index));
              log::debug!(
                "resolved local pseudo call from {}/{} to {}",
                object.name,
                func.name,
                name
              );
            }
          }
        }
      }
    }

    Ok(())
  }
}
