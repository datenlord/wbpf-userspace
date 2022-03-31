use anyhow::Result;
use bumpalo::Bump;
use serde::{Deserialize, Serialize};

use crate::{
  linker::{
    ebpf::{CALL, LD_DW_IMM},
    elf_ext::{StrtabExt, SymtabExt},
  },
  types::FnvIndexMap,
};

use super::{
  ebpf::{get_insn, Insn, EXIT, JA},
  image::{HostPlatform, TargetMachine},
};
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
  image: Vec<u8>,
}

impl<'a> GlobalLinker<'a> {
  pub fn new(bump: &'a Bump, config: GlobalLinkerConfig) -> Result<Self> {
    Ok(Self {
      bump,
      config,
      objects: vec![],
      all_functions: Default::default(),
      image: vec![],
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
    self.emit_image()?;
    self.rewrite_image_call_return()?;
    self.print_disassembly();
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
      let func = &self.objects[*obj_index].functions[*func_index];
      function_map
        .entry((*obj_index, func.section_index))
        .or_default()
        .insert(func.offset, (*name, *func_index));
    }

    let objects_snapshot = self.objects.clone();
    for (obj_index, func_index) in self.all_functions.values() {
      let object = &mut self.objects[*obj_index];
      let elf = &*object.elf;
      let object_reloc = &mut object.reloc;
      let func = &mut object.functions[*func_index];
      for (idx, insn) in func.code.iter_mut().enumerate() {
        if insn.insn.opc == CALL {
          // BPF_PSEUDO_CALL
          if insn.insn.src == 1 {
            if let Some(reloc) = object_reloc.remove(&(*func_index, idx * 8)) {
              let sym = elf.syms.get_result(reloc.r_sym)?;
              let sym_name = elf.shdr_strtab.get_at_result(sym.st_name)?;

              if let Some(&(obj_index, func_index)) = self.all_functions.get(sym_name) {
                insn.call_target_function = Some((obj_index, func_index));
                let target_object = &objects_snapshot[obj_index];
                let target_func = &target_object.functions[func_index];
                log::debug!(
                  "resolved relocated pseudo call from {}:{} to {}:{}",
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
                      "resolved helper call from {}:{} to {}",
                      object.name,
                      func.name,
                      helper_index,
                    );
                    ok = true;
                  }
                }
                if !ok {
                  return Err(anyhow::anyhow!(
                    "unresolved pseudo call from {}:{} to {}",
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
                "resolved local pseudo call from {}:{} to {}",
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

  fn emit_image(&mut self) -> Result<()> {
    for &(obj_index, func_index) in self.all_functions.values() {
      let object = &mut self.objects[obj_index];
      let func = &mut object.functions[func_index];
      func.global_linked_offset = self.image.len();
      log::info!(
        "emitting function {}:{} at {} len {}",
        object.name,
        func.name,
        func.global_linked_offset,
        func.code.len()
      );

      for insn in &func.code {
        self.image.extend_from_slice(&insn.insn.to_array());
      }
    }

    Ok(())
  }

  fn print_disassembly(&self) {
    let offset_to_func = self
      .all_functions
      .values()
      .map(|&(obj_index, func_index)| {
        let object = &self.objects[obj_index];
        let func = &object.functions[func_index];
        (func.global_linked_offset, (obj_index, func_index))
      })
      .collect::<FnvIndexMap<_, _>>();
    let mut off = 0usize;
    while off < self.image.len() {
      if let Some((obj_index, func_index)) = offset_to_func.get(&off) {
        let object = &self.objects[*obj_index];
        let func = &object.functions[*func_index];
        println!("\n<{}:{}>:", object.name, func.name);
      }
      let insn_len = if self.image[off] == LD_DW_IMM {
        16usize
      } else {
        8usize
      };
      let insn = super::ebpf_disassembler::to_insn_vec(&self.image[off..off + insn_len])
        .into_iter()
        .next()
        .unwrap();
      println!("\t{}", insn.desc);
      off += insn_len;
    }
  }

  fn rewrite_image_call_return(&mut self) -> Result<()> {
    let func_to_offset = self
      .all_functions
      .values()
      .map(|&(obj_index, func_index)| {
        let object = &self.objects[obj_index];
        let func = &object.functions[func_index];
        ((obj_index, func_index), func.global_linked_offset)
      })
      .collect::<FnvIndexMap<_, _>>();

    for &(obj_index, func_index) in self.all_functions.values() {
      let object = &self.objects[obj_index];
      let func = &object.functions[func_index];

      for (i, insn) in func.code.iter().enumerate() {
        let this_offset = (func.global_linked_offset + i * 8) as i64;
        if let Some(call_target_function) = insn.call_target_function {
          let call_target_function_body =
            &self.objects[call_target_function.0].functions[call_target_function.1];
          let target_offset = func_to_offset[&call_target_function] as i64;
          let diff = (target_offset - this_offset) / 8 - 1;
          let diff = if let Ok(x) = i16::try_from(diff) {
            x
          } else {
            anyhow::bail!(
              "call target offset {} is too far away from this offset {}",
              target_offset,
              this_offset
            );
          };
          let ja_insn = Insn {
            opc: JA,
            dst: 0,
            src: 2,
            off: diff,
            imm: -((call_target_function_body.stack_usage + 8) as i32),
          };
          self.image[this_offset as usize..(this_offset + 8) as usize]
            .copy_from_slice(&ja_insn.to_array());
          log::debug!(
            "rewritten call from {}:{} to {}:{} at insn index {}",
            object.name,
            func.name,
            object.name,
            call_target_function_body.name,
            i
          );
        }

        if insn.insn.opc == EXIT {
          let ja_insn = Insn {
            opc: JA,
            dst: 0,
            src: 1,
            off: 0,
            imm: (func.stack_usage + 8) as i32,
          };
          self.image[this_offset as usize..(this_offset + 8) as usize]
            .copy_from_slice(&ja_insn.to_array());
          log::debug!(
            "rewritten exit in {}:{} at insn index {}",
            object.name,
            func.name,
            i
          );
        }
      }
    }
    Ok(())
  }
}
