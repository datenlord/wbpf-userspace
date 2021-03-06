use anyhow::Result;
use bumpalo::Bump;
use fnv::{FnvHashMap, FnvHashSet};
use goblin::elf64::{
  section_header::{SHF_ALLOC, SHF_EXECINSTR, SHT_PROGBITS},
  sym::STB_LOCAL,
};
use petgraph::{
  graph::{DiGraph, NodeIndex},
  visit::{Dfs, Visitable},
};
use serde::{Deserialize, Serialize};

use crate::{
  linker::{
    ebpf::CALL,
    elf_ext::{StrtabExt, SymtabExt},
  },
  types::FnvIndexMap,
};

use super::{
  consts::{R_BPF_64_32, R_BPF_64_64},
  ebpf::{Insn, ADD64_IMM, EXIT, JA, LD_DW_REG, MOV32_IMM},
  image::{HostPlatform, OffsetTable, TargetMachine},
};
use super::{
  image::Image,
  local_linker::{LocalLinker, LocalObject},
};

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GlobalLinkerConfig {
  pub target_machine: TargetMachine,
  pub host_platform: HostPlatform,
  pub dce_roots: Option<Vec<String>>,
}

pub struct GlobalLinker<'a> {
  bump: &'a Bump,
  config: GlobalLinkerConfig,
  objects: Vec<LocalObject<'a>>,
  all_functions: FnvIndexMap<String, (usize, usize)>, // name -> (obj_index, func_index)
  offset_table: OffsetTable,
  code_image: Vec<u8>,
  data_image: Vec<u8>,
  data_section_to_offset: FnvHashMap<(u32, u32), u32>, // (obj_index, section_index) -> offset
}

impl<'a> GlobalLinker<'a> {
  pub fn new(bump: &'a Bump, config: GlobalLinkerConfig) -> Result<Self> {
    Ok(Self {
      bump,
      config,
      objects: vec![],
      all_functions: Default::default(),
      offset_table: Default::default(),
      code_image: vec![],
      data_image: vec![],
      data_section_to_offset: Default::default(),
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
    self.emit_data()?;
    self.populate_all_functions()?;
    self.resolve_pseudo_calls()?;
    self.resolve_generic_relocs()?;

    if let Some(dce_roots) = self.config.dce_roots.clone() {
      self.global_dce(&dce_roots)?;
    }

    self.emit_entry_trampoline()?;
    self.emit_code_image()?;
    self.rewrite_image_call_return()?;
    self.emit_offset_table()?;
    let mut image = Image::default();
    image.code = std::mem::replace(&mut self.code_image, vec![]);
    image.data = std::mem::replace(&mut self.data_image, vec![]);
    image.machine = Some(self.config.target_machine.clone());
    image.platform = Some(self.config.host_platform.clone());
    image.offset_table = Some(std::mem::replace(
      &mut self.offset_table,
      Default::default(),
    ));
    Ok(image)
  }

  fn emit_offset_table(&mut self) -> Result<()> {
    let func_offsets = self
      .all_functions
      .values()
      .map(|&(obj_index, func_index)| {
        let object = &self.objects[obj_index];
        let func = &object.functions[func_index];
        (func.name, func.global_linked_offset)
      })
      .collect::<FnvIndexMap<_, _>>();
    for (k, v) in func_offsets {
      self
        .offset_table
        .func_offsets
        .insert(k.to_string(), v as i32);
    }
    Ok(())
  }

  fn populate_all_functions(&mut self) -> Result<()> {
    for (obj_idx, obj) in self.objects.iter().enumerate() {
      for (func_idx, (func_name, func)) in obj.functions.iter().enumerate() {
        let func_name = if func.global {
          func_name.to_string()
        } else {
          format!("{}:{}", obj.name, func_name)
        };
        if let Some((obj_index, _)) = self.all_functions.get(&func_name) {
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

  fn emit_data(&mut self) -> Result<()> {
    for (obj_idx, object) in self.objects.iter().enumerate() {
      let elf = &*object.elf;
      for (section_index, shdr) in elf.section_headers.iter().enumerate() {
        if shdr.sh_type == SHT_PROGBITS
          && (shdr.sh_flags & SHF_ALLOC as u64) != 0
          && (shdr.sh_flags & SHF_EXECINSTR as u64) == 0
        {
          let data_offset = self.data_image.len();
          let file_range = shdr
            .file_range()
            .ok_or_else(|| anyhow::anyhow!("missing file range"))?;
          let data = object
            .raw
            .get(file_range)
            .ok_or_else(|| anyhow::anyhow!("file range out of bounds"))?;
          self.data_image.extend_from_slice(data);
          self.data_section_to_offset.insert(
            (obj_idx as u32, section_index as u32),
            data_offset as u32 + self.config.host_platform.data_offset as u32,
          );
        }
      }
    }
    Ok(())
  }

  fn resolve_generic_relocs(&mut self) -> Result<()> {
    for (object_index, object) in self.objects.iter_mut().enumerate() {
      let object_reloc = &mut object.reloc;
      let elf = &*object.elf;
      for (&(func_index, offset_in_func), reloc) in &*object_reloc {
        let sym = elf.syms.get_result(reloc.r_sym)?;
        let sym_name = elf.shdr_strtab.get_at_result(sym.st_name)?;
        if sym.st_bind() != STB_LOCAL {
          anyhow::bail!(
            "non-local data relocation is not supported: object {}, symbol {}",
            object.name,
            sym_name
          );
        }
        let data_base_offset = *self
          .data_section_to_offset
          .get(&(object_index as u32, sym.st_shndx as u32))
          .ok_or_else(|| anyhow::anyhow!("data offset not found"))?;
        let this_offset = data_base_offset + sym.st_value as u32;
        let func = &mut object.functions[func_index];

        if reloc.r_type == R_BPF_64_64 {
          let this_insn_index = offset_in_func / 8;
          let next_insn_index = this_insn_index + 1;
          let value = (func.code[this_insn_index].insn.imm as u64)
            | ((func.code[next_insn_index].insn.imm as u64) << 32);
          let value = value + this_offset as u64;
          func.code[this_insn_index].insn.imm = value as i32;
          func.code[next_insn_index].insn.imm = (value >> 32) as i32;
        } else if reloc.r_type == R_BPF_64_32 {
          let this_insn_index = offset_in_func / 8;
          let value = func.code[this_insn_index].insn.imm;
          func.code[this_insn_index].insn.imm = value + this_offset as i32;
        } else {
          anyhow::bail!(
            "unsupported relocation type: {}, object {}, symbol {}",
            reloc.r_type,
            object.name,
            sym_name
          );
        }
        log::debug!(
          "resolved generic data relocation: object {}, func {}, offset {}, target base {}, symbol {}",
          object.name,
          func.name,
          offset_in_func,
          data_base_offset,
          sym_name
        );
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
        .insert(func.offset, (name.as_str(), *func_index));
    }

    let objects_snapshot = self.objects.clone();
    for (obj_index, func_index) in self.all_functions.values() {
      let object = &mut self.objects[*obj_index];
      let elf = &*object.elf;
      let object_reloc = &mut object.reloc;
      let func = &mut object.functions[*func_index];
      for insn in func.code.iter_mut() {
        if insn.insn.opc == CALL {
          // BPF_PSEUDO_CALL
          if insn.insn.src == 1 {
            if let Some(reloc) = object_reloc.remove(&(*func_index, insn.original_offset as usize))
            {
              let sym = elf.syms.get_result(reloc.r_sym)?;
              let sym_name = elf.shdr_strtab.get_at_result(sym.st_name)?;

              if let Some(&(obj_index, func_index)) =
                self.all_functions.get(sym_name).or_else(|| {
                  self
                    .all_functions
                    .get(&format!("{}:{}", object.name, sym_name))
                })
              {
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
              assert!(insn.original_offset >= 0);
              let target_offset = (func.offset as i32
                + insn.original_offset as i32
                + (insn.insn.imm + 1) * 8) as usize;
              let (name, target_function_index) = *function_map
                .get(&(*obj_index, func.section_index))
                .unwrap()
                .get(&target_offset)
                .ok_or_else(|| {
                  log::error!(
                    "missing function at target offset - in {}:{}, insn offset {}",
                    object.name,
                    func.name,
                    insn.original_offset
                  );
                  anyhow::anyhow!("missing function at target offset")
                })?;
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

  fn emit_entry_trampoline(&mut self) -> Result<()> {
    let insns: Vec<Insn> = vec![
      // Initialize constant
      Insn {
        opc: MOV32_IMM,
        src: 0,
        dst: 10,
        off: 0,
        imm: 0,
      },
      // Load registers 0-9
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 0,
        off: 0,
        imm: 0,
      },
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 1,
        off: 8,
        imm: 0,
      },
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 2,
        off: 16,
        imm: 0,
      },
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 3,
        off: 24,
        imm: 0,
      },
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 4,
        off: 32,
        imm: 0,
      },
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 5,
        off: 40,
        imm: 0,
      },
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 6,
        off: 48,
        imm: 0,
      },
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 7,
        off: 56,
        imm: 0,
      },
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 8,
        off: 64,
        imm: 0,
      },
      Insn {
        opc: LD_DW_REG,
        src: 10,
        dst: 9,
        off: 72,
        imm: 0,
      },
      Insn {
        opc: ADD64_IMM,
        src: 0,
        dst: 10,
        off: 0,
        imm: 80,
      },
      // RETURN
      Insn {
        opc: JA,
        src: 1,
        dst: 0,
        off: 0,
        imm: 0,
      },
    ];

    self
      .code_image
      .extend(insns.iter().map(|x| x.to_array().into_iter()).flatten());
    Ok(())
  }

  fn emit_code_image(&mut self) -> Result<()> {
    for &(obj_index, func_index) in self.all_functions.values() {
      let object = &mut self.objects[obj_index];
      let func = &mut object.functions[func_index];
      func.global_linked_offset = self.code_image.len();
      log::debug!(
        "emitting function {}:{} at {} len {}",
        object.name,
        func.name,
        func.global_linked_offset,
        func.code.len()
      );

      for insn in &func.code {
        self.code_image.extend_from_slice(&insn.insn.to_array());
      }
    }

    Ok(())
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
            imm: -((func.stack_usage + 8) as i32),
          };
          self.code_image[this_offset as usize..(this_offset + 8) as usize]
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
            imm: 0,
          };
          self.code_image[this_offset as usize..(this_offset + 8) as usize]
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

  fn global_dce<S: AsRef<str>>(&mut self, roots: &[S]) -> Result<()> {
    let roots = roots
      .iter()
      .map(|x| x.as_ref())
      .collect::<FnvHashSet<&str>>();
    let root_indices = self
      .all_functions
      .keys()
      .enumerate()
      .filter(|x| roots.contains(x.1.as_str()))
      .map(|x| NodeIndex::new(x.0))
      .collect::<Vec<_>>();
    let fn_to_index = self
      .all_functions
      .values()
      .enumerate()
      .map(|(k, v)| (*v, k))
      .collect::<FnvHashMap<_, _>>();

    let mut edges: Vec<(u32, u32)> = Vec::new();
    for (i, &(obj_index, func_index)) in self.all_functions.values().enumerate() {
      let object = &self.objects[obj_index];
      let func = &object.functions[func_index];
      for insn in func.code.iter() {
        if let Some(target) = insn.call_target_function {
          edges.push((i as u32, fn_to_index[&target] as u32));
        }
      }
    }
    let g = DiGraph::<(), ()>::from_edges(edges.iter().copied());
    let mut dfs = Dfs::from_parts(root_indices, g.visit_map());
    let mut unused_functions = (0..self.all_functions.len()).collect::<FnvHashSet<_>>();
    while let Some(n) = dfs.next(&g) {
      unused_functions.remove(&n.index());
    }
    let all_functions = std::mem::replace(&mut self.all_functions, Default::default())
      .into_iter()
      .enumerate()
      .filter(|x| {
        if unused_functions.contains(&x.0) {
          log::debug!("removing unused function {}", x.1 .0);
          false
        } else {
          true
        }
      })
      .map(|x| x.1)
      .collect::<FnvIndexMap<String, (usize, usize)>>();
    self.all_functions = all_functions;
    Ok(())
  }
}
