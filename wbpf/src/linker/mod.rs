pub mod consts;
pub mod ebpf;
pub mod elf_ext;
pub mod global_linker;
pub mod local_linker;
pub mod ebpf_disassembler;
pub mod fs;

pub mod image {
  include!(concat!(env!("OUT_DIR"), "/wbpf.linker.image.rs"));
}
