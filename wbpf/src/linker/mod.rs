pub mod consts;
pub mod ebpf;
pub mod ebpf_disassembler;
pub mod elf_ext;
pub mod fs;
pub mod global_linker;
pub mod image_disassembler;
pub mod local_linker;

pub mod image {
  include!(concat!(env!("OUT_DIR"), "/wbpf.linker.image.rs"));
}
