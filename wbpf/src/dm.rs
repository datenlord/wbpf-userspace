use std::os::unix::prelude::AsRawFd;

use anyhow::Result;
use memmap2::{MmapOptions, MmapRaw};

use crate::{
  device::Device,
  uapi::{wbpf_uapi_read_dm_args, wbpf_uapi_write_dm_args},
};

pub struct DataMemory {
  device: Device,
  mem: MmapRaw,
}

impl DataMemory {
  pub(crate) fn new(device: Device) -> Result<Self> {
    let mem = MmapOptions::new().len(65536).map_raw(&*device.file)?;
    Ok(DataMemory { device, mem })
  }

  fn unaligned_op(
    &self,
    mut offset: usize,
    mut len: usize,
    mut op: impl FnMut(usize, bool) -> Result<()>,
  ) -> Result<()> {
    let end = offset.checked_add(len);
    if end.is_none() {
      anyhow::bail!("bad length");
    }
    while offset % 4 != 0 && len > 0 {
      op(offset, false)?;
      offset += 1;
      len -= 1;
    }
    while len >= 4 {
      op(offset, true)?;
      offset += 4;
      len -= 4;
    }
    while len > 0 {
      op(offset, false)?;
      offset += 1;
      len -= 1;
    }

    Ok(())
  }

  pub fn do_dma_read(&self, offset: u32, output: &mut [u8]) -> Result<()> {
    let output_len = output.len();
    let output_ptr = output.as_mut_ptr();
    let args = wbpf_uapi_read_dm_args {
      offset,
      data: output_ptr,
      data_len: output_len as u32,
    };
    unsafe {
      crate::uapi::ioc_read_dm(self.device.file.as_raw_fd(), &args)?;
    }
    Ok(())
  }

  pub fn do_dma_write(&self, offset: u32, data: &[u8]) -> Result<()> {
    let data_len = data.len();
    let data_ptr = data.as_ptr();
    let args = wbpf_uapi_write_dm_args {
      offset,
      data: data_ptr,
      data_len: data_len as u32,
    };
    unsafe {
      crate::uapi::ioc_write_dm(self.device.file.as_raw_fd(), &args)?;
    }
    Ok(())
  }

  pub fn do_read(&self, base_offset: u32, output: &mut [u8]) -> Result<()> {
    let mut index: usize = 0;
    let len = output.len();
    let base_offset = base_offset as usize;
    self.unaligned_op(base_offset, len, |off, word| {
      if word {
        let word = unsafe {
          std::ptr::read_volatile((self.mem.as_ptr() as *const u32).offset((off / 4) as _))
        };
        output[index..index + 4].copy_from_slice(&word.to_le_bytes());
        index += 4;
      } else {
        let byte = unsafe { std::ptr::read_volatile(self.mem.as_ptr().offset(off as _)) };
        output[index] = byte;
        index += 1;
      }
      Ok(())
    })?;
    assert_eq!(index, len);
    Ok(())
  }

  pub fn do_write(&self, base_offset: u32, data: &[u8]) -> Result<()> {
    let base_offset = base_offset as usize;
    self.unaligned_op(base_offset, data.len(), |off, word| {
      if word {
        let word = u32::from_le_bytes([
          data[off - base_offset],
          data[off - base_offset + 1],
          data[off - base_offset + 2],
          data[off - base_offset + 3],
        ]);
        unsafe {
          std::ptr::write_volatile((self.mem.as_ptr() as *mut u32).offset((off / 4) as _), word);
        }
      } else {
        unsafe {
          std::ptr::write_volatile(
            self.mem.as_mut_ptr().offset(off as _),
            data[off - base_offset],
          );
        }
      }
      Ok(())
    })?;
    Ok(())
  }
}
