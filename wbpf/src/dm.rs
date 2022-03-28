use anyhow::Result;
use memmap2::{MmapOptions, MmapRaw};

use crate::device::Device;

pub struct DataMemory {
  _device: Device,
  mem: MmapRaw,
}

impl DataMemory {
  pub(crate) fn new(device: Device) -> Result<Self> {
    let mem = MmapOptions::new().len(65536).map_raw(&*device.file)?;
    Ok(DataMemory {
      _device: device,
      mem,
    })
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

  pub fn do_read(&self, base_offset: usize, len: usize) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(len);
    self.unaligned_op(base_offset, len, |off, word| {
      if word {
        let word = unsafe {
          std::ptr::read_volatile((self.mem.as_ptr() as *const u32).offset((off / 4) as _))
        };
        buf.extend_from_slice(&word.to_le_bytes());
      } else {
        let byte = unsafe { std::ptr::read_volatile(self.mem.as_ptr().offset(off as _)) };
        buf.push(byte);
      }
      Ok(())
    })?;
    assert_eq!(buf.len(), len);
    Ok(buf)
  }

  pub fn do_write(&self, base_offset: usize, data: &[u8]) -> Result<()> {
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
