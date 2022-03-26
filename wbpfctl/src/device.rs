use std::fs::{File, OpenOptions};

use anyhow::Result;
use memmap2::{MmapOptions, MmapRaw};

use crate::consts::{ADDR_DM, ADDR_MMIO, DM_SIZE, MMIO_SIZE};

pub struct Device {
  _mem: File,
  mmio: MmapRaw,
  dm: MmapRaw,
}

impl Device {
  pub unsafe fn open() -> Result<Device> {
    let mem = OpenOptions::new().read(true).write(true).open("/dev/mem")?;
    let mmio = MmapOptions::new()
      .offset(ADDR_MMIO as _)
      .len(MMIO_SIZE)
      .map_raw(&mem)?;
    let dm = MmapOptions::new()
      .offset(ADDR_DM as _)
      .len(DM_SIZE)
      .map_raw(&mem)?;
    Ok(Device {
      _mem: mem,
      mmio,
      dm,
    })
  }

  fn unaligned_op(
    mut offset: usize,
    mut len: usize,
    mut op: impl FnMut(usize, bool) -> Result<()>,
  ) -> Result<()> {
    let end = offset.checked_add(len);
    if end.is_none() || end.unwrap() > DM_SIZE {
      anyhow::bail!("offset + len > DM_SIZE");
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

  pub fn read_dm(&self, base_offset: usize, len: usize) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::with_capacity(len);
    Self::unaligned_op(base_offset, len, |off, word| {
      if word {
        let word = unsafe {
          std::ptr::read_volatile((self.dm.as_ptr() as *const u32).offset((off / 4) as _))
        };
        buf.extend_from_slice(&word.to_le_bytes());
      } else {
        let byte = unsafe { std::ptr::read_volatile(self.dm.as_ptr().offset(off as _)) };
        buf.push(byte);
      }
      Ok(())
    })?;
    assert_eq!(buf.len(), len);
    Ok(buf)
  }

  pub fn write_dm(&self, base_offset: usize, data: &[u8]) -> Result<()> {
    Self::unaligned_op(base_offset, data.len(), |off, word| {
      if word {
        let word = u32::from_le_bytes([
          data[off - base_offset],
          data[off - base_offset + 1],
          data[off - base_offset + 2],
          data[off - base_offset + 3],
        ]);
        unsafe {
          std::ptr::write_volatile((self.dm.as_ptr() as *mut u32).offset((off / 4) as _), word);
        }
      } else {
        unsafe {
          std::ptr::write_volatile(
            self.dm.as_mut_ptr().offset(off as _),
            data[off - base_offset],
          );
        }
      }
      Ok(())
    })?;
    Ok(())
  }
}
