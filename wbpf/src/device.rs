use std::{
  fs::{File, OpenOptions},
  os::unix::prelude::AsRawFd,
  path::Path,
  sync::Arc,
};

use anyhow::Result;
use nix::errno::Errno;

use crate::{
  dm::DataMemory,
  uapi::{
    wbpf_uapi_load_code_args, wbpf_uapi_start_args, wbpf_uapi_stop_args, WBPF_IOCTL_LOAD_CODE,
    WBPF_IOCTL_START, WBPF_IOCTL_STOP,
  },
};

#[derive(Clone)]
pub struct Device {
  pub(crate) file: Arc<File>,
}

impl Device {
  pub fn open(path: &Path) -> Result<Self> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let dev = Device {
      file: Arc::new(file),
    };
    Ok(dev)
  }

  pub fn data_memory(&self) -> Result<DataMemory> {
    DataMemory::new(self.clone())
  }

  pub fn load_code(&self, pe_index: u32, offset: u32, code: &[u8]) -> Result<()> {
    let args = wbpf_uapi_load_code_args {
      pe_index,
      offset,
      code: code.as_ptr(),
      code_len: code.len() as u32,
    };
    let ret = unsafe {
      libc::ioctl(
        self.file.as_raw_fd(),
        WBPF_IOCTL_LOAD_CODE,
        &args as *const _,
      )
    };
    Errno::result(ret)?;
    Ok(())
  }

  pub fn stop(&self, pe_index: u32) -> Result<()> {
    let args = wbpf_uapi_stop_args { pe_index };
    let ret = unsafe { libc::ioctl(self.file.as_raw_fd(), WBPF_IOCTL_STOP, &args as *const _) };
    Errno::result(ret)?;
    Ok(())
  }

  pub fn start(&self, pe_index: u32, pc: u32) -> Result<()> {
    let args = wbpf_uapi_start_args { pe_index, pc };
    let ret = unsafe { libc::ioctl(self.file.as_raw_fd(), WBPF_IOCTL_START, &args as *const _) };
    Errno::result(ret)?;
    Ok(())
  }
}
