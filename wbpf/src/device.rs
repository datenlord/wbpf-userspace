use std::{
  fs::{File, OpenOptions},
  io::Read,
  os::unix::prelude::AsRawFd,
  path::Path,
  sync::Arc,
};

use anyhow::Result;
use nix::fcntl;
use tokio::{io::unix::AsyncFd, sync::Mutex};

use crate::{
  dm::DataMemory,
  linker::image::Image,
  perf::PerfCounters,
  uapi::{
    ioc_get_num_pe, ioc_load_code, ioc_start, ioc_stop, wbpf_uapi_load_code_args, wbpf_uapi_num_pe,
    wbpf_uapi_pe_exception_state, wbpf_uapi_performance_counters,
    wbpf_uapi_read_performance_counters_args, wbpf_uapi_start_args, wbpf_uapi_stop_args,
  },
};

#[derive(Clone)]
pub struct Device {
  pub(crate) file: Arc<Mutex<AsyncFd<File>>>,
  pub(crate) file_fd: i32,
  num_pe: u32,
}

#[derive(Clone, Debug)]
pub struct ExceptionState {
  pub pc: u32,
  pub code: u32,
  pub data: u64,
}

impl Device {
  pub async fn open(path: &Path) -> Result<Self> {
    let file = OpenOptions::new().read(true).write(true).open(path)?;
    let file_fd = file.as_raw_fd();
    fcntl::fcntl(
      file_fd,
      fcntl::F_SETFL(fcntl::OFlag::O_CLOEXEC | fcntl::OFlag::O_NONBLOCK),
    )?;
    let mut dev = Device {
      file: Arc::new(Mutex::new(AsyncFd::new(file)?)),
      file_fd,
      num_pe: 0,
    };
    dev.update_num_pe()?;

    let es = dev.read_exception_state().await?;
    log::info!("initial exception state: {:?}", es);
    Ok(dev)
  }

  pub async fn read_exception_state(&mut self) -> Result<Vec<ExceptionState>> {
    let mut buf = vec![wbpf_uapi_pe_exception_state::default(); self.num_pe as usize];
    let buf_size = std::mem::size_of::<wbpf_uapi_pe_exception_state>() * self.num_pe as usize;
    let file = self.file.lock().await;
    loop {
      let mut guard = file.readable().await?;

      match guard.try_io(|inner| {
        inner
          .get_ref()
          .read(unsafe { std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, buf_size) })
      }) {
        Ok(result) => {
          result?;
          break;
        }
        Err(_would_block) => continue,
      }
    }

    Ok(
      buf
        .iter()
        .map(|x| ExceptionState {
          pc: x.pc,
          code: x.code,
          data: x.data,
        })
        .collect(),
    )
  }

  fn update_num_pe(&mut self) -> Result<()> {
    let mut rsp: wbpf_uapi_num_pe = Default::default();
    unsafe {
      ioc_get_num_pe(self.file_fd, &mut rsp)?;
    }
    self.num_pe = rsp.num_pe;
    Ok(())
  }

  pub fn num_pe(&self) -> u32 {
    self.num_pe
  }

  pub async fn data_memory(&self) -> Result<DataMemory> {
    DataMemory::new(self.clone()).await
  }

  pub fn load_code(&self, pe_index: u32, offset: u32, code: &[u8]) -> Result<()> {
    let args = wbpf_uapi_load_code_args {
      pe_index,
      offset,
      code: code.as_ptr(),
      code_len: code.len() as u32,
    };
    unsafe {
      ioc_load_code(self.file_fd, &args)?;
    }
    Ok(())
  }

  pub fn stop(&self, pe_index: u32) -> Result<()> {
    let args = wbpf_uapi_stop_args { pe_index };
    unsafe {
      ioc_stop(self.file_fd, &args)?;
    }
    Ok(())
  }

  pub fn start(&self, pe_index: u32, pc: u32) -> Result<()> {
    let args = wbpf_uapi_start_args { pe_index, pc };
    unsafe {
      ioc_start(self.file_fd, &args)?;
    }
    Ok(())
  }

  pub fn read_perf_counters(&self, pe_index: u32) -> Result<PerfCounters> {
    let mut rsp: wbpf_uapi_performance_counters = Default::default();
    let req: wbpf_uapi_read_performance_counters_args = wbpf_uapi_read_performance_counters_args {
      pe_index,
      out: &mut rsp,
      size: std::mem::size_of::<wbpf_uapi_performance_counters>(),
    };
    unsafe {
      crate::uapi::ioc_get_performance_counters(self.file_fd, &req)?;
    }
    Ok(PerfCounters {
      cycles: rsp.cycles,
      commits: rsp.commits,
    })
  }

  pub fn load_image(&self, pe_index: u32, image: &Image) -> Result<()> {
    self.load_code(pe_index, 0, &image.code)?;
    Ok(())
  }
}
