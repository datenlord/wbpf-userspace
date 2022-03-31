use nix::{ioctl_read, ioctl_write_ptr};

const WBPF_IOC_MAGIC: u8 = b'w';

#[repr(C)]
pub struct wbpf_uapi_load_code_args {
  pub pe_index: u32,
  pub offset: u32,
  pub code: *const u8,
  pub code_len: u32,
}

#[repr(C)]
pub struct wbpf_uapi_stop_args {
  pub pe_index: u32,
}

#[repr(C)]
pub struct wbpf_uapi_start_args {
  pub pe_index: u32,
  pub pc: u32,
}

#[repr(C)]
pub struct wbpf_uapi_write_dm_args {
  pub offset: u32,
  pub data: *const u8,
  pub data_len: u32,
}

#[repr(C)]
pub struct wbpf_uapi_read_dm_args {
  pub offset: u32,
  pub data: *mut u8,
  pub data_len: u32,
}

#[repr(C)]
pub struct wbpf_uapi_hw_revision {
  pub major: u32,
  pub minor: u32,
}

#[derive(Default)]
#[repr(C)]
pub struct wbpf_uapi_num_pe {
  pub num_pe: u32,
}

#[repr(C)]
pub struct wbpf_uapi_read_performance_counters_args {
  pub pe_index: u32,
  pub out: *mut wbpf_uapi_performance_counters,
  pub size: usize,
}

#[derive(Default)]
#[repr(C)]
pub struct wbpf_uapi_performance_counters {
  pub cycles: u64,
  pub commits: u64,
}

#[derive(Default, Clone)]
#[repr(C)]
pub struct wbpf_uapi_pe_exception_state {
  pub pc: u32,
  pub code: u32,
  pub data: u64,
}

ioctl_write_ptr!(ioc_load_code, WBPF_IOC_MAGIC, 1, wbpf_uapi_load_code_args);
ioctl_write_ptr!(ioc_stop, WBPF_IOC_MAGIC, 2, wbpf_uapi_stop_args);
ioctl_write_ptr!(ioc_start, WBPF_IOC_MAGIC, 3, wbpf_uapi_start_args);
ioctl_write_ptr!(ioc_write_dm, WBPF_IOC_MAGIC, 4, wbpf_uapi_write_dm_args);
ioctl_write_ptr!(ioc_read_dm, WBPF_IOC_MAGIC, 5, wbpf_uapi_read_dm_args);
ioctl_read!(
  ioc_get_hw_revision,
  WBPF_IOC_MAGIC,
  6,
  wbpf_uapi_hw_revision
);
ioctl_read!(ioc_get_num_pe, WBPF_IOC_MAGIC, 7, wbpf_uapi_num_pe);
ioctl_write_ptr!(
  ioc_get_performance_counters,
  WBPF_IOC_MAGIC,
  8,
  wbpf_uapi_read_performance_counters_args
);
