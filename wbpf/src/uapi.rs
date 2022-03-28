pub const WBPF_IOCTL_LOAD_CODE: i32 = 0x1;
pub const WBPF_IOCTL_STOP: i32 = 0x2;
pub const WBPF_IOCTL_START: i32 = 0x3;

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