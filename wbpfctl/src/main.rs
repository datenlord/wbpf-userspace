use std::{
  fs::{File, OpenOptions},
  io::{stdin, stdout, Read, Write},
  path::{Path, PathBuf},
};

use anyhow::Result;
use structopt::StructOpt;
use wbpf::{
  device::Device,
  linker::{
    global_linker::{GlobalLinkerConfig},
    image::{HostPlatform, TargetMachine}, fs::link_files,
  },
};

#[derive(Debug, StructOpt)]
#[structopt(name = "wbpfctl", about = "wBPF control")]
struct Opt {
  /// Path to device.
  #[structopt(long, short = "d")]
  device: Option<PathBuf>,

  #[structopt(subcommand)]
  cmd: Command,
}

#[derive(Debug, StructOpt)]
enum Command {
  /// Read data memory.
  DmRead {
    /// Path to output file.
    #[structopt(long, short = "o")]
    output: PathBuf,

    /// Memory offset in bytes.
    #[structopt(long, default_value = "0")]
    offset: u32,

    /// Size in bytes.
    #[structopt(long)]
    size: u32,

    /// Use DMA.
    #[structopt(long)]
    dma: bool,
  },
  /// Write data memory.
  DmWrite {
    /// Path to input file.
    #[structopt(long, short = "i")]
    input: PathBuf,

    /// Memory offset in bytes.
    #[structopt(long, default_value = "0")]
    offset: u32,

    /// Use DMA.
    #[structopt(long)]
    dma: bool,
  },

  /// Load code.
  LoadCode {
    /// Path to input file.
    #[structopt(long, short = "i")]
    input: PathBuf,

    /// Processing element index.
    #[structopt(long, default_value = "0")]
    pe_index: u32,

    /// Offset in bytes.
    #[structopt(long, default_value = "0")]
    offset: u32,
  },

  /// Stop.
  Stop {
    /// Processing element index.
    #[structopt(long, default_value = "0")]
    pe_index: u32,
  },

  /// Start.
  Start {
    /// Processing element index.
    #[structopt(long, default_value = "0")]
    pe_index: u32,

    /// PC.
    #[structopt(long, default_value = "0")]
    pc: u32,
  },

  /// Link.
  Link {
    /// Input list.
    input: Vec<PathBuf>,

    /// Target machine YAML/JSON config.
    #[structopt(long)]
    target_machine: Option<PathBuf>,

    /// Host platform YAML/JSON config.
    #[structopt(long)]
    host_platform: Option<PathBuf>,
  },
}

fn main() -> Result<()> {
  pretty_env_logger::init_timed();
  let opt = Opt::from_args();

  let open_device = || {
    if let Some(device) = &opt.device {
      Device::open(&device).map_err(anyhow::Error::from)
    } else {
      Err(anyhow::anyhow!("no device specified"))
    }
  };

  match opt.cmd {
    Command::DmRead {
      output,
      offset,
      size,
      dma,
    } => {
      let device = open_device()?;
      let mut f: Box<dyn Write> = if output.to_string_lossy() == "-" {
        Box::new(stdout())
      } else {
        Box::new(OpenOptions::new().write(true).create(true).open(&output)?)
      };
      let device_dm = device.data_memory()?;
      let mut buffer = vec![0u8; size as usize];

      if dma {
        device_dm.do_dma_read(offset, &mut buffer)?;
      } else {
        device_dm.do_read(offset, &mut buffer)?;
      }

      f.write_all(&buffer)?;
      log::info!("Read {} bytes from data memory.", buffer.len());
    }

    Command::DmWrite { input, offset, dma } => {
      let device = open_device()?;
      let buf = read_input(&input)?;
      let device_dm = device.data_memory()?;

      if dma {
        device_dm.do_dma_write(offset, &buf)?;
      } else {
        device_dm.do_write(offset, &buf)?;
      }

      log::info!("Wrote {} bytes to data memory.", buf.len());
    }

    Command::LoadCode {
      input,
      pe_index,
      offset,
    } => {
      let device = open_device()?;
      let code = read_input(&input)?;
      device.load_code(pe_index, offset, &code)?;
      log::info!("Code loaded. See dmesg.");
    }
    Command::Stop { pe_index } => {
      let device = open_device()?;
      device.stop(pe_index)?;
      log::info!("Stopped.");
    }
    Command::Start { pe_index, pc } => {
      let device = open_device()?;
      device.start(pe_index, pc)?;
      log::info!("Started.");
    }
    Command::Link {
      input,
      target_machine,
      host_platform,
    } => {
      let target_machine: TargetMachine = if let Some(p) = &target_machine {
        serde_yaml::from_str(&std::fs::read_to_string(p)?)?
      } else {
        Default::default()
      };
      let host_platform: HostPlatform = if let Some(p) = &host_platform {
        serde_yaml::from_str(&std::fs::read_to_string(p)?)?
      } else {
        Default::default()
      };
      let config = GlobalLinkerConfig {
        target_machine,
        host_platform,
      };
      link_files(config, &input)?;
    }
  }

  Ok(())
}

fn read_input(input: &Path) -> Result<Vec<u8>> {
  let mut f: Box<dyn Read> = if input.to_string_lossy() == "-" {
    Box::new(stdin())
  } else {
    Box::new(File::open(input)?)
  };
  let mut buf: Vec<u8> = Vec::new();
  f.read_to_end(&mut buf)?;
  Ok(buf)
}
