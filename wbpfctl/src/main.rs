use std::{
  fs::{File, OpenOptions},
  io::{stdin, stdout, Read, Write},
  path::{Path, PathBuf},
};

use anyhow::Result;
use structopt::StructOpt;
use wbpf::device::Device;

#[derive(Debug, StructOpt)]
#[structopt(name = "wbpfctl", about = "wBPF control")]
struct Opt {
  /// Path to device.
  #[structopt(long, short = "d")]
  device: PathBuf,

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
  },
  /// Write data memory.
  DmWrite {
    /// Path to input file.
    #[structopt(long, short = "i")]
    input: PathBuf,

    /// Memory offset in bytes.
    #[structopt(long, default_value = "0")]
    offset: u32,
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
}

fn main() -> Result<()> {
  pretty_env_logger::init_timed();
  let opt = Opt::from_args();
  let device = Device::open(&opt.device)?;

  match opt.cmd {
    Command::DmRead {
      output,
      offset,
      size,
    } => {
      let mut f: Box<dyn Write> = if output.to_string_lossy() == "-" {
        Box::new(stdout())
      } else {
        Box::new(OpenOptions::new().write(true).create(true).open(&output)?)
      };
      let device_dm = device.data_memory()?;
      let dm = device_dm.do_read(offset as _, size as _)?;
      f.write_all(&dm)?;
      log::info!("Read {} bytes from data memory.", dm.len());
    }

    Command::DmWrite { input, offset } => {
      let buf = read_input(&input)?;
      let device_dm = device.data_memory()?;
      device_dm.do_write(offset as _, &buf)?;
      log::info!("Wrote {} bytes to data memory.", buf.len());
    }

    Command::LoadCode {
      input,
      pe_index,
      offset,
    } => {
      let code = read_input(&input)?;
      device.load_code(pe_index, offset, &code)?;
      log::info!("Code loaded. See dmesg.");
    }
    Command::Stop { pe_index } => {
      device.stop(pe_index)?;
      log::info!("Stopped.");
    }
    Command::Start { pe_index, pc } => {
      device.start(pe_index, pc)?;
      log::info!("Started.");
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
