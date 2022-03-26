mod consts;
mod device;

use std::{
  fs::{File, OpenOptions},
  io::{stdin, stdout, Read, Write},
  path::PathBuf,
};

use anyhow::Result;
use device::Device;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "wbpfctl", about = "wBPF control")]
struct Opt {
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
    offset: u32,

    /// Size in bytes.
    size: u32,
  },
  /// Write data memory.
  DmWrite {
    /// Path to input file.
    #[structopt(long, short = "i")]
    input: PathBuf,

    /// Memory offset in bytes.
    offset: u32,
  },
}

fn main() -> Result<()> {
  pretty_env_logger::init_timed();
  let opt = Opt::from_args();

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
      let device = unsafe { Device::open()? };
      let dm = device.read_dm(offset as _, size as _)?;
      f.write_all(&dm)?;
      log::info!("Read {} bytes from data memory.", dm.len());
    }

    Command::DmWrite { input, offset } => {
      let mut f: Box<dyn Read> = if input.to_string_lossy() == "-" {
        Box::new(stdin())
      } else {
        Box::new(File::open(&input)?)
      };
      let mut buf: Vec<u8> = Vec::new();
      f.read_to_end(&mut buf)?;
      let device = unsafe { Device::open()? };
      device.write_dm(offset as _, &buf)?;
      log::info!("Wrote {} bytes to data memory.", buf.len());
    }
  }

  Ok(())
}
