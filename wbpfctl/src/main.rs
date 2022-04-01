use std::{
  fs::{File, OpenOptions},
  io::{stdin, stdout, Read, Write},
  path::{Path, PathBuf},
};

use serde::Deserialize;

use anyhow::Result;
use prost::Message;
use structopt::StructOpt;
use tokio::runtime::Handle;
use wbpf::{
  device::Device,
  linker::{
    fs::link_files,
    global_linker::GlobalLinkerConfig,
    image::{HostPlatform, Image, TargetMachine},
    image_disassembler::DisassembledImage,
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

  /// Read perf counters.
  PerfCounters {
    /// Processing element index.
    #[structopt(long, default_value = "0")]
    pe_index: u32,
  },

  /// Link.
  Link {
    /// Input list.
    input: Vec<PathBuf>,

    /// Output path.
    #[structopt(long, short = "o")]
    output: Option<PathBuf>,

    /// Target machine YAML/JSON config.
    #[structopt(long)]
    target_machine: Option<PathBuf>,

    /// Host platform YAML/JSON config.
    #[structopt(long)]
    host_platform: Option<PathBuf>,

    /// Comma-delimited dead code elimination root functions.
    #[structopt(long)]
    dce_roots: Option<String>,
  },

  /// Load image.
  LoadImage {
    /// Input file.
    #[structopt(long, short = "i")]
    input: PathBuf,

    /// Processing element index.
    #[structopt(long, default_value = "0")]
    pe_index: u32,

    /// Path to machine state spec.
    #[structopt(long)]
    state: PathBuf,
  },

  /// Disassemble image.
  DisassembleImage {
    /// Input file.
    #[structopt(long, short = "i")]
    input: PathBuf,

    /// Binary output?
    #[structopt(long)]
    binary: bool,
  },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MachineState {
  registers: Vec<i64>,
  entry_point: String,
}

#[tokio::main]
async fn main() -> Result<()> {
  pretty_env_logger::init_timed();
  let opt = Opt::from_args();

  let open_device = || {
    if let Some(device) = &opt.device {
      tokio::task::block_in_place(move || {
        Handle::current()
          .block_on(async move { Device::open(&device).await.map_err(anyhow::Error::from) })
      })
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
      let mut f = open_output(&output)?;
      let device_dm = device.data_memory().await?;
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
      let device_dm = device.data_memory().await?;

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
    Command::PerfCounters { pe_index } => {
      let device = open_device()?;
      let perfctr = device.read_perf_counters(pe_index)?;
      println!("{:?}", perfctr);
    }
    Command::Link {
      input,
      output,
      target_machine,
      host_platform,
      dce_roots,
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
        dce_roots: dce_roots.map(|x| x.split(',').map(|x| x.to_string()).collect()),
      };
      let image = link_files(config, &input)?;
      if let Some(p) = &output {
        let mut output = open_output(p)?;
        output.write_all(&image.encode_to_vec())?;
      }
    }
    Command::LoadImage {
      input,
      pe_index,
      state,
    } => {
      let mut device = open_device()?;
      let state: MachineState = serde_yaml::from_str(&std::fs::read_to_string(&state)?)?;
      if state.registers.len() != 11 {
        return Err(anyhow::anyhow!("invalid state"));
      }
      let image = read_input(&input)?;
      device.stop(pe_index)?;
      loop {
        let es = device.read_exception_state().await?;
        let es = &es[pe_index as usize];

        // STOP | INTR
        if es.code == 0x80000007u32 {
          break;
        }
      }
      let image = Image::decode(image.as_slice())?;
      device.load_image(pe_index, &image)?;

      let offset_table = image
        .offset_table
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no offset table"))?;

      let offset = *offset_table
        .func_offsets
        .get(&state.entry_point)
        .ok_or_else(|| anyhow::anyhow!("no entry point"))?;
      let mut state_snapshot = [0u64; 11];
      for i in 0..11 {
        state_snapshot[i] = state.registers[i] as u64;
      }
      state_snapshot[10] = (state_snapshot[10] << 32) | (offset as u64);
      let size = std::mem::size_of_val(&state_snapshot);
      let dm = device.data_memory().await?;
      dm.do_dma_write(0, unsafe {
        std::slice::from_raw_parts(state_snapshot.as_ptr() as *const u8, size)
      })?;
      let start_perfctr = device.read_perf_counters(pe_index)?;
      device.start(pe_index, 0)?;
      let es = loop {
        let es = device.read_exception_state().await?;
        let es = es.into_iter().nth(pe_index as usize).unwrap();
        if es.code & 0x80000000u32 != 0 {
          break es;
        }
      };
      let end_perfctr = device.read_perf_counters(pe_index)?;
      println!("new es: {:?}", es);
      println!("cycles={} commits={}", end_perfctr.cycles - start_perfctr.cycles, end_perfctr.commits - start_perfctr.commits);
    }
    Command::DisassembleImage { input, binary } => {
      let image = read_input(&input)?;
      let image = Image::decode(image.as_slice())?;
      if binary {
        for (i, byte) in image.code.iter().enumerate() {
          if i + 1 == image.code.len() {
            println!("0x{:02x}", byte);
          } else {
            print!("0x{:02x}, ", byte);
          }
        }
      } else {
        println!("{}", DisassembledImage::new(&image));
      }
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

fn open_output(output: &Path) -> Result<Box<dyn Write>> {
  let f: Box<dyn Write> = if output.to_string_lossy() == "-" {
    Box::new(stdout())
  } else {
    Box::new(
      OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&output)?,
    )
  };
  Ok(f)
}
