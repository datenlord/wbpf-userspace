use std::path::Path;

use anyhow::Result;
use bumpalo::Bump;

use crate::linker::global_linker::{GlobalLinker, GlobalLinkerConfig};

use super::image::Image;

pub fn link_files<S: AsRef<Path>>(config: GlobalLinkerConfig, input: &[S]) -> Result<Image> {
  let input = input
    .iter()
    .map(|x| {
      std::fs::canonicalize(x).map_err(|e| {
        anyhow::Error::from(e).context(format!(
          "error resolving path '{}'",
          x.as_ref().to_string_lossy()
        ))
      })
    })
    .collect::<Result<Vec<_>>>()?;
  let mut files: Vec<Vec<u8>> = Vec::new();
  for p in &input {
    files.push(std::fs::read(p)?);
  }
  let bump = Bump::new();
  let mut linker = GlobalLinker::new(&bump, config)?;
  for (name, object) in input.iter().zip(files.iter()) {
    linker.add_object(&name.to_string_lossy(), object)?;
  }
  Ok(linker.emit()?)
}
