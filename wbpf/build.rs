use std::io::Result;
fn main() -> Result<()> {
  let mut config = prost_build::Config::new();
  config.type_attribute(".", "#[derive(serde::Serialize, serde::Deserialize)]");
  config.type_attribute(".", "#[serde(rename_all = \"camelCase\")]");
  config.compile_protos(&["src/linker/image.proto"], &["src/"])?;
  Ok(())
}
