//! Process settings from the environment (template style); policy lives in the TOML file.

use std::path::PathBuf;

use figment::{
  Figment,
  providers::{Env, Serialized},
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub struct Settings {
  pub log_level: String,
  pub config_path: PathBuf,
}

impl Default for Settings {
  fn default() -> Self {
    Self {
      log_level: "info".into(),
      config_path: "/etc/gluon/config.toml".into(),
    }
  }
}

impl Settings {
  pub fn parse() -> Self {
    Figment::new()
      .merge(Serialized::defaults(Self::default()))
      .merge(Env::raw().only(&["LOG_LEVEL", "CONFIG_PATH"]))
      .extract()
      .expect("Failed to parse settings")
  }
}
