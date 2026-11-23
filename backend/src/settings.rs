//! Process settings from the environment (template style); policy lives in the TOML file.

use centaurus::{
  Config,
  backend::config::{BaseConfig, MetricsConfig},
};
use figment::{
  Figment,
  providers::{Env, Serialized},
};
use serde::{Deserialize, Serialize};

/// `PORT`, `LOG_LEVEL`, `ALLOWED_ORIGINS`, `METRICS_ENABLED`, `METRICS_PORT`, `METRICS_NAME`.
#[derive(Deserialize, Serialize, Clone, Config)]
pub struct Settings {
  #[base]
  #[serde(flatten)]
  pub base: BaseConfig,
  #[metrics]
  #[serde(flatten)]
  pub metrics: MetricsConfig,
}

impl Default for Settings {
  fn default() -> Self {
    Self {
      base: BaseConfig::default(),
      metrics: MetricsConfig {
        metrics_enabled: true,
        metrics_name: "gluon".into(),
        ..Default::default()
      },
    }
  }
}

impl Settings {
  pub fn parse() -> Self {
    Figment::new()
      .merge(Serialized::defaults(Self::default()))
      .merge(Env::raw().global())
      .extract()
      .expect("Failed to parse settings")
  }
}
