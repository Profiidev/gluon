use std::{path::PathBuf, process::ExitCode};

use backend::{App, Config, Settings};
use centaurus::logging::init_logging;
use clap::Parser;
#[cfg(debug_assertions)]
use dotenvy::dotenv;

/// GitHub App token broker: exchanges CI OIDC tokens for scoped installation tokens.
#[derive(Parser)]
#[command(name = "gluon", version)]
struct Cli {
  /// Path to the TOML configuration.
  #[arg(
    long = "config",
    env = "CONFIG_PATH",
    default_value = "/etc/gluon/config.toml"
  )]
  config_path: PathBuf,

  /// Validate the configuration and exit.
  #[arg(long)]
  check: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
  #[cfg(debug_assertions)]
  dotenv().ok();

  let cli = Cli::parse();

  if cli.check {
    return match Config::load(&cli.config_path) {
      Ok(_) => {
        println!("{}: OK", cli.config_path.display());
        ExitCode::SUCCESS
      }
      Err(e) => {
        eprintln!("{}: {e}", cli.config_path.display());
        ExitCode::FAILURE
      }
    };
  }

  let settings = Settings::parse();
  init_logging(settings.base.log_level);
  match App::new(settings, cli.config_path).await {
    Ok(app) => {
      app.run().await;
      ExitCode::SUCCESS
    }
    Err(e) => {
      tracing::error!("startup failed: {e}");
      ExitCode::FAILURE
    }
  }
}
