use std::{path::PathBuf, process::ExitCode};

use backend::{App, Config, Settings};
use centaurus::logging::init_logging;
#[cfg(debug_assertions)]
use dotenvy::dotenv;

const USAGE: &str = "usage: gluon [--config <path>] [--check]";

#[tokio::main]
async fn main() -> ExitCode {
  #[cfg(debug_assertions)]
  dotenv().ok();

  let settings = Settings::parse();
  let mut config_path = settings.config_path;
  let mut check = false;
  let mut args = std::env::args().skip(1);
  while let Some(arg) = args.next() {
    match arg.as_str() {
      "--check" => check = true,
      "--config" => match args.next() {
        Some(p) => config_path = PathBuf::from(p),
        None => {
          eprintln!("{USAGE}");
          return ExitCode::from(2);
        }
      },
      _ => {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
      }
    }
  }

  if check {
    return match Config::load(&config_path) {
      Ok(_) => {
        println!("{}: OK", config_path.display());
        ExitCode::SUCCESS
      }
      Err(e) => {
        eprintln!("{}: {e}", config_path.display());
        ExitCode::FAILURE
      }
    };
  }

  init_logging(
    settings
      .log_level
      .parse()
      .unwrap_or(tracing::level_filters::LevelFilter::INFO),
  );
  match App::new(config_path).await {
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
