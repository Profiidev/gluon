use std::{path::PathBuf, sync::Arc};

use axum::{Extension, Router};
use centaurus::{
  backend::{
    endpoints::health::ReadyCheck,
    init::{listener_setup, run_app_connect_info},
    router::build_router,
  },
  version_header,
};
use tokio::net::TcpListener;
use tracing::info;

pub use crate::{
  config::Config,
  settings::Settings,
  state::{AppState, Runtime},
};

pub mod api;
pub mod config;
pub mod github;
pub mod keys;
pub mod oidc;
pub mod policy;
mod settings;
pub mod state;

pub struct App {
  app: Router,
  listener: TcpListener,
  pub state: Arc<AppState>,
}

impl App {
  pub async fn new(settings: Settings, config_path: PathBuf) -> Result<App, String> {
    let config = Config::load(&config_path)?;
    let http = state::http_client();
    let runtime = Runtime::build(config, None, &http)?;
    let state = Arc::new(AppState::new(runtime, config_path, http));

    let listener = listener_setup(settings.base.port).await;
    let api_state = state.clone();
    let ready_state = state.clone();
    // Routes end up under /api; centaurus adds /api/health, /api/ready, metrics, CORS and logging.
    let mut app = build_router(
      |limiter| api::router(api_state, limiter),
      |router, _| async move {
        router.layer(Extension(ReadyCheck::new(move || {
          ready_state
            .runtime
            .load()
            .ready()
            .then_some(())
            .ok_or("JWKS not fetched yet")
        })))
      },
      settings,
    )
    .await;
    version_header!(app);

    state.spawn_jwks_fetch();
    state::spawn_reloaders(state.clone());

    Ok(App {
      app,
      listener,
      state,
    })
  }

  pub fn port(&self) -> u16 {
    self.listener.local_addr().expect("listener address").port()
  }

  pub async fn run(self) {
    info!("Listening on {}", self.listener.local_addr().unwrap());
    run_app_connect_info(self.listener, self.app).await;
  }
}
