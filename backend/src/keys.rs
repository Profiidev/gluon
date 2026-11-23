//! GitHub App private keys. Key material is zeroized after parsing and
//! never appears in `Debug` output or errors.

use std::{fmt, path::Path};

use jsonwebtoken::EncodingKey;
use zeroize::Zeroizing;

use crate::config::KeySource;

pub struct AppKey {
  pub encoding: EncodingKey,
  /// Where the key came from, for logs.
  pub origin: String,
}

impl fmt::Debug for AppKey {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "AppKey({})", self.origin)
  }
}

impl AppKey {
  // shortcut: jsonwebtoken's EncodingKey keeps its own copy of the DER bytes
  // and does not zeroize it on drop; an external signer would fix that.
  pub fn load(source: &KeySource) -> Result<AppKey, String> {
    let (pem, origin) = match source {
      KeySource::File { path } => (read_file(path)?, format!("file:{}", path.display())),
      KeySource::SystemdCredential { name } => {
        let dir = std::env::var("CREDENTIALS_DIRECTORY")
          .map_err(|_| format!("systemd credential {name}: CREDENTIALS_DIRECTORY is not set"))?;
        let path = Path::new(&dir).join(name);
        (read_file(&path)?, format!("systemd-credential:{name}"))
      }
      KeySource::Env { name } => {
        let value =
          Zeroizing::new(std::env::var(name).map_err(|_| format!("env key {name} is not set"))?);
        (
          Zeroizing::new(value.as_bytes().to_vec()),
          format!("env:{name}"),
        )
      }
    };
    let encoding =
      EncodingKey::from_rsa_pem(&pem).map_err(|_| format!("{origin}: not a valid RSA PEM key"))?;
    Ok(AppKey { encoding, origin })
  }
}

fn read_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    // 0400 is the goal; group read is tolerated because Kubernetes adds it with fsGroup.
    if mode & 0o037 != 0 {
      return Err(format!(
        "{}: mode {mode:o} is too open (no group write or world access allowed)",
        path.display()
      ));
    }
  }
  std::fs::read(path)
    .map(Zeroizing::new)
    .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(test)]
mod test {
  use std::{io::Write, os::unix::fs::PermissionsExt};

  use super::*;

  const KEY: &str = include_str!("../tests/fixtures/app-key.pem");

  fn key_file(mode: u32) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(KEY.as_bytes()).unwrap();
    std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode)).unwrap();
    f
  }

  #[test]
  fn file_modes() {
    for mode in [0o400, 0o440, 0o600] {
      let f = key_file(mode);
      let src = KeySource::File {
        path: f.path().into(),
      };
      AppKey::load(&src).unwrap();
    }
    for mode in [0o644, 0o460, 0o404] {
      let f = key_file(mode);
      let src = KeySource::File {
        path: f.path().into(),
      };
      assert!(AppKey::load(&src).unwrap_err().contains("too open"));
    }
  }

  #[test]
  fn env_and_errors_hide_material() {
    unsafe { std::env::set_var("GLUON_TEST_KEY", KEY) };
    let key = AppKey::load(&KeySource::Env {
      name: "GLUON_TEST_KEY".into(),
    })
    .unwrap();
    assert_eq!(format!("{key:?}"), "AppKey(env:GLUON_TEST_KEY)");

    unsafe { std::env::set_var("GLUON_TEST_KEY", "not a key") };
    let err = AppKey::load(&KeySource::Env {
      name: "GLUON_TEST_KEY".into(),
    })
    .unwrap_err();
    assert!(!err.contains("not a key"));
  }

  #[test]
  fn systemd_credential() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gh-app-main");
    std::fs::write(&path, KEY).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
    unsafe { std::env::set_var("CREDENTIALS_DIRECTORY", dir.path()) };
    AppKey::load(&KeySource::SystemdCredential {
      name: "gh-app-main".into(),
    })
    .unwrap();
  }
}
