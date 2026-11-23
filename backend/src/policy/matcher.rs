//! `match` conditions: every entry must hold. Values are compiled once at load time.

use std::{collections::BTreeMap, fmt, sync::Arc};

use globset::{GlobBuilder, GlobMatcher};
use regex::Regex;

use crate::oidc::caller::{Caller, FIELDS};

pub struct Matcher {
  conditions: Vec<Condition>,
  expr: Option<Arc<cel::Program>>,
}

struct Condition {
  field: String,
  negate: bool,
  op: Op,
}

enum Op {
  In(Vec<String>),
  Glob(GlobMatcher),
  Regex(Regex),
}

impl fmt::Debug for Matcher {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let fields: Vec<_> = self.conditions.iter().map(|c| c.field.as_str()).collect();
    f.debug_struct("Matcher")
      .field("fields", &fields)
      .field("expr", &self.expr.is_some())
      .finish()
  }
}

fn scalar(v: &toml::Value) -> Result<String, String> {
  match v {
    toml::Value::String(s) => Ok(s.clone()),
    toml::Value::Integer(i) => Ok(i.to_string()),
    toml::Value::Boolean(b) => Ok(b.to_string()),
    _ => Err(format!("unsupported value {v}")),
  }
}

fn list(v: &toml::Value) -> Result<Vec<String>, String> {
  match v {
    toml::Value::Array(a) => a.iter().map(scalar).collect(),
    v => Ok(vec![scalar(v)?]),
  }
}

impl Matcher {
  /// Shorthand: `field = "x"` is `eq`, `field = [..]` is `in`,
  /// `field = { glob = "..", not_eq = ".." }` lists operators.
  pub fn compile(spec: &BTreeMap<String, toml::Value>) -> Result<Matcher, String> {
    let mut conditions = Vec::new();
    let mut expr = None;
    for (field, value) in spec {
      if field == "expr" {
        let src = value.as_str().ok_or("expr must be a string")?;
        let program = cel::Program::compile(src).map_err(|e| format!("expr: {e}"))?;
        expr = Some(Arc::new(program));
        continue;
      }
      if !FIELDS.contains(&field.as_str()) && !field.starts_with("claims.") {
        return Err(format!("unknown match field {field}"));
      }
      let ops: Vec<(String, toml::Value)> = match value {
        toml::Value::Table(t) => t.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        toml::Value::Array(_) => vec![("in".into(), value.clone())],
        v => vec![("eq".into(), v.clone())],
      };
      if ops.is_empty() {
        return Err(format!("{field}: empty condition"));
      }
      for (name, v) in ops {
        let (negate, base) = match name.strip_prefix("not_") {
          Some(b) => (true, b),
          None => (false, name.as_str()),
        };
        let op = match base {
          "eq" | "in" => Op::In(list(&v)?),
          "glob" => {
            let pattern = v
              .as_str()
              .ok_or(format!("{field}.{name} must be a string"))?;
            // `*` does not cross `/`; use `**` for that.
            let glob = GlobBuilder::new(pattern)
              .literal_separator(true)
              .build()
              .map_err(|e| format!("{field}.{name}: {e}"))?;
            Op::Glob(glob.compile_matcher())
          }
          "regex" => {
            let pattern = v
              .as_str()
              .ok_or(format!("{field}.{name} must be a string"))?;
            let re = Regex::new(&format!("^(?:{pattern})$"))
              .map_err(|e| format!("{field}.{name}: {e}"))?;
            Op::Regex(re)
          }
          _ => return Err(format!("{field}: unknown operator {name}")),
        };
        conditions.push(Condition {
          field: field.clone(),
          negate,
          op,
        });
      }
    }
    Ok(Matcher { conditions, expr })
  }

  pub fn matches(&self, caller: &Caller) -> bool {
    for c in &self.conditions {
      let value = caller.get(&c.field);
      let hit = match (&c.op, value.as_deref()) {
        (_, None) => false,
        (Op::In(values), Some(v)) => values.iter().any(|x| x == v),
        (Op::Glob(g), Some(v)) => g.is_match(v),
        (Op::Regex(r), Some(v)) => r.is_match(v),
      };
      if hit == c.negate {
        return false;
      }
    }
    match &self.expr {
      Some(program) => eval_cel(program, caller),
      None => true,
    }
  }
}

fn eval_cel(program: &cel::Program, caller: &Caller) -> bool {
  let mut ctx = cel::Context::default();
  let value = match cel::to_value(caller) {
    Ok(v) => v,
    Err(e) => {
      tracing::warn!("cel: cannot convert caller: {e}");
      return false;
    }
  };
  ctx.add_variable_from_value("caller", value);
  match program.execute(&ctx) {
    Ok(cel::Value::Bool(b)) => b,
    Ok(other) => {
      tracing::warn!("cel: expression returned non-bool {other:?}");
      false
    }
    Err(e) => {
      tracing::debug!("cel: evaluation error {e}");
      false
    }
  }
}

#[cfg(test)]
mod test {
  use super::*;

  fn m(src: &str) -> Matcher {
    let t: toml::Table = toml::from_str(src).unwrap();
    Matcher::compile(&t.into_iter().collect()).unwrap()
  }

  fn caller() -> Caller {
    let mut c = Caller::test("Profiidev/foo", 1, 10);
    c.ref_ = Some("refs/heads/feature/x".into());
    c
  }

  #[test]
  fn operators() {
    let c = caller();
    assert!(m("repository = 'Profiidev/foo'").matches(&c));
    assert!(m("repository_id = [1, 2]").matches(&c));
    assert!(!m("repository_id = { not_in = [1] }").matches(&c));
    assert!(m("ref = { glob = 'refs/heads/**' }").matches(&c));
    assert!(!m("ref = { glob = 'refs/heads/*' }").matches(&c));
    assert!(m("ref = { regex = 'refs/heads/feat.*' }").matches(&c));
    // Anchored: a substring is not enough.
    assert!(!m("ref = { regex = 'heads' }").matches(&c));
    assert!(m("ref = { not_regex = 'refs/tags/.*' }").matches(&c));
    // Missing values never satisfy a positive condition, but satisfy negated ones.
    assert!(!m("environment = { eq = 'prod' }").matches(&c));
    assert!(m("environment = { not_eq = 'prod' }").matches(&c));
  }

  #[test]
  fn cel_expressions() {
    let c = caller();
    assert!(
      m("expr = \"caller.repository.startsWith('Profiidev/') && caller.ref != 'refs/heads/main'\"")
        .matches(&c)
    );
    assert!(!m("expr = \"caller.repository == 'other/repo'\"").matches(&c));
    // Non-bool and errors fail closed.
    assert!(!m("expr = \"caller.repository\"").matches(&c));
    assert!(!m("expr = \"caller.missing.field == 1\"").matches(&c));
  }
}
