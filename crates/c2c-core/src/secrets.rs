//! Secrets : uniquement par reference 1Password (`op://vault/item/champ`), jamais en clair.
use crate::runner::CommandRunner;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

/// Valeur secrete : Debug/Display masques, acces explicite par `expose`.
pub struct Secret(String);

impl Secret {
    pub fn new(v: String) -> Self {
        Secret(v)
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

#[derive(Debug, Error)]
pub enum SecretError {
    #[error("reference invalide (attendu op://coffre/element/champ)")]
    BadReference,
    #[error("secret introuvable ou 1Password verrouille")]
    Unavailable,
}

pub trait SecretProvider {
    fn read(&self, reference: &str) -> Result<Secret, SecretError>;
}

pub fn validate_reference(r: &str) -> Result<(), SecretError> {
    let ok = r.starts_with("op://")
        && r.len() > 5
        && r.len() < 300
        && r.matches('/').count() >= 4
        && !r.chars().any(|c| c.is_control() || c == '\\' || c == '"' || c == '\'' || c == '`' || c == '$' || c == ';' || c == '&' || c == '|' || c == '<' || c == '>')
        && !r.contains("..");
    if ok {
        Ok(())
    } else {
        Err(SecretError::BadReference)
    }
}

/// Lit via la CLI 1Password : `op read --no-newline <ref>`. Les erreurs n'exposent jamais la sortie.
pub struct OpCli<'a> {
    pub runner: &'a dyn CommandRunner,
}

impl SecretProvider for OpCli<'_> {
    fn read(&self, reference: &str) -> Result<Secret, SecretError> {
        validate_reference(reference)?;
        let args = vec!["read".to_string(), "--no-newline".to_string(), reference.to_string()];
        match self.runner.run("op", &args) {
            Ok(o) if o.status == 0 => Ok(Secret::new(o.stdout)),
            _ => Err(SecretError::Unavailable),
        }
    }
}

/// Faux fournisseur pour les tests.
#[derive(Default)]
pub struct FakeSecrets(pub HashMap<String, String>);

impl SecretProvider for FakeSecrets {
    fn read(&self, reference: &str) -> Result<Secret, SecretError> {
        validate_reference(reference)?;
        self.0.get(reference).map(|v| Secret::new(v.clone())).ok_or(SecretError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    #[test]
    fn reference_validation() {
        assert!(validate_reference("op://Homelab/c2c").is_err());
        assert!(validate_reference("op://Homelab/c2c/token").is_ok());
        assert!(validate_reference("op://Homelab/c2c/section/token").is_ok());
        for bad in ["", "op://", "http://x/y/z/w", "op://a/b/c; rm", "op://a/b/c/$(x)", "op://a/../c/d"] {
            assert!(validate_reference(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn debug_never_shows_value() {
        let s = Secret::new("hunter2".into());
        assert!(!format!("{s:?}").contains("hunter2"));
    }

    #[test]
    fn op_cli_uses_argv_and_hides_failure_output() {
        let r = RecordingRunner::ok("value");
        let v = OpCli { runner: &r }.read("op://V/item/field").unwrap();
        assert_eq!(v.expose(), "value");
        assert_eq!(r.calls()[0].0, "op");
        let bad = RecordingRunner::failing(1);
        let e = OpCli { runner: &bad }.read("op://V/item/field").unwrap_err();
        assert!(!e.to_string().contains("boom"));
    }

    #[test]
    fn invalid_reference_never_reaches_runner() {
        let r = RecordingRunner::ok("x");
        assert!(OpCli { runner: &r }.read("op://a/b/c; rm -rf").is_err());
        assert!(r.calls().is_empty());
    }

    #[test]
    fn fake_provider() {
        let mut f = FakeSecrets::default();
        f.0.insert("op://V/i/f".into(), "x".into());
        assert_eq!(f.read("op://V/i/f").unwrap().expose(), "x");
        assert!(f.read("op://V/i/other").is_err());
    }
}
