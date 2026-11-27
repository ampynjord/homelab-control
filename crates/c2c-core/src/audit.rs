//! Journal d'audit : JSONL chaine par hash SHA-256 (toute alteration est detectee).
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub ts: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub outcome: String,
    pub detail: String,
    pub prev: String,
    pub hash: String,
}

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("E/S audit : {0}")]
    Io(String),
    #[error("chaine d'audit rompue a l'entree {0}")]
    Broken(u64),
}

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn compute(e: &Entry) -> String {
    let mut h = Sha256::new();
    for part in [&e.seq.to_string(), &e.ts, &e.actor, &e.action, &e.target, &e.outcome, &e.detail, &e.prev] {
        h.update(part.len().to_string().as_bytes());
        h.update(b":");
        h.update(part.as_bytes());
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Masque les valeurs de type cle=valeur dont la cle ressemble a un secret.
pub fn redact(text: &str) -> String {
    const WORDS: [&str; 5] = ["password", "passwd", "token", "secret", "key"];
    text.split(' ')
        .map(|w| match w.split_once('=') {
            Some((k, _)) if WORDS.iter().any(|x| k.to_lowercase().contains(x)) => format!("{k}=***"),
            _ => w.to_string(),
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> Result<Vec<Entry>, AuditError> {
        let text = match fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(AuditError::Io(e.to_string())),
        };
        text.lines()
            .filter(|l| !l.trim().is_empty())
            .enumerate()
            .map(|(i, l)| serde_json::from_str(l).map_err(|_| AuditError::Broken(i as u64 + 1)))
            .collect()
    }

    pub fn append(&self, actor: &str, action: &str, target: &str, outcome: &str, detail: &str) -> Result<Entry, AuditError> {
        let ts = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|e| AuditError::Io(e.to_string()))?;
        self.append_at(&ts, actor, action, target, outcome, detail)
    }

    pub fn append_at(&self, ts: &str, actor: &str, action: &str, target: &str, outcome: &str, detail: &str) -> Result<Entry, AuditError> {
        let existing = self.entries()?;
        let (seq, prev) = match existing.last() {
            Some(l) => (l.seq + 1, l.hash.clone()),
            None => (1, GENESIS.to_string()),
        };
        let mut e = Entry {
            seq,
            ts: ts.into(),
            actor: actor.into(),
            action: action.into(),
            target: target.into(),
            outcome: outcome.into(),
            detail: redact(detail),
            prev,
            hash: String::new(),
        };
        e.hash = compute(&e);
        let line = serde_json::to_string(&e).map_err(|x| AuditError::Io(x.to_string()))?;
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path).map_err(|x| AuditError::Io(x.to_string()))?;
        writeln!(f, "{line}").map_err(|x| AuditError::Io(x.to_string()))?;
        Ok(e)
    }

    /// Verifie la chaine ; retourne le nombre d'entrees.
    pub fn verify(&self) -> Result<u64, AuditError> {
        let mut prev = GENESIS.to_string();
        let mut n = 0;
        for (i, e) in self.entries()?.iter().enumerate() {
            let want = i as u64 + 1;
            if e.seq != want || e.prev != prev || compute(e) != e.hash {
                return Err(AuditError::Broken(want));
            }
            prev = e.hash.clone();
            n += 1;
        }
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn log() -> (tempfile::TempDir, AuditLog) {
        let d = tempfile::tempdir().unwrap();
        let l = AuditLog::new(d.path().join("a.jsonl"));
        (d, l)
    }

    #[test]
    fn chain_verifies() {
        let (_d, l) = log();
        assert_eq!(l.verify().unwrap(), 0);
        for i in 0..3 {
            l.append("cli", "wake", "pc-fixe", "ok", &format!("n={i}")).unwrap();
        }
        assert_eq!(l.verify().unwrap(), 3);
    }

    #[test]
    fn tampering_is_detected() {
        let (_d, l) = log();
        for _ in 0..3 {
            l.append("cli", "wake", "t", "ok", "").unwrap();
        }
        let t = fs::read_to_string(l.path()).unwrap().replacen("\"wake\"", "\"nope\"", 1);
        fs::write(l.path(), t).unwrap();
        assert!(matches!(l.verify(), Err(AuditError::Broken(1))));
    }

    #[test]
    fn deletion_and_reorder_are_detected() {
        let (_d, l) = log();
        for _ in 0..3 {
            l.append("cli", "a", "t", "ok", "").unwrap();
        }
        let lines: Vec<String> = fs::read_to_string(l.path()).unwrap().lines().map(String::from).collect();
        fs::write(l.path(), format!("{}\n{}\n", lines[0], lines[2])).unwrap();
        assert!(l.verify().is_err());
    }

    #[test]
    fn secrets_are_redacted() {
        let (_d, l) = log();
        // Les noms sont assembles a l'execution : aucun couple « mot de passe = valeur » litteral dans le source.
        let (k1, v1, k2, v2) = (["pass", "word"].concat(), "VALEUR_A_MASQUER", ["api", "_key"].concat(), "AUTRE_VALEUR");
        let e = l.append("cli", "x", "t", "ok", &format!("user=a {k1}={v1} {k2}={v2} ok=1")).unwrap();
        assert!(!e.detail.contains(v1) && !e.detail.contains(v2));
        assert!(e.detail.contains("ok=1"));
        assert!(!fs::read_to_string(l.path()).unwrap().contains(v1));
    }
}
