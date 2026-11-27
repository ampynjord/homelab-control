//! Cle d'identite de l'agent (Ed25519), generee sur SA machine au premier demarrage, comme une cle d'hote SSH.
//! Elle sert a signer les reponses : les clients en epinglent la cle publique et reconnaissent ainsi le vrai agent.
//! Le fichier n'est lisible que par le compte qui execute l'agent ; sinon l'agent refuse de demarrer. Aucun 1Password requis.
use crate::proto::{generate_key, parse_seed, seed_hex};
use crate::runner::CommandRunner;
use ed25519_dalek::SigningKey;
use std::path::{Path, PathBuf};

/// Emplacement par defaut : a cote de la configuration.
pub fn path_for(config: &Path) -> PathBuf {
    config.with_file_name("c2c-agent-hostkey")
}

/// Lit la cle si le fichier existe (sans jamais en creer une).
pub fn load(path: &Path) -> Result<Option<SigningKey>, String> {
    match std::fs::read_to_string(path) {
        Ok(t) => parse_seed(&t).map(Some).map_err(|e| format!("{} : {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("lecture de {} : {e}", path.display())),
    }
}

/// Restreint le fichier au compte courant. Echec = erreur (on ne garde jamais une cle d'identite lisible par d'autres).
fn restrict(path: &Path, runner: &dyn CommandRunner) -> Result<(), String> {
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").map_err(|_| "USERNAME absent : droits du fichier de cle impossibles a fixer".to_string())?;
        let args = vec![path.display().to_string(), "/inheritance:r".into(), "/grant:r".into(), format!("{user}:F")];
        match runner.run("icacls", &args) {
            Ok(o) if o.status == 0 => Ok(()),
            _ => Err("icacls a echoue : droits du fichier de cle non restreints".into()),
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = runner;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())
    }
}

/// Charge la cle, ou la cree (premier demarrage). Renvoie (cle, creee_maintenant).
pub fn load_or_create(path: &Path, runner: &dyn CommandRunner) -> Result<(SigningKey, bool), String> {
    if let Some(k) = load(path)? {
        return Ok((k, false));
    }
    let k = generate_key();
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|e| format!("creation de {} : {e}", path.display()))?;
        f.write_all(seed_hex(&k).as_bytes()).map_err(|e| e.to_string())?;
    }
    if let Err(e) = restrict(path, runner) {
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok((k, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::pubkey_hex;
    use crate::runner::RecordingRunner;

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("c2c-hostkey-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn created_once_then_reloaded_identically() {
        let p = tmp("once");
        let r = RecordingRunner::ok("");
        let (k1, created) = load_or_create(&p, &r).unwrap();
        assert!(created);
        let (k2, created2) = load_or_create(&p, &r).unwrap();
        assert!(!created2);
        assert_eq!(pubkey_hex(&k1), pubkey_hex(&k2));
        // Sous Windows, les droits sont fixes par icacls : une seule fois, a la creation.
        #[cfg(windows)]
        assert_eq!(r.calls().iter().filter(|(c, _)| c == "icacls").count(), 1);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    #[cfg(windows)]
    fn a_key_whose_permissions_cannot_be_restricted_is_not_kept() {
        let p = tmp("acl");
        let r = RecordingRunner::failing(5);
        assert!(load_or_create(&p, &r).is_err());
        assert!(!p.exists(), "pas de cle laissee lisible par d'autres");
    }

    #[test]
    fn corrupted_files_are_refused_and_load_never_creates() {
        let p = tmp("bad");
        assert!(load(&p).unwrap().is_none());
        assert!(!p.exists());
        std::fs::write(&p, "pas une cle").unwrap();
        assert!(load(&p).is_err());
        assert!(load_or_create(&p, &RecordingRunner::ok("")).is_err());
        std::fs::remove_file(&p).ok();
    }
}
