//! `c2c keygen <appareil>` : cree la paire de cles de CET appareil. La cle PRIVEE va directement dans le 1Password de cet appareil
//! (jamais affichee, jamais dans un fichier ni dans une ligne de commande : elle transite par l'entree standard de `op`).
//! Seule la cle PUBLIQUE est affichee : elle se place dans la configuration de l'agent (`[[agent.client]] pubkey`).
use c2c_core::proto::{generate_key, pubkey_hex, seed_hex};
use c2c_core::runner::CommandRunner;
use serde_json::json;

#[derive(Debug, Clone)]
pub struct Keygen {
    pub pubkey: String,
    /// Reference 1Password de la cle privee, a mettre dans `key_ref` de la machine pilotee.
    pub key_ref: String,
    pub title: String,
}

fn safe_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 40 && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

pub fn keygen(runner: &dyn CommandRunner, device: &str, vault: &str) -> Result<Keygen, String> {
    if !safe_name(device) || !safe_name(vault) {
        return Err("nom d'appareil ou de coffre invalide (lettres, chiffres, - _ . ; 40 caracteres max)".into());
    }
    let title = format!("c2c-{device}-key");
    let key_ref = format!("op://{vault}/{title}/password");
    // On ne remplace jamais une cle existante : elle pourrait etre en service.
    let exists = runner.run("op", &["read".into(), "--no-newline".into(), key_ref.clone()]).map(|o| o.status == 0).unwrap_or(false);
    if exists {
        return Err(format!("{key_ref} existe deja : supprimez-le dans 1Password si vous voulez regenerer la cle (l'agent devra alors recevoir la nouvelle cle publique)"));
    }
    let key = generate_key();
    let template = json!({
        "title": title,
        "category": "PASSWORD",
        "fields": [{"id": "password", "type": "CONCEALED", "purpose": "PASSWORD", "value": seed_hex(&key)}],
        "tags": ["c2c"]
    })
    .to_string();
    let created = runner
        .run_stdin("op", &["item".into(), "create".into(), "--vault".into(), vault.into()], &template)
        .map_err(|e| format!("op indisponible : {e}"))?;
    if created.status != 0 {
        return Err("creation dans 1Password refusee (application verrouillee ? integration CLI active ?)".into());
    }
    // Relecture : la cle enregistree doit etre exactement celle qu'on vient de generer.
    let back = runner.run("op", &["read".into(), "--no-newline".into(), key_ref.clone()]).map_err(|e| e.to_string())?;
    if back.status != 0 || back.stdout.trim() != seed_hex(&key) {
        return Err("verification apres creation echouee : la cle enregistree ne correspond pas".into());
    }
    Ok(Keygen { pubkey: pubkey_hex(&key), key_ref, title })
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2c_core::runner::{Output, RecordingRunner};
    use std::io;
    use std::sync::Mutex;

    /// Faux `op` : memorise le champ `password` du modele recu sur l'entree standard et le restitue a `op read`.
    #[derive(Default)]
    struct FakeOp {
        stored: Mutex<Option<String>>,
        argv: Mutex<Vec<String>>,
    }

    impl CommandRunner for FakeOp {
        fn run(&self, program: &str, args: &[String]) -> io::Result<Output> {
            self.argv.lock().unwrap().push(format!("{program} {}", args.join(" ")));
            let ok = |s: String| Output { status: 0, stdout: s, stderr: String::new() };
            match (program, args.first().map(String::as_str)) {
                ("op", Some("read")) => match self.stored.lock().unwrap().clone() {
                    Some(v) => Ok(ok(v)),
                    None => Ok(Output { status: 1, stdout: String::new(), stderr: "isn't an item".into() }),
                },
                _ => Ok(ok(String::new())),
            }
        }
        fn run_stdin(&self, program: &str, args: &[String], stdin: &str) -> io::Result<Output> {
            self.argv.lock().unwrap().push(format!("{program} {}", args.join(" ")));
            let v: serde_json::Value = serde_json::from_str(stdin).unwrap();
            *self.stored.lock().unwrap() = v["fields"][0]["value"].as_str().map(str::to_string);
            Ok(Output { status: 0, stdout: "created".into(), stderr: String::new() })
        }
    }

    #[test]
    fn private_key_goes_to_1password_only_and_matches_the_public_key_shown() {
        let op = FakeOp::default();
        let k = keygen(&op, "portable", "Homelab").unwrap();
        assert_eq!(k.key_ref, "op://Homelab/c2c-portable-key/password");
        let seed = op.stored.lock().unwrap().clone().unwrap();
        assert_eq!(seed.len(), 64);
        // La cle publique affichee derive bien de la cle privee enregistree.
        let derived = c2c_core::proto::pubkey_hex(&c2c_core::proto::parse_seed(&seed).unwrap());
        assert_eq!(k.pubkey, derived);
        // Jamais sur une ligne de commande, jamais dans ce que l'on renvoie a l'ecran.
        assert!(op.argv.lock().unwrap().iter().all(|l| !l.contains(&seed)));
        assert!(!k.pubkey.contains(&seed) && !format!("{k:?}").contains(&seed));
    }

    #[test]
    fn an_existing_key_is_never_replaced_and_names_are_validated() {
        let op = FakeOp::default();
        keygen(&op, "portable", "Homelab").unwrap();
        assert!(keygen(&op, "portable", "Homelab").unwrap_err().contains("existe deja"));
        assert!(keygen(&op, "a b", "Homelab").is_err());
        assert!(keygen(&op, "ok", "x; calc").is_err());
        assert!(keygen(&op, "", "Homelab").is_err());
        let ko = RecordingRunner::failing(1);
        assert!(keygen(&ko, "x", "Homelab").unwrap_err().contains("refusee"));
    }
}
