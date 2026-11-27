//! Mises a jour signees : un manifeste (version + empreintes SHA-256 des fichiers) signe en Ed25519 par la cle de publication.
//! La cle privee reste dans le 1Password du proprietaire ; l'application n'embarque que la cle publique et refuse tout manifeste
//! ou fichier non conforme. Aucune notion de transport ici : le manifeste peut venir du tailnet, d'un fichier local, etc.
use crate::proto::{generate_key, parse_pubkey, parse_seed};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PREFIX: &[u8] = b"c2c-update1\n";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileEntry {
    pub name: String,
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Manifest {
    pub version: String,
    pub files: Vec<FileEntry>,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    manifest: String, // JSON du manifeste, signe tel quel (octets exacts)
    signature: String,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

fn signed_bytes(manifest_json: &str) -> Vec<u8> {
    [PREFIX, manifest_json.as_bytes()].concat()
}

/// Signe un manifeste ; renvoie l'enveloppe JSON a publier.
pub fn sign_manifest(key: &SigningKey, m: &Manifest) -> String {
    let manifest = serde_json::to_string(m).expect("manifeste serialisable");
    let sig = key.sign(&signed_bytes(&manifest));
    let sig_hex: String = sig.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
    serde_json::to_string_pretty(&Envelope { manifest, signature: sig_hex }).expect("enveloppe serialisable")
}

/// Verifie la signature puis decode le manifeste. Toute erreur = refus.
pub fn verify_manifest(pubkey: &VerifyingKey, envelope: &str) -> Result<Manifest, String> {
    let env: Envelope = serde_json::from_str(envelope).map_err(|_| "enveloppe illisible".to_string())?;
    let raw = (0..env.signature.len()).step_by(2).map(|i| env.signature.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok())).collect::<Option<Vec<u8>>>().ok_or("signature illisible")?;
    let arr: [u8; 64] = raw.try_into().map_err(|_| "signature de mauvaise longueur".to_string())?;
    pubkey.verify(&signed_bytes(&env.manifest), &Signature::from_bytes(&arr)).map_err(|_| "signature invalide : mise a jour refusee".to_string())?;
    let m: Manifest = serde_json::from_str(&env.manifest).map_err(|_| "manifeste illisible".to_string())?;
    parse_version(&m.version)?;
    Ok(m)
}

/// Verifie qu'un fichier telecharge correspond exactement au manifeste (nom connu, taille et SHA-256).
pub fn verify_file(m: &Manifest, name: &str, bytes: &[u8]) -> Result<(), String> {
    let e = m.files.iter().find(|f| f.name == name).ok_or_else(|| format!("{name} absent du manifeste"))?;
    if e.size != bytes.len() as u64 || e.sha256 != sha256_hex(bytes) {
        return Err(format!("{name} ne correspond pas au manifeste signe : refuse"));
    }
    Ok(())
}

pub fn parse_version(v: &str) -> Result<(u64, u64, u64), String> {
    let v = v.strip_prefix('v').unwrap_or(v);
    let p: Vec<&str> = v.split('.').collect();
    if p.len() != 3 {
        return Err(format!("version invalide : {v}"));
    }
    let n = |s: &str| s.parse::<u64>().map_err(|_| format!("version invalide : {v}"));
    Ok((n(p[0])?, n(p[1])?, n(p[2])?))
}

/// Vrai si `candidate` est strictement plus recente que `current` (pas de retour en arriere : anti-downgrade).
pub fn is_newer(current: &str, candidate: &str) -> Result<bool, String> {
    Ok(parse_version(candidate)? > parse_version(current)?)
}

/// Nouvelle paire de cles de publication : (graine hex a mettre dans 1Password, cle publique hex a embarquer dans l'application).
pub fn new_release_key() -> (String, String) {
    let k = generate_key();
    (crate::proto::seed_hex(&k), crate::proto::pubkey_hex(&k))
}

pub fn load_keys(seed: &str, pubkey: &str) -> Result<(SigningKey, VerifyingKey), String> {
    Ok((parse_seed(seed)?, parse_pubkey(pubkey)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(bytes: &[u8]) -> Manifest {
        Manifest { version: "0.5.0".into(), files: vec![FileEntry { name: "c2c.exe".into(), sha256: sha256_hex(bytes), size: bytes.len() as u64 }] }
    }

    #[test]
    fn signed_manifest_roundtrips_and_checks_files() {
        let k = generate_key();
        let m = sample(b"binaire");
        let env = sign_manifest(&k, &m);
        let got = verify_manifest(&k.verifying_key(), &env).unwrap();
        assert_eq!(got, m);
        assert!(verify_file(&got, "c2c.exe", b"binaire").is_ok());
        assert!(verify_file(&got, "c2c.exe", b"binaire!").is_err(), "fichier modifie refuse");
        assert!(verify_file(&got, "autre.exe", b"binaire").is_err(), "fichier inconnu refuse");
    }

    #[test]
    fn wrong_key_or_tampered_manifest_is_refused() {
        let (k, other) = (generate_key(), generate_key());
        let env = sign_manifest(&k, &sample(b"x"));
        assert!(verify_manifest(&other.verifying_key(), &env).is_err());
        let tampered = env.replace("0.5.0", "9.9.9");
        assert!(verify_manifest(&k.verifying_key(), &tampered).is_err());
        assert!(verify_manifest(&k.verifying_key(), "pas du json").is_err());
    }

    #[test]
    fn versions_compare_without_downgrade() {
        assert!(is_newer("0.4.0", "v0.4.1").unwrap());
        assert!(is_newer("0.4.9", "0.10.0").unwrap(), "comparaison numerique, pas textuelle");
        assert!(!is_newer("0.4.0", "0.4.0").unwrap());
        assert!(!is_newer("0.4.0", "0.3.9").unwrap());
        assert!(is_newer("0.4.0", "abc").is_err());
    }
}

// ---------- mise a jour depuis les releases GitHub (depot public : aucun jeton) ----------
use crate::runner::CommandRunner;
use std::path::{Path, PathBuf};

/// Version de ce programme : celle du tag de la release (injectee par la CI via `C2C_VERSION`), sinon celle du paquet.
pub const VERSION: &str = match option_env!("C2C_VERSION") {
    Some(v) if !v.is_empty() => v,
    _ => env!("CARGO_PKG_VERSION"),
};
pub const DEFAULT_REPO: &str = "ampynjord/homelab-control";
/// Fichiers remplacables, s'ils existent a cote de l'executable en cours.
pub const ASSETS: [&str; 2] = ["c2c.exe", "c2c-desktop.exe"];

#[derive(Debug, Clone, PartialEq)]
pub struct Release {
    pub tag: String,
    pub assets: Vec<(String, String)>, // (nom, url de telechargement)
}

fn safe_repo(repo: &str) -> bool {
    let parts: Vec<&str> = repo.split('/').collect();
    parts.len() == 2 && parts.iter().all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'))
}

/// Une URL de telechargement n'est acceptee que si elle pointe vers une release du depot configure (HTTPS, caracteres sains).
pub fn valid_download_url(repo: &str, url: &str) -> bool {
    let prefix = format!("https://github.com/{repo}/releases/download/");
    safe_repo(repo) && url.starts_with(&prefix) && url[prefix.len()..].chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'))
}

pub fn parse_release(repo: &str, json: &str) -> Result<Release, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|_| "reponse GitHub illisible".to_string())?;
    let tag = v["tag_name"].as_str().ok_or("pas de release publiee")?.to_string();
    parse_version(&tag)?;
    let assets = v["assets"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| Some((x["name"].as_str()?.to_string(), x["browser_download_url"].as_str()?.to_string()))).filter(|(_, u)| valid_download_url(repo, u)).collect())
        .unwrap_or_default();
    Ok(Release { tag, assets })
}

fn ps(runner: &dyn CommandRunner, script: String) -> Result<String, String> {
    let o = runner.run("powershell", &["-NoProfile".into(), "-NonInteractive".into(), "-Command".into(), script]).map_err(|e| format!("PowerShell indisponible : {e}"))?;
    if o.status != 0 {
        return Err(format!("echec du telechargement ({})", o.stderr.lines().next().unwrap_or("erreur inconnue")));
    }
    Ok(o.stdout)
}

pub fn latest(runner: &dyn CommandRunner, repo: &str) -> Result<Release, String> {
    if !safe_repo(repo) {
        return Err("depot invalide".into());
    }
    let script = format!(
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $ProgressPreference='SilentlyContinue'; Invoke-RestMethod -UseBasicParsing -Headers @{{'User-Agent'='c2c'}} -Uri 'https://api.github.com/repos/{repo}/releases/latest' | ConvertTo-Json -Depth 5 -Compress"
    );
    parse_release(repo, &ps(runner, script)?)
}

fn download(runner: &dyn CommandRunner, repo: &str, url: &str, dest: &Path) -> Result<Vec<u8>, String> {
    if !valid_download_url(repo, url) {
        return Err("adresse de telechargement refusee".into());
    }
    let d = dest.to_string_lossy();
    if d.contains('\'') {
        return Err("chemin temporaire invalide".into());
    }
    let script = format!("[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $ProgressPreference='SilentlyContinue'; Invoke-WebRequest -UseBasicParsing -Headers @{{'User-Agent'='c2c'}} -Uri '{url}' -OutFile '{d}'");
    ps(runner, script)?;
    std::fs::read(dest).map_err(|e| format!("fichier telecharge illisible : {e}"))
}

fn sha_of_text(t: &str) -> Result<String, String> {
    let h = t.split_whitespace().next().unwrap_or("").to_lowercase();
    if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) {
        Ok(h)
    } else {
        Err("empreinte publiee invalide".into())
    }
}

/// Remplace `dir/name` par `bytes` : l'ancien fichier est renomme en `.old` (possible meme s'il tourne), puis remis si l'ecriture echoue.
pub fn swap_file(dir: &Path, name: &str, bytes: &[u8]) -> Result<PathBuf, String> {
    let target = dir.join(name);
    let old = dir.join(format!("{name}.old"));
    let staged = dir.join(format!("{name}.new"));
    std::fs::write(&staged, bytes).map_err(|e| format!("ecriture impossible : {e}"))?;
    let _ = std::fs::remove_file(&old);
    if target.exists() {
        std::fs::rename(&target, &old).map_err(|e| {
            let _ = std::fs::remove_file(&staged);
            format!("remplacement impossible : {e}")
        })?;
    }
    if let Err(e) = std::fs::rename(&staged, &target) {
        let _ = std::fs::rename(&old, &target);
        return Err(format!("remplacement impossible : {e}"));
    }
    Ok(target)
}

/// Telecharge et installe la release : tout est verifie (URL, empreinte SHA-256 publiee) AVANT de remplacer le moindre fichier.
pub fn install(runner: &dyn CommandRunner, repo: &str, rel: &Release, dir: &Path) -> Result<Vec<String>, String> {
    let tmp = std::env::temp_dir().join(format!("c2c-maj-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).map_err(|e| e.to_string())?;
    let result = (|| {
        let mut ready: Vec<(&str, Vec<u8>)> = Vec::new();
        for name in ASSETS.iter().filter(|n| dir.join(n).exists()) {
            let url_of = |n: &str| rel.assets.iter().find(|(a, _)| a == n).map(|(_, u)| u.clone()).ok_or_else(|| format!("{n} absent de la release {}", rel.tag));
            let bin = download(runner, repo, &url_of(name)?, &tmp.join(name))?;
            let sha = download(runner, repo, &url_of(&format!("{name}.sha256"))?, &tmp.join(format!("{name}.sha256")))?;
            if sha_of_text(&String::from_utf8_lossy(&sha))? != sha256_hex(&bin) {
                return Err(format!("{name} : empreinte SHA-256 differente de celle publiee, mise a jour refusee"));
            }
            ready.push((name, bin));
        }
        if ready.is_empty() {
            return Err("aucun fichier C2C a mettre a jour dans ce dossier".into());
        }
        let mut done = Vec::new();
        for (name, bin) in ready {
            swap_file(dir, name, &bin)?;
            done.push(name.to_string());
        }
        Ok(done)
    })();
    let _ = std::fs::remove_dir_all(&tmp);
    result
}

#[cfg(test)]
mod release_tests {
    use super::*;

    #[test]
    fn only_urls_of_the_configured_repo_are_accepted() {
        let r = "o/p";
        assert!(valid_download_url(r, "https://github.com/o/p/releases/download/v1.0.0/c2c.exe"));
        assert!(!valid_download_url(r, "https://github.com/autre/p/releases/download/v1.0.0/c2c.exe"));
        assert!(!valid_download_url(r, "http://github.com/o/p/releases/download/v1.0.0/c2c.exe"));
        assert!(!valid_download_url(r, "https://github.com/o/p/releases/download/v1/c2c.exe'; calc; '"));
        assert!(!valid_download_url("o/p'x", "https://github.com/o/p'x/releases/download/a"));
    }

    #[test]
    fn parses_release_and_drops_foreign_assets() {
        let j = r#"{"tag_name":"v0.6.0","assets":[
          {"name":"c2c.exe","browser_download_url":"https://github.com/o/p/releases/download/v0.6.0/c2c.exe"},
          {"name":"evil.exe","browser_download_url":"https://evil.example/evil.exe"}]}"#;
        let rel = parse_release("o/p", j).unwrap();
        assert_eq!(rel.tag, "v0.6.0");
        assert_eq!(rel.assets.len(), 1);
        assert!(parse_release("o/p", r#"{"tag_name":"latest"}"#).is_err());
        assert!(parse_release("o/p", "x").is_err());
    }

    #[test]
    fn swap_keeps_the_old_file_and_installs_the_new_one() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("c2c.exe"), b"ancien").unwrap();
        swap_file(d.path(), "c2c.exe", b"nouveau").unwrap();
        assert_eq!(std::fs::read(d.path().join("c2c.exe")).unwrap(), b"nouveau");
        assert_eq!(std::fs::read(d.path().join("c2c.exe.old")).unwrap(), b"ancien");
        assert!(!d.path().join("c2c.exe.new").exists());
    }

    #[test]
    fn published_hash_must_be_valid_hex() {
        assert!(sha_of_text(&format!("{}  c2c.exe\r\n", "a".repeat(64))).is_ok());
        assert!(sha_of_text("pas un hash").is_err());
    }
}
