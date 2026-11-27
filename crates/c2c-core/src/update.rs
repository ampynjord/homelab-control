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
