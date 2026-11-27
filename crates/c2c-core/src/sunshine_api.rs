//! API web de Sunshine (appairage Moonlight, liste/retrait de clients), depuis le PC fixe uniquement.
//! Les identifiants viennent de 1Password : lus UNE SEULE FOIS par processus (cache en memoire, jamais sur disque ni dans le
//! journal), puis transmis a PowerShell par l'ENTREE STANDARD (jamais par la ligne de commande ni par un fichier).
//! Un agent qui tourne en continu ne redemande donc rien a 1Password apres son premier appel. Le certificat de Sunshine est autosigne : au lieu de desactiver la
//! verification, on EPINGLE son empreinte (celle de `credentials\cacert.pem`).
use crate::runner::CommandRunner;
use crate::secrets::{validate_reference, OpCli, SecretProvider};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct SunshineConfig {
    #[serde(default = "default_url")]
    pub url: String,
    #[serde(default = "default_user_ref")]
    pub user_ref: String,
    #[serde(default = "default_pass_ref")]
    pub pass_ref: String,
    #[serde(default = "default_cert")]
    pub cert_path: String,
}

fn default_url() -> String {
    "https://127.0.0.1:47990".into()
}
fn default_user_ref() -> String {
    "op://Homelab/Sunshine/username".into()
}
fn default_pass_ref() -> String {
    "op://Homelab/Sunshine/password".into()
}
fn default_cert() -> String {
    r"C:\Program Files\Sunshine\config\credentials\cacert.pem".into()
}

impl Default for SunshineConfig {
    fn default() -> Self {
        Self { url: default_url(), user_ref: default_user_ref(), pass_ref: default_pass_ref(), cert_path: default_cert() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Clients,
    /// Demandes d'appairage en attente de PIN (GET /api/pin).
    Pending,
    /// `pairing_id` : identifiant de la demande ; absent = la seule demande en attente.
    Pin { pin: String, name: String, pairing_id: Option<String> },
    Unpair { uuid: String },
}

fn safe_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '_' | '-' | '.'))
}

impl Action {
    pub fn pin(pin: &str, name: &str, pairing_id: Option<&str>) -> Result<Self, String> {
        if pin.len() != 4 || !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err("le PIN doit faire 4 chiffres".into());
        }
        if !safe_text(name, 32) {
            return Err("nom invalide (lettres, chiffres, espace, _ - . ; 32 caracteres max)".into());
        }
        if let Some(id) = pairing_id {
            if id.len() != 32 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err("pairing-id invalide (32 caracteres hexadecimaux)".into());
            }
        }
        Ok(Action::Pin { pin: pin.into(), name: name.into(), pairing_id: pairing_id.map(|s| s.to_lowercase()) })
    }

    pub fn unpair(uuid: &str) -> Result<Self, String> {
        let ok = uuid.len() == 36 && uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        if !ok {
            return Err("identifiant de client invalide (UUID attendu)".into());
        }
        Ok(Action::Unpair { uuid: uuid.to_uppercase() })
    }

    fn request(&self) -> (&'static str, &'static str, Option<String>) {
        match self {
            Action::Clients => ("GET", "/api/clients/list", None),
            Action::Pending => ("GET", "/api/pin", None),
            // Le corps du POST est construit dans le script (il y insere l'identifiant de la demande en attente).
            Action::Pin { .. } => ("POST", "/api/pin", None),
            Action::Unpair { uuid } => ("POST", "/api/unpair", Some(serde_json::json!({"uuid": uuid}).to_string())),
        }
    }
}

fn plain(s: &str) -> bool {
    !s.contains(['\'', '"', '`', '$', '\n', '\r', ';', '|', '&'])
}

/// Construit le script PowerShell. Refuse toute valeur de configuration pouvant en sortir d'une chaine.
pub fn build_script(cfg: &SunshineConfig, action: &Action) -> Result<String, String> {
    validate_reference(&cfg.user_ref).map_err(|e| e.to_string())?;
    validate_reference(&cfg.pass_ref).map_err(|e| e.to_string())?;
    let url_ok = (cfg.url.starts_with("https://127.0.0.1:") || cfg.url.starts_with("https://localhost:")) && plain(&cfg.url);
    if !url_ok {
        return Err("url Sunshine : seule l'adresse locale https://127.0.0.1:<port> est acceptee".into());
    }
    if !plain(&cfg.cert_path) || !plain(&cfg.user_ref) || !plain(&cfg.pass_ref) {
        return Err("valeur de configuration Sunshine invalide".into());
    }
    let (method, path, body) = action.request();
    let body_line = match (&body, action) {
        // Appairage : on lit d'abord la demande en attente (GET /api/pin) pour en prendre l'identifiant.
        (_, Action::Pin { pin, name, pairing_id }) => format!(
            "$id = '{id}'\nif (-not $id) {{\n  $pend = Invoke-RestMethod -Uri '{url}/api/pin' -Method GET -Headers $h\n  $list = @($pend.pairings)\n  if ($list.Count -eq 0) {{ throw 'aucune demande d''appairage en attente : afficher le PIN sur l''appareil (Moonlight), puis relancer' }}\n  if ($list.Count -gt 1) {{ throw ('plusieurs demandes en attente (' + (($list | ForEach-Object {{ $_.name + ' ' + $_.id }}) -join ', ') + ') : preciser --pairing-id') }}\n  $id = $list[0].id\n}}\n$body = (@{{ pairing_id = $id; pin = '{pin}'; name = '{name}' }} | ConvertTo-Json -Compress)\n",
            id = pairing_id.clone().unwrap_or_default(),
            url = cfg.url,
            pin = pin,
            name = name
        ),
        (Some(b), _) => format!("$body = '{b}'\n"),
        (None, _) => "$body = $null\n".into(),
    };
    Ok(format!(
        r#"[Console]::OutputEncoding = [Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$u = [Console]::In.ReadLine()
$p = [Console]::In.ReadLine()
if (-not $u -or -not $p) {{ throw 'identifiants Sunshine non recus' }}
$thumb = (New-Object Security.Cryptography.X509Certificates.X509Certificate2 '{cert}').Thumbprint
Add-Type @"
using System.Net.Security; using System.Security.Cryptography.X509Certificates;
public static class C2CPin {{
  public static string Thumb;
  public static bool Check(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) {{ return c != null && new X509Certificate2(c).Thumbprint == Thumb; }}
  public static RemoteCertificateValidationCallback Cb() {{ return Check; }}
}}
"@
[C2CPin]::Thumb = $thumb
[Net.ServicePointManager]::ServerCertificateValidationCallback = [C2CPin]::Cb()
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$h = @{{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($u + ':' + $p)) }}
{body_line}if ($body) {{ $r = Invoke-RestMethod -Uri '{url}{path}' -Method {method} -Headers $h -ContentType 'application/json' -Body $body }}
else {{ $r = Invoke-RestMethod -Uri '{url}{path}' -Method {method} -Headers $h }}
$r | ConvertTo-Json -Depth 6
"#,
        cert = cfg.cert_path,
        url = cfg.url,
        path = path,
        method = method,
        body_line = body_line,
    ))
}

type Creds = (String, String);

fn cache() -> &'static std::sync::Mutex<std::collections::HashMap<(String, String), Creds>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<(String, String), Creds>>> = std::sync::OnceLock::new();
    C.get_or_init(Default::default)
}

/// Identifiants Sunshine : cache en memoire du processus, sinon lecture 1Password (une fois, meme si plusieurs appels arrivent
/// en meme temps : le verrou est tenu pendant la lecture).
fn credentials(runner: &dyn CommandRunner, cfg: &SunshineConfig) -> Result<Creds, String> {
    let key = (cfg.user_ref.clone(), cfg.pass_ref.clone());
    let mut cache = cache().lock().unwrap();
    if let Some(c) = cache.get(&key) {
        return Ok(c.clone());
    }
    let op = OpCli { runner };
    let read = |r: &str| op.read(r).map(|s| s.expose().to_string()).map_err(|_| "identifiants Sunshine illisibles (1Password verrouille ?)".to_string());
    let (u, p) = (read(&cfg.user_ref)?, read(&cfg.pass_ref)?);
    if u.is_empty() || p.is_empty() || u.contains(['\n', '\r']) || p.contains(['\n', '\r']) {
        return Err("identifiants Sunshine invalides (vides ou sur plusieurs lignes)".into());
    }
    cache.insert(key, (u.clone(), p.clone()));
    Ok((u, p))
}

/// Oublie les identifiants en memoire (apres un echec d'authentification, ou pour forcer une relecture).
pub fn forget_credentials(cfg: &SunshineConfig) {
    cache().lock().unwrap().remove(&(cfg.user_ref.clone(), cfg.pass_ref.clone()));
}

/// Identifiants a transmettre a une requete distante (lus dans le 1Password de l'appareil qui appelle, mis en cache memoire).
pub fn read_credentials(runner: &dyn CommandRunner, cfg: &SunshineConfig) -> Result<(String, String), String> {
    credentials(runner, cfg)
}

pub fn run(runner: &dyn CommandRunner, cfg: &SunshineConfig, action: &Action) -> Result<String, String> {
    run_with(runner, cfg, action, None)
}

/// `creds` : identifiants fournis par l'appelant (agent : l'appareil les envoie, rien n'est lu dans 1Password ici).
pub fn run_with(runner: &dyn CommandRunner, cfg: &SunshineConfig, action: &Action, creds: Option<(String, String)>) -> Result<String, String> {
    let script = build_script(cfg, action)?;
    let (u, p) = match &creds {
        Some((u, p)) => {
            if u.is_empty() || p.is_empty() || u.contains(['\n', '\r']) || p.contains(['\n', '\r']) {
                return Err("identifiants Sunshine invalides (vides ou sur plusieurs lignes)".into());
            }
            (u.clone(), p.clone())
        }
        None => credentials(runner, cfg)?,
    };
    let out = runner
        .run_stdin("powershell", &["-NoProfile".into(), "-NonInteractive".into(), "-Command".into(), script], &format!("{u}\n{p}\n"))
        .map_err(|e| format!("PowerShell indisponible : {e}"))?;
    if out.status != 0 {
        // Un identifiant refuse (mot de passe change) ne doit pas rester en cache : la prochaine requete relira 1Password.
        if creds.is_none() {
            forget_credentials(cfg);
        }
        // stderr peut citer l'erreur de l'API ; il ne contient jamais les identifiants (recus sur l'entree, jamais affiches).
        return Err(format!("appel Sunshine en echec : {}", out.stderr.trim().lines().next().unwrap_or("erreur inconnue")));
    }
    Ok(out.stdout.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    #[test]
    fn pin_and_name_are_validated() {
        assert!(Action::pin("1234", "portable", None).is_ok());
        assert!(Action::pin("12a4", "portable", None).is_err());
        assert!(Action::pin("123", "portable", None).is_err());
        assert!(Action::pin("1234", "", None).is_err());
        assert!(Action::pin("1234", "x'; calc; '", None).is_err());
        assert!(Action::pin("1234", &"a".repeat(33), None).is_err());
        assert!(Action::pin("1234", "tel", Some("0123456789abcdef0123456789abcdef")).is_ok());
        assert!(Action::pin("1234", "tel", Some("zz23456789abcdef0123456789abcdef")).is_err());
        assert!(Action::pin("1234", "tel", Some("0123'; calc")).is_err());
    }

    #[test]
    fn unpair_needs_a_uuid() {
        assert!(Action::unpair("0f8fad5b-d9cb-469f-a165-70867728950e").is_ok());
        assert!(Action::unpair("x'; calc").is_err());
        assert!(Action::unpair("").is_err());
    }

    #[test]
    fn script_targets_the_right_endpoint_and_holds_no_secret() {
        let cfg = SunshineConfig::default();
        let s = build_script(&cfg, &Action::pin("1234", "portable", None).unwrap()).unwrap();
        assert!(s.contains("/api/pin") && s.contains("POST") && s.contains("pin = '1234'") && s.contains("name = 'portable'"));
        assert!(s.contains("-Method GET") && s.contains("$list.Count -eq 0") && s.contains("$id = ''"));
        let s2 = build_script(&cfg, &Action::pin("1234", "tel", Some("0123456789abcdef0123456789abcdef")).unwrap()).unwrap();
        assert!(s2.contains("$id = '0123456789abcdef0123456789abcdef'"));
        let p = build_script(&cfg, &Action::Pending).unwrap();
        assert!(p.contains("/api/pin") && p.contains("-Method GET"));
        assert!(s.contains("[Console]::In.ReadLine()") && !s.contains("op read") && !s.contains("Homelab"), "aucun identifiant ni reference dans le script");
        assert!(s.contains("Thumbprint") && !s.contains("SkipCertificateCheck") && !s.contains("return true"));
        let g = build_script(&cfg, &Action::Clients).unwrap();
        assert!(g.contains("/api/clients/list") && g.contains("GET") && g.contains("$body = $null"));
    }

    #[test]
    fn dangerous_or_remote_settings_are_refused() {
        let mut c = SunshineConfig::default();
        c.url = "https://example.com:47990".into();
        assert!(build_script(&c, &Action::Clients).is_err());
        let mut c = SunshineConfig::default();
        c.url = "https://127.0.0.1:47990'; calc; '".into();
        assert!(build_script(&c, &Action::Clients).is_err());
        let mut c = SunshineConfig::default();
        c.cert_path = "a'b".into();
        assert!(build_script(&c, &Action::Clients).is_err());
        let mut c = SunshineConfig::default();
        c.user_ref = "op://a/b/c; rm".into();
        assert!(build_script(&c, &Action::Clients).is_err());
    }

    #[test]
    fn simultaneous_calls_read_1password_only_once() {
        let cfg = cfg_for("concurrent");
        let r = std::sync::Arc::new(RecordingRunner::ok("{\"status\":true}"));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let (r, cfg) = (r.clone(), cfg.clone());
                std::thread::spawn(move || run(&*r, &cfg, &Action::Clients).unwrap())
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(r.calls().iter().filter(|(p, _)| p == "op").count(), 2, "une seule lecture (identifiant + mot de passe) pour 8 appels simultanes");
    }

    #[test]
    fn caller_supplied_credentials_never_touch_1password() {
        let cfg = cfg_for("fournis");
        let r = RecordingRunner::ok("{\"status\":true}");
        assert!(run_with(&r, &cfg, &Action::Clients, Some(("admin".into(), "mdp".into()))).is_ok());
        assert!(r.calls().iter().all(|(p, _)| p != "op"), "aucun appel 1Password");
        assert_eq!(r.stdins.lock().unwrap().last().unwrap(), "admin\nmdp\n");
        assert!(!r.calls().last().unwrap().1.join(" ").contains("mdp"));
        assert!(run_with(&r, &cfg, &Action::Clients, Some(("a\nb".into(), "x".into()))).is_err());
        assert!(run_with(&r, &cfg, &Action::Clients, Some(("".into(), "x".into()))).is_err());
    }

    fn cfg_for(tag: &str) -> SunshineConfig {
        SunshineConfig { user_ref: format!("op://T/{tag}/user"), pass_ref: format!("op://T/{tag}/pass"), ..SunshineConfig::default() }
    }

    #[test]
    fn credentials_go_through_stdin_and_are_read_from_1password_only_once() {
        let cfg = cfg_for("once");
        let ok = RecordingRunner::ok("{\"named_certs\":[]}");
        assert_eq!(run(&ok, &cfg, &Action::Clients).unwrap(), "{\"named_certs\":[]}");
        let calls = ok.calls();
        assert_eq!(calls.iter().filter(|(p, _)| p == "op").count(), 2, "identifiant + mot de passe, une fois");
        let (prog, args) = calls.last().unwrap();
        assert_eq!(prog, "powershell");
        // Le secret n'est NI dans la ligne de commande NI dans le script : seulement sur l'entree standard.
        assert!(!args.join(" ").contains("{\"named_certs\":[]}"));
        assert_eq!(ok.stdins.lock().unwrap().last().unwrap(), "{\"named_certs\":[]}\n{\"named_certs\":[]}\n");
        // Deuxieme appel : plus aucun `op`.
        run(&ok, &cfg, &Action::Pending).unwrap();
        assert_eq!(ok.calls().iter().filter(|(p, _)| p == "op").count(), 2);
    }

    #[test]
    fn a_forgotten_credential_is_reread_and_bad_ones_are_reported() {
        let cfg = cfg_for("forget");
        let ok = RecordingRunner::ok("secret");
        run(&ok, &cfg, &Action::Clients).unwrap();
        forget_credentials(&cfg);
        run(&ok, &cfg, &Action::Clients).unwrap();
        assert_eq!(ok.calls().iter().filter(|(p, _)| p == "op").count(), 4, "relu apres oubli");
        let ko = RecordingRunner::failing(1);
        assert!(run(&ko, &cfg_for("illisible"), &Action::Clients).unwrap_err().contains("illisibles"));
        // Identifiant sur plusieurs lignes : refuse (injection de lignes dans l'entree standard).
        let multi = RecordingRunner::ok("a\nb");
        assert!(run(&multi, &cfg_for("multi"), &Action::Clients).unwrap_err().contains("invalides"));
    }
}
