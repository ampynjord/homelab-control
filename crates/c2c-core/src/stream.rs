//! Hote de streaming (Parsec aujourd'hui, Sunshine/Apollo demain) : detection de session par le journal.
//! NON VERIFIE sur une vraie installation : les marqueurs de journal de Sunshine/Apollo sont des valeurs par
//! defaut a confirmer au premier essai (ils sont configurables).
use crate::runner::CommandRunner;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum StreamKind {
    #[default]
    Parsec,
    Sunshine,
    Apollo,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StreamConfig {
    #[serde(default)]
    pub kind: StreamKind,
    /// Journal de l'hote (Sunshine/Apollo).
    pub log_path: Option<String>,
    /// Nom du processus (sans .exe) qui doit tourner, sinon la session est consideree terminee.
    pub process: Option<String>,
    #[serde(default = "default_connect")]
    pub connect_marker: String,
    #[serde(default = "default_disconnect")]
    pub disconnect_marker: String,
}

fn default_connect() -> String {
    "CLIENT CONNECTED".into()
}
fn default_disconnect() -> String {
    "CLIENT DISCONNECTED".into()
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self { kind: StreamKind::Parsec, log_path: None, process: None, connect_marker: default_connect(), disconnect_marker: default_disconnect() }
    }
}

/// Le dernier marqueur rencontre l'emporte. Sans marqueur : pas de session.
pub fn session_from_log(text: &str, connect: &str, disconnect: &str) -> bool {
    let mut active = false;
    for line in text.lines() {
        if line.contains(disconnect) {
            active = false;
        } else if line.contains(connect) {
            active = true;
        }
    }
    active
}

pub fn process_running(runner: &dyn CommandRunner, name: &str) -> Option<bool> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return None;
    }
    let image = format!("IMAGENAME eq {name}.exe");
    let out = runner.run("tasklist", &["/FI".into(), image, "/NH".into()]).ok().filter(|o| o.status == 0)?;
    Some(out.stdout.to_lowercase().contains(&format!("{}.exe", name.to_lowercase())))
}

/// Session Sunshine/Apollo : journal + processus vivant. `None` = indetermine (l'appelant suppose active).
pub fn sunshine_session_active(cfg: &StreamConfig, log_text: Option<&str>, runner: &dyn CommandRunner) -> Option<bool> {
    let text = log_text?;
    if let Some(p) = &cfg.process {
        if !process_running(runner, p)? {
            return Some(false);
        }
    }
    Some(session_from_log(text, &cfg.connect_marker, &cfg.disconnect_marker))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    #[test]
    fn last_marker_wins() {
        let c = "CLIENT CONNECTED";
        let d = "CLIENT DISCONNECTED";
        assert!(!session_from_log("", c, d));
        assert!(session_from_log("x\n[..]: Info: CLIENT CONNECTED\n", c, d));
        assert!(!session_from_log("CLIENT CONNECTED\nCLIENT DISCONNECTED\n", c, d));
        assert!(session_from_log("CLIENT CONNECTED\nCLIENT DISCONNECTED\nCLIENT CONNECTED\n", c, d));
    }

    #[test]
    fn dead_process_ends_session_even_if_log_says_connected() {
        let cfg = StreamConfig { process: Some("sunshine".into()), ..Default::default() };
        let gone = RecordingRunner::ok("INFO: aucune tache en cours\n");
        assert_eq!(sunshine_session_active(&cfg, Some("CLIENT CONNECTED\n"), &gone), Some(false));
        let up = RecordingRunner::ok("sunshine.exe     1234 Console\n");
        assert_eq!(sunshine_session_active(&cfg, Some("CLIENT CONNECTED\n"), &up), Some(true));
    }

    #[test]
    fn unreadable_log_is_unknown() {
        assert_eq!(sunshine_session_active(&StreamConfig::default(), None, &RecordingRunner::ok("")), None);
    }

    #[test]
    fn process_name_is_validated() {
        let r = RecordingRunner::ok("");
        assert_eq!(process_running(&r, "a b; calc"), None);
        assert!(r.calls().is_empty());
    }

    #[test]
    fn config_defaults() {
        let c: StreamConfig = toml::from_str("kind = \"apollo\"").unwrap();
        assert_eq!(c.kind, StreamKind::Apollo);
        assert_eq!(c.connect_marker, "CLIENT CONNECTED");
    }
}
