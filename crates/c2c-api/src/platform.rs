//! Acces au systeme partages par toutes les commandes : fichiers d'etat a cote du journal, detection de session,
//! backend d'affichage (Windows uniquement). Ex-fonctions de `main.rs`, deplacees ici pour que CLI, agent et UI les partagent.
use c2c_core::config::Config;
use c2c_core::display::{self, DisplayConfig, Layout, Screen};
use c2c_core::runner::SystemRunner;
use std::path::{Path, PathBuf};

/// Fichier du choix de disposition, a cote du journal d'audit. Absent ou "auto" : Watch suit la session.
pub fn mode_path(audit: &Path) -> PathBuf {
    audit.with_file_name("c2c-display-mode.txt")
}

pub fn read_pin(path: &Path) -> Option<Layout> {
    match std::fs::read_to_string(path).ok()?.trim() {
        "local" => Some(Layout::Local),
        "remote" => Some(Layout::Remote),
        _ => None,
    }
}

pub fn profile_path(audit: &Path) -> PathBuf {
    audit.with_file_name("c2c-display-profile.txt")
}

pub fn read_profile(audit: &Path) -> Option<String> {
    let t = std::fs::read_to_string(profile_path(audit)).ok()?;
    let t = t.trim();
    (!t.is_empty()).then(|| t.to_string())
}

pub fn load(path: &Path) -> Result<Config, String> {
    let t = std::fs::read_to_string(path).map_err(|e| format!("lecture de {} : {e}", path.display()))?;
    Config::parse(&t).map_err(|e| e.to_string())
}

pub fn display_cfg(config: &Path, audit: &Path) -> DisplayConfig {
    let sel = read_profile(audit);
    std::fs::read_to_string(config).ok().and_then(|t| Config::parse(&t).ok()).map(|c| c.display.to_config(sel.as_deref())).unwrap_or_default()
}

pub fn stream_cfg(path: &Path) -> c2c_core::stream::StreamConfig {
    std::fs::read_to_string(path).ok().and_then(|t| Config::parse(&t).ok()).map(|c| c.stream).unwrap_or_default()
}

pub fn detect_session(cfg: &c2c_core::stream::StreamConfig) -> Option<bool> {
    use c2c_core::stream::StreamKind;
    match cfg.kind {
        StreamKind::Parsec => {
            let log = std::fs::read(r"C:\ProgramData\Parsec\log.txt").map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
            c2c_core::session::parsec_session_active(&SystemRunner, &log)
        }
        StreamKind::Sunshine | StreamKind::Apollo => {
            let text = cfg.log_path.as_ref().and_then(|p| std::fs::read(p).ok()).map(|b| String::from_utf8_lossy(&b).into_owned());
            c2c_core::stream::sunshine_session_active(cfg, text.as_deref(), &SystemRunner)
        }
    }
}

#[cfg(windows)]
pub fn real_inspect() -> Result<Vec<Screen>, String> {
    c2c_windows::inspect_screens().map_err(|e| e.to_string())
}
#[cfg(not(windows))]
pub fn real_inspect() -> Result<Vec<Screen>, String> {
    Err("backend d'affichage disponible sous Windows uniquement".into())
}

#[cfg(windows)]
pub fn real_apply(l: Layout, c: &DisplayConfig, o: &display::ApplyOptions) -> Result<display::Outcome, display::DisplayError> {
    let mut b = c2c_windows::WindowsBackend::new(vec![c.remote_id.clone()]);
    display::apply(&mut b, l, c, o)
}
#[cfg(not(windows))]
pub fn real_apply(_: Layout, _: &DisplayConfig, _: &display::ApplyOptions) -> Result<display::Outcome, display::DisplayError> {
    Err(display::DisplayError::Backend("Windows uniquement".into()))
}

/// Detail d'un echec d'application : l'erreur, puis les ecarts restants entre l'etat reel et la disposition voulue.
pub fn failure_detail(err: Option<&display::DisplayError>, layout: Layout, cfg: &DisplayConfig) -> String {
    let Some(e) = err else { return String::new() };
    let mut s = format!("{e:?}");
    if let Ok(screens) = real_inspect() {
        let p = display::check(layout, &screens, cfg);
        if !p.is_empty() {
            s.push_str(&format!(" ; restant : {p:?}"));
        }
    }
    s
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
