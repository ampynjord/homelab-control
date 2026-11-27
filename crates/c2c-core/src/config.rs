//! Configuration de la flotte (fichier TOML, sans aucun secret).
use crate::wake::{Mac, MacError};
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Deserialize, Clone)]
pub struct WakeConfig {
    pub pi_user: String,
    pub pi_host: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MachineConfig {
    pub name: String,
    pub address: String,
    pub mac: Option<String>,
    /// Port TCP sonde pour savoir si la machine est allumee (ex. 3389).
    pub probe_port: Option<u16>,
    /// Adresse de l'agent (tailnet), ex. "pc-fixe.example.ts.net:7443".
    pub agent_addr: Option<String>,
    /// Reference 1Password de la cle PRIVEE de CET appareil (cote client) : lue seulement quand on se connecte.
    pub key_ref: Option<String>,
    /// Cle publique de l'agent de cette machine (epinglee : reconnait le vrai agent).
    pub agent_pubkey: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AgentClient {
    pub name: String,
    /// Cle PUBLIQUE de l'appareil (64 caracteres hexadecimaux). Pas un secret : l'agent n'a rien a lire dans 1Password.
    pub pubkey: String,
    /// Droits : noms de droits ou groupes `@read`, `@common`, `@all`.
    pub allowed: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct AgentConfig {
    /// Adresse d'ecoute (IP Tailscale de cette machine uniquement).
    pub bind: Option<String>,
    /// Proprietaire Tailscale attendu des pairs (verifie par `tailscale whois`). Si absent : filtre par plage seulement.
    pub owner: Option<String>,
    /// Fichier de la cle d'identite de l'agent (defaut : `c2c-agent-hostkey` a cote de la configuration).
    pub host_key: Option<String>,
    #[serde(rename = "client", default)]
    pub clients: Vec<AgentClient>,
}

impl MachineConfig {
    pub fn mac(&self) -> Result<Option<Mac>, MacError> {
        self.mac.as_deref().map(str::parse).transpose()
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub wake: WakeConfig,
    /// Nom de ce client aupres des agents.
    pub client_name: Option<String>,
    #[serde(default)]
    pub agent: AgentConfig,
    #[serde(default)]
    pub stream: crate::stream::StreamConfig,
    #[serde(default)]
    pub display: DisplaySection,
    #[serde(default)]
    pub sunshine: crate::sunshine_api::SunshineConfig,
    #[serde(rename = "machine", default)]
    pub machines: Vec<MachineConfig>,
}

/// Section [display] : mode de l'ecran virtuel en disposition Remote (par defaut : celui de DisplayConfig).
#[derive(Debug, Deserialize, Clone, Default)]
pub struct DisplaySection {
    pub remote_mode: Option<crate::display::Mode>,
    /// Profils nommes de l'ecran virtuel : [display.profiles.portable] w/h/hz.
    #[serde(default)]
    pub profiles: std::collections::BTreeMap<String, crate::display::Mode>,
}

impl DisplaySection {
    /// Mode retenu : le profil choisi s'il existe, sinon `remote_mode`, sinon le defaut.
    pub fn to_config(&self, selected: Option<&str>) -> crate::display::DisplayConfig {
        let mut c = crate::display::DisplayConfig::default();
        if let Some(m) = selected.and_then(|n| self.profiles.get(n)).copied().or(self.remote_mode) {
            c.remote_mode = m;
        }
        c
    }
}

/// Proportions lisibles d'un mode : 2560x1600 -> "16:10", 1920x1080 -> "16:9".
pub fn aspect_ratio(w: u32, h: u32) -> String {
    fn gcd(a: u32, b: u32) -> u32 {
        if b == 0 { a } else { gcd(b, a % b) }
    }
    if w == 0 || h == 0 {
        return "?".into();
    }
    let g = gcd(w, h);
    let (a, b) = (w / g, h / g);
    match (a, b) {
        (8, 5) => "16:10".into(),
        _ => format!("{a}:{b}"),
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration illisible : {0}")]
    Parse(String),
    #[error("machine inconnue : {0}")]
    UnknownMachine(String),
    #[error("MAC invalide pour {0}")]
    BadMac(String),
    #[error("nom de machine en double : {0}")]
    Duplicate(String),
}

impl Config {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let c: Config = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
        let mut seen = std::collections::HashSet::new();
        for m in &c.machines {
            if !seen.insert(m.name.clone()) {
                return Err(ConfigError::Duplicate(m.name.clone()));
            }
            m.mac().map_err(|_| ConfigError::BadMac(m.name.clone()))?;
            if let Some(k) = &m.agent_pubkey {
                crate::proto::parse_pubkey(k).map_err(|e| ConfigError::Parse(format!("agent_pubkey de {} : {e}", m.name)))?;
            }
        }
        for cl in &c.agent.clients {
            crate::proto::parse_pubkey(&cl.pubkey).map_err(|e| ConfigError::Parse(format!("pubkey du client {} : {e}", cl.name)))?;
        }
        Ok(c)
    }

    pub fn machine(&self, name: &str) -> Result<&MachineConfig, ConfigError> {
        self.machines.iter().find(|m| m.name == name).ok_or_else(|| ConfigError::UnknownMachine(name.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[wake]
pi_user = "pi"
pi_host = "pi"

[[machine]]
name = "pc-fixe"
address = "pc-fixe.example.ts.net"
mac = "02:00:5E:00:00:01"
probe_port = 3389

[[machine]]
name = "portable"
address = "portable.example.ts.net"
"#;

    #[test]
    fn parses_sample() {
        let c = Config::parse(SAMPLE).unwrap();
        assert_eq!(c.machines.len(), 2);
        assert!(c.machine("pc-fixe").unwrap().mac().unwrap().is_some());
        assert!(c.machine("portable").unwrap().mac().unwrap().is_none());
    }

    #[test]
    fn unknown_machine() {
        let c = Config::parse(SAMPLE).unwrap();
        assert!(matches!(c.machine("nope"), Err(ConfigError::UnknownMachine(_))));
    }

    #[test]
    fn rejects_bad_mac_and_duplicates() {
        let bad = SAMPLE.replace("02:00:5E:00:00:01", "xx");
        assert!(matches!(Config::parse(&bad), Err(ConfigError::BadMac(_))));
        let dup = format!("{SAMPLE}\n[[machine]]\nname = \"pc-fixe\"\naddress = \"x\"\n");
        assert!(matches!(Config::parse(&dup), Err(ConfigError::Duplicate(_))));
    }
}

#[cfg(test)]
mod display_section_tests {
    use super::*;

    #[test]
    fn remote_mode_is_configurable() {
        let c = Config::parse("[wake]\npi_user=\"u\"\npi_host=\"h\"\n[display]\nremote_mode = { w = 2560, h = 1600, hz = 60 }\n").unwrap();
        assert_eq!(c.display.to_config(None).remote_mode, crate::display::Mode { w: 2560, h: 1600, hz: 60 });
    }

    #[test]
    fn remote_mode_defaults_when_absent() {
        let c = Config::parse("[wake]\npi_user=\"u\"\npi_host=\"h\"\n").unwrap();
        assert_eq!(c.display.to_config(None).remote_mode, crate::display::DisplayConfig::default().remote_mode);
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    const T: &str = "[wake]\npi_user=\"u\"\npi_host=\"h\"\n[display]\nremote_mode = { w = 1920, h = 1080, hz = 60 }\n[display.profiles.portable]\nw = 2560\nh = 1600\nhz = 60\n[display.profiles.fluide]\nw = 1920\nh = 1200\nhz = 120\n";

    #[test]
    fn selected_profile_wins_then_remote_mode() {
        let c = Config::parse(T).unwrap();
        assert_eq!(c.display.to_config(Some("portable")).remote_mode.w, 2560);
        assert_eq!(c.display.to_config(Some("fluide")).remote_mode.hz, 120);
        assert_eq!(c.display.to_config(Some("inconnu")).remote_mode.w, 1920);
        assert_eq!(c.display.to_config(None).remote_mode.h, 1080);
    }

    #[test]
    fn ratios() {
        assert_eq!(aspect_ratio(2560, 1600), "16:10");
        assert_eq!(aspect_ratio(1920, 1200), "16:10");
        assert_eq!(aspect_ratio(1920, 1080), "16:9");
        assert_eq!(aspect_ratio(2560, 1080), "64:27");
    }
}
