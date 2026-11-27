//! Reveil Wake-on-LAN : paquet magique + transports (Pi par SSH, ou diffusion UDP locale).
use crate::runner::CommandRunner;
use std::fmt;
use std::net::UdpSocket;
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mac(pub [u8; 6]);

#[derive(Debug, Error, PartialEq, Eq)]
#[error("adresse MAC invalide")]
pub struct MacError;

impl FromStr for Mac {
    type Err = MacError;
    fn from_str(s: &str) -> Result<Self, MacError> {
        let sep = if s.contains(':') {
            ':'
        } else if s.contains('-') {
            '-'
        } else {
            return Err(MacError);
        };
        let parts: Vec<&str> = s.split(sep).collect();
        if parts.len() != 6 {
            return Err(MacError);
        }
        let mut b = [0u8; 6];
        for (i, p) in parts.iter().enumerate() {
            if p.len() != 2 || !p.chars().all(|c| c.is_ascii_hexdigit()) {
                return Err(MacError);
            }
            b[i] = u8::from_str_radix(p, 16).map_err(|_| MacError)?;
        }
        Ok(Mac(b))
    }
}

impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", b[0], b[1], b[2], b[3], b[4], b[5])
    }
}

/// 6 octets 0xFF puis 16 fois l'adresse MAC = 102 octets.
pub fn magic_packet(mac: &Mac) -> [u8; 102] {
    let mut p = [0xFFu8; 102];
    for i in 0..16 {
        p[6 + i * 6..12 + i * 6].copy_from_slice(&mac.0);
    }
    p
}

#[derive(Debug, Error)]
pub enum WakeError {
    #[error("transport de reveil en echec : {0}")]
    Transport(String),
}

pub trait WakeTransport {
    fn send(&self, mac: &Mac) -> Result<(), WakeError>;
    fn describe(&self) -> String;
}

/// Envoi via le Raspberry Pi : `ssh user@host wakeonlan <MAC>` (SSH Tailscale, sans mot de passe).
/// Le MAC est valide par le type `Mac`, donc aucune injection possible.
pub struct SshPiTransport<'a> {
    pub runner: &'a dyn CommandRunner,
    pub user: String,
    pub host: String,
}

impl SshPiTransport<'_> {
    pub fn command(&self, mac: &Mac) -> (String, Vec<String>) {
        (
            "ssh".into(),
            vec![
                "-o".into(),
                "BatchMode=yes".into(),
                "-o".into(),
                "ConnectTimeout=8".into(),
                format!("{}@{}", self.user, self.host),
                "wakeonlan".into(),
                mac.to_string(),
            ],
        )
    }
}

impl WakeTransport for SshPiTransport<'_> {
    fn send(&self, mac: &Mac) -> Result<(), WakeError> {
        let (prog, args) = self.command(mac);
        let out = self.runner.run(&prog, &args).map_err(|e| WakeError::Transport(e.to_string()))?;
        if out.status == 0 {
            Ok(())
        } else {
            Err(WakeError::Transport(format!("ssh a retourne {}", out.status)))
        }
    }
    fn describe(&self) -> String {
        format!("ssh {}@{} wakeonlan", self.user, self.host)
    }
}

/// Diffusion UDP directe (a utiliser depuis une machine du meme LAN, ex. le Pi).
pub struct UdpBroadcastTransport {
    pub broadcast: String,
}

impl WakeTransport for UdpBroadcastTransport {
    fn send(&self, mac: &Mac) -> Result<(), WakeError> {
        let s = UdpSocket::bind("0.0.0.0:0").map_err(|e| WakeError::Transport(e.to_string()))?;
        s.set_broadcast(true).map_err(|e| WakeError::Transport(e.to_string()))?;
        s.send_to(&magic_packet(mac), (self.broadcast.as_str(), 9))
            .map_err(|e| WakeError::Transport(e.to_string()))?;
        Ok(())
    }
    fn describe(&self) -> String {
        format!("UDP broadcast {}:9", self.broadcast)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    #[test]
    fn parse_mac_variants() {
        let m: Mac = "02:00:5E:00:00:01".parse().unwrap();
        assert_eq!(m.to_string(), "02:00:5E:00:00:01");
        assert_eq!("02-00-5e-00-00-01".parse::<Mac>().unwrap(), m);
    }

    #[test]
    fn reject_bad_mac() {
        for bad in ["", "02:00:5E:00:00", "02:00:5E:00:00:01:05", "ZZ:00:5E:00:00:01", "02005E000001", "02:00:5E:00:00:0;"] {
            assert!(bad.parse::<Mac>().is_err(), "{bad}");
        }
    }

    #[test]
    fn magic_packet_layout() {
        let m: Mac = "02:00:5E:00:00:01".parse().unwrap();
        let p = magic_packet(&m);
        assert_eq!(p.len(), 102);
        assert!(p[..6].iter().all(|&b| b == 0xFF));
        for i in 0..16 {
            assert_eq!(&p[6 + i * 6..12 + i * 6], &m.0);
        }
    }

    #[test]
    fn ssh_command_is_argv_with_validated_mac() {
        let r = RecordingRunner::ok("");
        let t = SshPiTransport { runner: &r, user: "pi".into(), host: "pi".into() };
        let m: Mac = "02:00:5E:00:00:01".parse().unwrap();
        t.send(&m).unwrap();
        let calls = r.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "ssh");
        assert_eq!(calls[0].1.last().unwrap(), "02:00:5E:00:00:01");
        assert!(calls[0].1.contains(&"pi@pi".to_string()));
    }

    #[test]
    fn ssh_failure_is_reported() {
        let r = RecordingRunner::failing(255);
        let t = SshPiTransport { runner: &r, user: "u".into(), host: "h".into() };
        assert!(t.send(&"02:00:5E:00:00:01".parse().unwrap()).is_err());
    }
}
