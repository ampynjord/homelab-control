//! Sonde de sante reseau sortante. Cas vise (RETEX 2026-11-24) : la connexion TCP aboutit mais les donnees
//! ne reviennent pas (NAT64/PMTU degrade). On envoie une requete HTTP minimale et on exige un octet de reponse.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathState {
    /// Reponse recue.
    Ok { ms: u128 },
    /// TCP etabli mais aucune donnee en retour : chemin degrade.
    Degraded,
    /// Connexion impossible.
    Unreachable,
}

pub fn probe_http(addr: SocketAddr, host: &str, timeout: Duration) -> PathState {
    let start = Instant::now();
    let Ok(mut s) = TcpStream::connect_timeout(&addr, timeout) else { return PathState::Unreachable };
    s.set_read_timeout(Some(timeout)).ok();
    s.set_write_timeout(Some(timeout)).ok();
    let req = format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return PathState::Degraded;
    }
    let mut b = [0u8; 16];
    match s.read(&mut b) {
        Ok(n) if n > 0 => PathState::Ok { ms: start.elapsed().as_millis() },
        _ => PathState::Degraded,
    }
}

/// Verdict global a partir des chemins IPv4 et IPv6 : le chemin IPv4 seul degrade est le motif du RETEX.
pub fn verdict(v4: &PathState, v6: &PathState) -> &'static str {
    match (v4, v6) {
        (PathState::Ok { .. }, PathState::Ok { .. }) => "ok",
        (PathState::Ok { .. }, _) => "ipv6-degrade",
        (_, PathState::Ok { .. }) => "ipv4-degrade",
        _ => "hors-ligne-ou-tout-degrade",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn answering_server_is_ok() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut buf = [0u8; 64];
            let _ = s.read(&mut buf);
            s.write_all(b"HTTP/1.1 301 Moved\r\n\r\n").unwrap();
        });
        assert!(matches!(probe_http(a, "x", Duration::from_secs(2)), PathState::Ok { .. }));
        t.join().unwrap();
    }

    #[test]
    fn silent_server_is_degraded_not_unreachable() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        let t = std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            std::thread::sleep(Duration::from_millis(700));
            drop(s);
        });
        assert_eq!(probe_http(a, "x", Duration::from_millis(300)), PathState::Degraded);
        t.join().unwrap();
    }

    #[test]
    fn closed_port_is_unreachable() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        drop(l);
        assert_eq!(probe_http(a, "x", Duration::from_millis(300)), PathState::Unreachable);
    }

    #[test]
    fn verdicts() {
        let ok = PathState::Ok { ms: 1 };
        assert_eq!(verdict(&ok, &ok), "ok");
        assert_eq!(verdict(&PathState::Degraded, &ok), "ipv4-degrade");
        assert_eq!(verdict(&ok, &PathState::Unreachable), "ipv6-degrade");
        assert_eq!(verdict(&PathState::Degraded, &PathState::Unreachable), "hors-ligne-ou-tout-degrade");
    }
}
