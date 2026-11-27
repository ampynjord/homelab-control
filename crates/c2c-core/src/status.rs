//! Etat des machines : sonde TCP injectable.
use crate::config::MachineConfig;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Online,
    Offline,
    /// Pas de port de sonde configure.
    Unknown,
}

pub trait Prober {
    fn tcp_open(&self, host: &str, port: u16) -> bool;
}

pub struct TcpProber {
    pub timeout: Duration,
}

impl Prober for TcpProber {
    fn tcp_open(&self, host: &str, port: u16) -> bool {
        match (host, port).to_socket_addrs() {
            Ok(mut addrs) => addrs.any(|a| TcpStream::connect_timeout(&a, self.timeout).is_ok()),
            Err(_) => false,
        }
    }
}

pub fn probe(machine: &MachineConfig, prober: &dyn Prober) -> State {
    match machine.probe_port {
        None => State::Unknown,
        Some(p) if prober.tcp_open(&machine.address, p) => State::Online,
        Some(_) => State::Offline,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixed(bool);
    impl Prober for Fixed {
        fn tcp_open(&self, _: &str, _: u16) -> bool {
            self.0
        }
    }

    fn m(port: Option<u16>) -> MachineConfig {
        MachineConfig { name: "x".into(), address: "x".into(), mac: None, probe_port: port, agent_addr: None, key_ref: None, agent_pubkey: None }
    }

    #[test]
    fn states() {
        assert_eq!(probe(&m(Some(1)), &Fixed(true)), State::Online);
        assert_eq!(probe(&m(Some(1)), &Fixed(false)), State::Offline);
        assert_eq!(probe(&m(None), &Fixed(true)), State::Unknown);
    }

    #[test]
    fn tcp_prober_detects_listener_and_closed_port() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let p = TcpProber { timeout: Duration::from_millis(500) };
        assert!(p.tcp_open("127.0.0.1", port));
        drop(l);
        assert!(!p.tcp_open("127.0.0.1", port));
    }
}
