//! Serveur et client de l'agent : une requete JSON par connexion TCP (une ligne), sur le tailnet uniquement.
//! Liaison refusee hors loopback / 100.64.0.0/10 ; pairs hors de ces plages refuses ; tailles et delais bornes.
use crate::audit::AuditLog;
use crate::proto::{sign_request, verify_response, AuthError, Authenticator, Request, Response};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};
use std::time::Duration;

pub const MAX_LINE: u64 = 8 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Loopback ou plage CGNAT de Tailscale (100.64.0.0/10).
pub fn is_tailnet_or_loopback(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_loopback() || (v.octets()[0] == 100 && (64..=127).contains(&v.octets()[1])),
        IpAddr::V6(v) => v.is_loopback(),
    }
}

/// Verification supplementaire du pair (identite Tailscale), en plus de la plage d'adresses.
pub trait PeerCheck {
    fn allowed(&self, ip: &IpAddr) -> bool;
}

/// Accepte tout pair deja filtre par plage (usage tests).
pub struct AnyPeer;
impl PeerCheck for AnyPeer {
    fn allowed(&self, _: &IpAddr) -> bool {
        true
    }
}

/// Interroge `tailscale whois` : le pair doit appartenir au proprietaire attendu. Loopback toujours accepte.
pub struct TailscaleOwner {
    pub owner: String,
}

pub fn whois_owner_matches(output: &str, owner: &str) -> bool {
    let mut in_user = false;
    for l in output.lines() {
        if l.starts_with("User:") {
            in_user = true;
        } else if in_user {
            if let Some(n) = l.trim().strip_prefix("Name:") {
                return n.trim() == owner;
            }
        }
    }
    false
}

impl PeerCheck for TailscaleOwner {
    fn allowed(&self, ip: &IpAddr) -> bool {
        if ip.is_loopback() {
            return true;
        }
        let mut c = std::process::Command::new("tailscale");
        c.args(["whois", &ip.to_string()]);
        match crate::runner::quiet(&mut c).output() {
            Ok(o) if o.status.success() => whois_owner_matches(&String::from_utf8_lossy(&o.stdout), &self.owner),
            _ => false,
        }
    }
}

pub trait Handler {
    fn handle(&self, action: &str, args: &Value) -> Result<Value, String>;
    /// Droit exige pour cette requete (par defaut : le nom de l'action). Permet des droits dependant des arguments
    /// (ex. forcer l'affichage). Calcule avant la verification de signature, ne decide de rien par lui-meme.
    fn required_right(&self, action: &str, _args: &Value) -> String {
        action.to_string()
    }
}

pub fn bind(addr: &str) -> Result<TcpListener, String> {
    let l = TcpListener::bind(addr).map_err(|e| format!("liaison impossible : {e}"))?;
    let local = l.local_addr().map_err(|e| e.to_string())?;
    if !is_tailnet_or_loopback(&local.ip()) {
        return Err(format!("refus : {} n'est ni le tailnet ni le loopback", local.ip()));
    }
    Ok(l)
}

fn read_request(s: &mut TcpStream) -> Result<Request, String> {
    s.set_read_timeout(Some(IO_TIMEOUT)).ok();
    s.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut line = String::new();
    BufReader::new(s.take(MAX_LINE)).read_line(&mut line).map_err(|e| e.to_string())?;
    if !line.ends_with('\n') {
        return Err("requete trop longue ou incomplete".into());
    }
    serde_json::from_str(&line).map_err(|_| "JSON invalide".to_string())
}

fn send(s: &mut TcpStream, r: &Response) {
    if let Ok(mut t) = serde_json::to_string(r) {
        t.push('\n');
        let _ = s.write_all(t.as_bytes());
    }
}

/// Traite UNE connexion. Les refus renvoient un message generique non signe (rien ne fuit) et sont audites.
pub fn serve_one(l: &TcpListener, auth: &Authenticator, h: &dyn Handler, peers: &dyn PeerCheck, audit: &AuditLog, now: impl Fn() -> i64) {
    let Ok((mut s, peer)) = l.accept() else { return };
    if !is_tailnet_or_loopback(&peer.ip()) {
        let _ = audit.append("agent", "refus", &peer.ip().to_string(), "pair-hors-tailnet", "");
        return;
    }
    if !peers.allowed(&peer.ip()) {
        let _ = audit.append("agent", "refus", &peer.ip().to_string(), "pair-non-verifie", "");
        return;
    }
    let refuse = |s: &mut TcpStream| send(s, &Response { ok: false, data: json!({"error": "refuse"}), sig: String::new() });
    let req = match read_request(&mut s) {
        Ok(r) => r,
        Err(e) => {
            let _ = audit.append("agent", "refus", &peer.ip().to_string(), "requete-invalide", &e);
            return refuse(&mut s);
        }
    };
    let needed = h.required_right(&req.action, &req.args);
    match auth.verify_request_for(&req, now(), &needed) {
        Ok(()) => {}
        Err(e) => {
            let why = match e {
                AuthError::UnknownClient => "client-inconnu",
                AuthError::BadSignature => "signature",
                AuthError::Stale => "horodatage",
                AuthError::Replay => "rejeu",
                AuthError::Forbidden => "action-interdite",
            };
            let _ = audit.append(&req.client, &req.action, &peer.ip().to_string(), "refuse", &format!("{why} ({needed})"));
            return refuse(&mut s);
        }
    }
    let (ok, data) = match h.handle(&req.action, &req.args) {
        Ok(d) => (true, d),
        Err(e) => (false, json!({"error": e})),
    };
    let _ = audit.append(&req.client, &req.action, &peer.ip().to_string(), if ok { "ok" } else { "echec" }, "");
    send(&mut s, &auth.sign_response(&req.nonce, ok, data));
}

#[derive(Debug)]
pub enum CallError {
    Io(String),
    Refused,
    /// Reponse non signee correctement : serveur usurpe ou rejeu.
    BadServerSignature,
}

pub fn call(addr: &str, key: &SigningKey, agent_pub: &VerifyingKey, client: &str, now: i64, action: &str, args: Value) -> Result<Response, CallError> {
    let req = sign_request(key, client, now, action, args);
    let mut s = TcpStream::connect(addr).map_err(|e| CallError::Io(e.to_string()))?;
    s.set_read_timeout(Some(IO_TIMEOUT)).ok();
    s.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut t = serde_json::to_string(&req).map_err(|e| CallError::Io(e.to_string()))?;
    t.push('\n');
    s.write_all(t.as_bytes()).map_err(|e| CallError::Io(e.to_string()))?;
    let mut line = String::new();
    BufReader::new(s.take(MAX_LINE * 8)).read_line(&mut line).map_err(|e| CallError::Io(e.to_string()))?;
    let resp: Response = serde_json::from_str(&line).map_err(|_| CallError::Io("reponse invalide".into()))?;
    if resp.sig.is_empty() {
        return Err(CallError::Refused);
    }
    if !verify_response(agent_pub, &req, &resp) {
        return Err(CallError::BadServerSignature);
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ClientPolicy;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn ck() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }
    fn hk() -> SigningKey {
        SigningKey::from_bytes(&[6u8; 32])
    }

    struct Echo;
    impl Handler for Echo {
        fn handle(&self, action: &str, args: &Value) -> Result<Value, String> {
            match action {
                "ping" => Ok(json!({"pong": true})),
                "echo" => Ok(args.clone()),
                _ => Err("action inconnue".into()),
            }
        }
    }

    fn auth() -> Authenticator {
        let mut m = HashMap::new();
        m.insert("portable".to_string(), ClientPolicy { pubkey: ck().verifying_key(), allowed: ["ping", "echo"].iter().map(|s| s.to_string()).collect() });
        Authenticator::new(hk(), m).unwrap()
    }

    /// Lance un serveur loopback qui traite `n` connexions ; retourne (adresse, journal, thread).
    fn start(n: usize) -> (String, Arc<AuditLog>, tempfile::TempDir, std::thread::JoinHandle<()>) {
        let l = bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let dir = tempfile::tempdir().unwrap();
        let audit = Arc::new(AuditLog::new(dir.path().join("a.jsonl")));
        let a2 = audit.clone();
        let t = std::thread::spawn(move || {
            let au = auth();
            for _ in 0..n {
                serve_one(&l, &au, &Echo, &AnyPeer, &a2, || 1000);
            }
        });
        (addr, audit, dir, t)
    }

    #[test]
    fn end_to_end_ok_with_mutual_authentication() {
        let (addr, audit, _d, t) = start(2);
        let r = call(&addr, &ck(), &hk().verifying_key(), "portable", 1000, "ping", json!({})).unwrap();
        assert!(r.ok && r.data["pong"] == true);
        let r = call(&addr, &ck(), &hk().verifying_key(), "portable", 1000, "echo", json!({"x": 1})).unwrap();
        assert_eq!(r.data["x"], 1);
        t.join().unwrap();
        assert_eq!(audit.verify().unwrap(), 2);
    }

    #[test]
    fn forbidden_action_and_wrong_key_are_refused_and_audited() {
        let (addr, audit, _d, t) = start(2);
        assert!(matches!(call(&addr, &ck(), &hk().verifying_key(), "portable", 1000, "display.apply", json!({})), Err(CallError::Refused)));
        assert!(matches!(call(&addr, &SigningKey::from_bytes(&[1u8; 32]), &hk().verifying_key(), "portable", 1000, "ping", json!({})), Err(CallError::Refused)));
        t.join().unwrap();
        let e = audit.entries().unwrap();
        assert_eq!(e[0].outcome, "refuse");
        assert_eq!(e[0].detail, "action-interdite (display.apply)");
        assert_eq!(e[1].detail, "signature (ping)");
    }

    #[test]
    fn stale_timestamp_is_refused() {
        let (addr, _a, _d, t) = start(1);
        assert!(matches!(call(&addr, &ck(), &hk().verifying_key(), "portable", 500, "ping", json!({})), Err(CallError::Refused)));
        t.join().unwrap();
    }

    #[test]
    fn impostor_server_is_detected_by_client() {
        // Faux serveur : repond ok avec une signature faite avec une AUTRE cle.
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let req = read_request(&mut s).unwrap();
            let mut m = HashMap::new();
            m.insert("portable".to_string(), ClientPolicy { pubkey: ck().verifying_key(), allowed: Default::default() });
            let fake = Authenticator::new(SigningKey::from_bytes(&[9u8; 32]), m).unwrap();
            send(&mut s, &fake.sign_response(&req.nonce, true, json!({"pong": true})));
        });
        assert!(matches!(call(&addr, &ck(), &hk().verifying_key(), "portable", 1000, "ping", json!({})), Err(CallError::BadServerSignature)));
        t.join().unwrap();
    }

    #[test]
    fn oversized_request_is_dropped() {
        let (addr, audit, _d, t) = start(1);
        let mut s = TcpStream::connect(&addr).unwrap();
        s.write_all(&vec![b'a'; 20_000]).unwrap();
        s.write_all(b"\n").ok();
        let mut buf = String::new();
        let _ = BufReader::new(s).read_line(&mut buf);
        t.join().unwrap();
        assert_eq!(audit.entries().unwrap()[0].detail, "requete trop longue ou incomplete");
    }

    #[test]
    fn whois_parsing() {
        let t = "Machine:
  Name: a.ts.net
User:
  Name:     me@x.org
  ID: 1
";
        assert!(whois_owner_matches(t, "me@x.org"));
        assert!(!whois_owner_matches(t, "other@x.org"));
        assert!(!whois_owner_matches("Machine:
  Name: me@x.org
", "me@x.org"));
    }

    #[test]
    fn rejected_peer_gets_no_answer_and_is_audited() {
        struct No;
        impl PeerCheck for No {
            fn allowed(&self, _: &IpAddr) -> bool {
                false
            }
        }
        let l = bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::new(dir.path().join("a.jsonl"));
        let t = std::thread::spawn(move || {
            serve_one(&l, &auth(), &Echo, &No, &audit, || 1000);
            audit.entries().unwrap()[0].outcome.clone()
        });
        let _ = call(&addr, &ck(), &hk().verifying_key(), "portable", 1000, "ping", json!({}));
        assert_eq!(t.join().unwrap(), "pair-non-verifie");
    }

    #[test]
    fn bind_policy() {
        assert!(bind("0.0.0.0:0").is_err());
        assert!(bind("127.0.0.1:0").is_ok());
        assert!(is_tailnet_or_loopback(&"100.64.0.10".parse().unwrap()));
        assert!(!is_tailnet_or_loopback(&"100.128.0.1".parse().unwrap()));
        assert!(!is_tailnet_or_loopback(&"192.168.1.66".parse().unwrap()));
        assert!(!is_tailnet_or_loopback(&"37.59.123.135".parse().unwrap()));
    }
}
