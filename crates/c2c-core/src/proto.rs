//! Protocole de l'agent (v2) : requetes et reponses signees en Ed25519, anti-rejeu, droits par client.
//! Le chiffrement du transport est assure par WireGuard (Tailscale). Ici : authentification MUTUELLE par cles asymetriques.
//! - Chaque appareil client a sa paire de cles : la cle PRIVEE reste dans le 1Password de cet appareil ; l'agent ne connait que
//!   la cle PUBLIQUE (aucun secret a lire au demarrage : l'agent demarre seul).
//! - L'agent a sa propre cle d'identite (generee sur sa machine, comme une cle d'hote SSH) ; les clients epinglent sa cle publique.
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

pub const MAX_SKEW_SECS: i64 = 30;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Request {
    pub client: String,
    pub ts: i64,
    pub nonce: String,
    pub action: String,
    #[serde(default)]
    pub args: Value,
    #[serde(default)]
    pub sig: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Response {
    pub ok: bool,
    #[serde(default)]
    pub data: Value,
    #[serde(default)]
    pub sig: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AuthError {
    UnknownClient,
    BadSignature,
    Stale,
    Replay,
    Forbidden,
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok()).collect()
}

/// Paire de cles neuve (aleatoire du systeme).
pub fn generate_key() -> SigningKey {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("source d'aleatoire du systeme");
    SigningKey::from_bytes(&seed)
}

/// Cle privee depuis sa graine (64 caracteres hexadecimaux).
pub fn parse_seed(s: &str) -> Result<SigningKey, String> {
    let b = unhex(s.trim()).filter(|b| b.len() == 32).ok_or("cle privee invalide (64 caracteres hexadecimaux attendus)")?;
    let seed: [u8; 32] = b.try_into().map_err(|_| "cle privee invalide")?;
    Ok(SigningKey::from_bytes(&seed))
}

pub fn seed_hex(k: &SigningKey) -> String {
    hex(&k.to_bytes())
}

pub fn pubkey_hex(k: &SigningKey) -> String {
    hex(k.verifying_key().as_bytes())
}

/// Cle publique depuis sa forme hexadecimale (64 caracteres).
pub fn parse_pubkey(s: &str) -> Result<VerifyingKey, String> {
    let b = unhex(s.trim()).filter(|b| b.len() == 32).ok_or("cle publique invalide (64 caracteres hexadecimaux attendus)")?;
    let arr: [u8; 32] = b.try_into().map_err(|_| "cle publique invalide")?;
    VerifyingKey::from_bytes(&arr).map_err(|_| "cle publique invalide (point hors courbe)".to_string())
}

fn req_canonical(r: &Request) -> String {
    format!("c2c2\n{}\n{}\n{}\n{}\n{}", r.client, r.ts, r.nonce, r.action, r.args)
}

fn resp_canonical(nonce: &str, ok: bool, data: &Value) -> String {
    format!("c2c2-resp\n{nonce}\n{ok}\n{data}")
}

pub fn new_nonce() -> String {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).expect("source d'aleatoire du systeme");
    hex(&b)
}

pub fn sign_request(key: &SigningKey, client: &str, ts: i64, action: &str, args: Value) -> Request {
    let mut r = Request { client: client.into(), ts, nonce: new_nonce(), action: action.into(), args, sig: String::new() };
    r.sig = hex(&key.sign(req_canonical(&r).as_bytes()).to_bytes());
    r
}

fn verify_sig(pubkey: &VerifyingKey, message: &str, sig_hex: &str) -> bool {
    let Some(b) = unhex(sig_hex) else { return false };
    let Ok(arr) = <[u8; 64]>::try_from(b.as_slice()) else { return false };
    pubkey.verify(message.as_bytes(), &Signature::from_bytes(&arr)).is_ok()
}

/// Cote client : verifie que la reponse est bien signee par l'agent epingle pour CETTE requete.
pub fn verify_response(agent_pub: &VerifyingKey, req: &Request, resp: &Response) -> bool {
    verify_sig(agent_pub, &resp_canonical(&req.nonce, resp.ok, &resp.data), &resp.sig)
}

pub struct ClientPolicy {
    pub pubkey: VerifyingKey,
    pub allowed: HashSet<String>,
}

pub struct Authenticator {
    host: SigningKey,
    clients: HashMap<String, ClientPolicy>,
    seen: Mutex<HashMap<String, i64>>,
}

impl Authenticator {
    pub fn new(host: SigningKey, clients: HashMap<String, ClientPolicy>) -> Result<Self, String> {
        if clients.is_empty() {
            return Err("aucun client autorise".into());
        }
        Ok(Self { host, clients, seen: Mutex::new(HashMap::new()) })
    }

    pub fn host_pubkey(&self) -> VerifyingKey {
        self.host.verifying_key()
    }

    /// Ordre voulu : client connu, signature, fraicheur, rejeu, droit sur l'action.
    /// La signature est verifiee AVANT d'enregistrer le nonce : un inconnu ne peut pas remplir le cache.
    pub fn verify_request(&self, r: &Request, now: i64) -> Result<(), AuthError> {
        self.verify_request_for(r, now, &r.action)
    }

    /// Comme `verify_request`, mais le droit exige est `needed` (ex. `display-apply!force`) et non le nom brut de l'action.
    pub fn verify_request_for(&self, r: &Request, now: i64, needed: &str) -> Result<(), AuthError> {
        let p = self.clients.get(&r.client).ok_or(AuthError::UnknownClient)?;
        if !verify_sig(&p.pubkey, &req_canonical(r), &r.sig) {
            return Err(AuthError::BadSignature);
        }
        if (now - r.ts).abs() > MAX_SKEW_SECS {
            return Err(AuthError::Stale);
        }
        {
            let mut seen = self.seen.lock().unwrap();
            seen.retain(|_, t| now - *t <= 2 * MAX_SKEW_SECS);
            let key = format!("{}:{}", r.client, r.nonce);
            if seen.contains_key(&key) {
                return Err(AuthError::Replay);
            }
            seen.insert(key, r.ts);
        }
        if !p.allowed.contains(needed) {
            return Err(AuthError::Forbidden);
        }
        Ok(())
    }

    pub fn sign_response(&self, req_nonce: &str, ok: bool, data: Value) -> Response {
        let sig = hex(&self.host.sign(resp_canonical(req_nonce, ok, &data).as_bytes()).to_bytes());
        Response { ok, data, sig }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn client_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }
    fn host_key() -> SigningKey {
        SigningKey::from_bytes(&[3u8; 32])
    }

    fn auth() -> Authenticator {
        let mut m = HashMap::new();
        m.insert("portable".to_string(), ClientPolicy { pubkey: client_key().verifying_key(), allowed: ["ping", "status"].iter().map(|s| s.to_string()).collect() });
        Authenticator::new(host_key(), m).unwrap()
    }

    #[test]
    fn valid_request_passes() {
        let r = sign_request(&client_key(), "portable", 1000, "status", json!({}));
        assert_eq!(auth().verify_request(&r, 1000), Ok(()));
    }

    #[test]
    fn replay_is_refused() {
        let a = auth();
        let r = sign_request(&client_key(), "portable", 1000, "ping", json!({}));
        assert_eq!(a.verify_request(&r, 1000), Ok(()));
        assert_eq!(a.verify_request(&r, 1001), Err(AuthError::Replay));
    }

    #[test]
    fn tampering_is_refused() {
        let mut r = sign_request(&client_key(), "portable", 1000, "ping", json!({}));
        r.action = "display.apply".into();
        assert_eq!(auth().verify_request(&r, 1000), Err(AuthError::BadSignature));
        let mut r = sign_request(&client_key(), "portable", 1000, "ping", json!({"a": 1}));
        r.args = json!({"a": 2});
        assert_eq!(auth().verify_request(&r, 1000), Err(AuthError::BadSignature));
    }

    #[test]
    fn wrong_key_and_unknown_client() {
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let r = sign_request(&other, "portable", 1000, "ping", json!({}));
        assert_eq!(auth().verify_request(&r, 1000), Err(AuthError::BadSignature));
        let r = sign_request(&client_key(), "intrus", 1000, "ping", json!({}));
        assert_eq!(auth().verify_request(&r, 1000), Err(AuthError::UnknownClient));
    }

    #[test]
    fn malformed_signatures_are_refused_not_panicking() {
        let mut r = sign_request(&client_key(), "portable", 1000, "ping", json!({}));
        for bad in ["", "zz", "00", &"00".repeat(63), &"00".repeat(65)] {
            r.sig = bad.to_string();
            assert_eq!(auth().verify_request(&r, 1000), Err(AuthError::BadSignature));
        }
    }

    #[test]
    fn stale_and_future_are_refused() {
        let r = sign_request(&client_key(), "portable", 1000, "ping", json!({}));
        assert_eq!(auth().verify_request(&r, 1000 + MAX_SKEW_SECS + 1), Err(AuthError::Stale));
        let r = sign_request(&client_key(), "portable", 1000 + 500, "ping", json!({}));
        assert_eq!(auth().verify_request(&r, 1000), Err(AuthError::Stale));
    }

    #[test]
    fn action_not_in_policy_is_forbidden() {
        let r = sign_request(&client_key(), "portable", 1000, "display.apply", json!({}));
        assert_eq!(auth().verify_request(&r, 1000), Err(AuthError::Forbidden));
    }

    #[test]
    fn unsigned_junk_does_not_fill_nonce_cache() {
        let a = auth();
        let other = SigningKey::from_bytes(&[1u8; 32]);
        for i in 0..50 {
            let mut r = sign_request(&other, "portable", 1000, "ping", json!({}));
            r.nonce = format!("junk{i}");
            let _ = a.verify_request(&r, 1000);
        }
        assert_eq!(a.seen.lock().unwrap().len(), 0);
    }

    #[test]
    fn response_is_bound_to_request_and_to_the_pinned_agent_key() {
        let a = auth();
        let agent_pub = host_key().verifying_key();
        let r = sign_request(&client_key(), "portable", 1000, "ping", json!({}));
        let resp = a.sign_response(&r.nonce, true, json!({"pong": true}));
        assert!(verify_response(&agent_pub, &r, &resp));
        let other = sign_request(&client_key(), "portable", 1000, "ping", json!({}));
        assert!(!verify_response(&agent_pub, &other, &resp), "reponse rejouee sur une autre requete");
        let mut forged = resp.clone();
        forged.data = json!({"pong": false});
        assert!(!verify_response(&agent_pub, &r, &forged));
        let impostor = SigningKey::from_bytes(&[8u8; 32]).verifying_key();
        assert!(!verify_response(&impostor, &r, &resp), "un autre agent ne peut pas se faire passer pour le bon");
    }

    #[test]
    fn empty_policy_rejected_and_key_encodings_roundtrip() {
        assert!(Authenticator::new(host_key(), HashMap::new()).is_err());
        let k = client_key();
        assert_eq!(parse_seed(&seed_hex(&k)).unwrap().to_bytes(), k.to_bytes());
        assert_eq!(parse_pubkey(&pubkey_hex(&k)).unwrap(), k.verifying_key());
        assert!(parse_seed("abc").is_err() && parse_seed(&"zz".repeat(32)).is_err());
        assert!(parse_pubkey("00").is_err());
        assert_ne!(pubkey_hex(&generate_key()), pubkey_hex(&generate_key()));
    }
}
