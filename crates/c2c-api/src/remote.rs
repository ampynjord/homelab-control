//! Execution d'une commande sur une machine : en local, ou par l'agent signe (tailnet) quand la machine pilotee est une autre.
//! Utilise par les applications (bureau, mobile) ; la CLI garde `c2c remote` pour les appels bruts.
//! 1Password n'est sollicite que ICI, sur l'appareil qui se connecte, et une seule fois par processus (cle privee en memoire) :
//! l'agent, lui, n'y touche jamais.
use crate::exec::{run, Ctx, Output};
use crate::platform::{load, unix_now};
use crate::registry::{find, Target};
use c2c_core::agent::{call, CallError};
use c2c_core::audit::AuditLog;
use c2c_core::proto::{parse_pubkey, parse_seed};
use c2c_core::runner::SystemRunner;
use c2c_core::secrets::{OpCli, SecretProvider};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Value};

/// Appelle l'agent a `addr` avec la cle privee de cet appareil ; la reponse doit etre signee par l'agent epingle `agent_pub`.
pub fn call_agent(addr: &str, key: &SigningKey, agent_pub: &VerifyingKey, client: &str, name: &str, args: &Value) -> Result<Output, String> {
    let r = call(addr, key, agent_pub, client, unix_now(), name, args.clone()).map_err(|e| match e {
        CallError::Io(m) => format!("agent injoignable : {m}"),
        CallError::Refused => "refuse par l'agent (droit manquant, cle inconnue ou appareil non reconnu)".to_string(),
        CallError::BadServerSignature => "reponse non signee par l'agent epingle : serveur usurpe, rejeu, ou cle de l'agent changee (agent_pubkey)".to_string(),
    })?;
    if !r.ok {
        let why = r.data.get("error").and_then(Value::as_str).unwrap_or("echec");
        return Err(why.to_string());
    }
    match (r.data.get("text").and_then(Value::as_str), r.data.get("ok").and_then(Value::as_bool)) {
        (Some(t), Some(ok)) => Ok(Output { ok, text: t.to_string(), data: r.data.get("data").cloned().unwrap_or(Value::Null) }),
        // Actions historiques de l'agent (`status`, `display.apply`) : reponse brute.
        _ => Ok(Output { ok: true, text: serde_json::to_string_pretty(&r.data).unwrap_or_default(), data: r.data }),
    }
}

/// Cles privees de cet appareil : lues dans 1Password une seule fois par processus (memoire uniquement), oubliees apres un refus.
fn key_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>> {
    static C: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, [u8; 32]>>> = std::sync::OnceLock::new();
    C.get_or_init(Default::default)
}

/// Cle privee de cet appareil depuis sa reference 1Password (`key_ref`).
/// Le verrou du cache reste tenu PENDANT la lecture : des appels simultanes (tableau de bord) attendent le resultat au lieu de
/// declencher chacun une demande d'autorisation a 1Password.
pub fn client_key(kref: &str) -> Result<SigningKey, String> {
    let mut cache = key_cache().lock().unwrap();
    if let Some(seed) = cache.get(kref) {
        return Ok(SigningKey::from_bytes(seed));
    }
    let secret = OpCli { runner: &SystemRunner }.read(kref).map_err(|e| format!("cle de cet appareil illisible (1Password verrouille ?) : {e}"))?;
    let key = parse_seed(secret.expose())?;
    cache.insert(kref.to_string(), key.to_bytes());
    Ok(key)
}

/// `machine` absent : on est sur la machine pilotee (ou la commande s'execute ici). Sinon : par l'agent de `machine`.
pub fn run_on(ctx: &Ctx, machine: Option<&str>, name: &str, args: &Value) -> Result<Output, String> {
    let spec = find(name).ok_or_else(|| format!("commande inconnue : {name}"))?;
    let Some(m) = machine else { return run(ctx, name, args) };
    if spec.target == Target::Local {
        return run(ctx, name, args);
    }
    let cfg = load(&ctx.config)?;
    let mc = cfg.machine(m).map_err(|e| e.to_string())?;
    let addr = mc.agent_addr.clone().ok_or_else(|| format!("{m} n'a pas d'agent configure (agent_addr)"))?;
    let kref = mc.key_ref.clone().ok_or_else(|| format!("{m} n'a pas de cle configuree (key_ref : cle privee de cet appareil)"))?;
    let apub = parse_pubkey(mc.agent_pubkey.as_deref().ok_or_else(|| format!("{m} n'a pas de cle d'agent epinglee (agent_pubkey)"))?)?;
    let me = cfg.client_name.clone().ok_or("client_name manquant dans la configuration")?;
    // Sunshine : le mot de passe est celui du 1Password de CET appareil, envoye avec la requete (jamais journalise, jamais stocke
    // par l'agent). Les simulations n'en ont pas besoin.
    let mut args = args.clone();
    let needs_auth = name.starts_with("sunshine.") && (!spec.has_execute || args.get("execute").and_then(Value::as_bool).unwrap_or(false));
    if needs_auth {
        let (u, p) = c2c_core::sunshine_api::read_credentials(&SystemRunner, &cfg.sunshine)?;
        if !args.is_object() {
            args = json!({});
        }
        args["_auth"] = json!({"user": u, "pass": p});
    }
    let key = client_key(&kref)?;
    let r = call_agent(&addr, &key, &apub, &me, name, &args);
    if matches!(&r, Err(e) if e.contains("refuse")) {
        key_cache().lock().unwrap().remove(&kref); // cle peut-etre remplacee : relue au prochain appel
    }
    let _ = AuditLog::new(&ctx.audit).append(ctx.actor, &format!("remote:{name}"), m, if r.is_ok() { "ok" } else { "echec" }, "");
    r
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{expand_allowed, ApiHandler};
    use c2c_core::agent::{bind, serve_one, AnyPeer};
    use c2c_core::proto::{Authenticator, ClientPolicy};
    use std::collections::HashMap;

    fn client_sk() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }
    fn host_sk() -> SigningKey {
        SigningKey::from_bytes(&[4u8; 32])
    }

    /// Agent reel (ApiHandler) sur loopback, traitant `n` requetes, avec les droits `allowed`.
    fn agent(n: usize, allowed: &[&str], dir: &std::path::Path) -> (String, std::thread::JoinHandle<()>) {
        std::fs::write(dir.join("c2c.toml"), "[wake]\npi_user=\"u\"\npi_host=\"h\"\n[display.profiles.fhd]\nw = 1920\nh = 1080\nhz = 60\n").unwrap();
        let l = bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let mut m = HashMap::new();
        m.insert("ui".to_string(), ClientPolicy { pubkey: client_sk().verifying_key(), allowed: expand_allowed(&allowed.iter().map(|s| s.to_string()).collect::<Vec<_>>()) });
        let auth = Authenticator::new(host_sk(), m).unwrap();
        let h = ApiHandler { ctx: Ctx { config: dir.join("c2c.toml"), audit: dir.join("a.jsonl"), actor: "agent" } };
        let audit = AuditLog::new(dir.join("srv.jsonl"));
        let t = std::thread::spawn(move || {
            for _ in 0..n {
                serve_one(&l, &auth, &h, &AnyPeer, &audit, unix_now);
            }
        });
        (addr, t)
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("c2c-remote-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn c(addr: &str, n: &str, a: Value) -> Result<Output, String> {
        call_agent(addr, &client_sk(), &host_sk().verifying_key(), "ui", n, &a)
    }

    #[test]
    fn read_client_reads_but_cannot_write_through_the_real_agent() {
        let d = tmp("rights");
        let (addr, t) = agent(5, &["@read"], &d);
        assert_eq!(c(&addr, "ping", json!({})).unwrap().data["pong"], true);
        assert_eq!(c(&addr, "display-mode", json!({})).unwrap().data["mode"], "auto");
        assert!(c(&addr, "display-profile", json!({})).unwrap().text.contains("fhd : 1920x1080@60"));
        // Ecriture : droit `display-mode!set` absent -> refus de l'agent.
        assert!(c(&addr, "display-mode", json!({"mode": "remote"})).unwrap_err().contains("refuse"));
        // Simulation d'un appairage : `sunshine.pin!plan` est en lecture, aucune action reelle, pas de mot de passe requis.
        assert!(c(&addr, "sunshine.pin", json!({"pin": "1234"})).unwrap().text.contains("simulation"));
        t.join().unwrap();
        assert!(!d.join("c2c-display-mode.txt").exists());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn common_client_can_write_but_not_do_destructive_things() {
        let d = tmp("common");
        let (addr, t) = agent(3, &["@common"], &d);
        assert_eq!(c(&addr, "display-mode", json!({"mode": "remote"})).unwrap().data["mode"], "remote");
        assert!(c(&addr, "sunshine.unpair", json!({"uuid": "0f8fad5b-d9cb-469f-a165-70867728950e", "execute": true})).unwrap_err().contains("refuse"));
        assert!(c(&addr, "display-apply", json!({"layout": "local", "execute": true, "force": true})).unwrap_err().contains("refuse"));
        t.join().unwrap();
        assert_eq!(std::fs::read_to_string(d.join("c2c-display-mode.txt")).unwrap(), "remote");
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn the_agent_never_falls_back_to_its_own_1password_for_sunshine() {
        let d = tmp("nofallback");
        let (addr, t) = agent(1, &["@all"], &d);
        // Execution reelle sans `_auth` : l'agent refuse au lieu d'aller lire 1Password (pas de fenetre sur le PC fixe).
        let e = c(&addr, "sunshine.pin", json!({"pin": "1234", "execute": true})).unwrap_err();
        assert!(e.contains("non fournis par l'appareil"), "{e}");
        t.join().unwrap();
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn local_target_commands_never_go_through_the_agent() {
        let d = tmp("local");
        let ctx = Ctx { config: d.join("c2c.toml"), audit: d.join("a.jsonl"), actor: "ui" };
        std::fs::write(&ctx.config, "[wake]\npi_user=\"u\"\npi_host=\"h\"\n[[machine]]\nname=\"m\"\naddress=\"127.0.0.1\"\nprobe_port=1\n").unwrap();
        let r = run_on(&ctx, Some("m"), "status", &json!({})).unwrap();
        assert!(r.data["machines"].is_array());
        // Machine distante sans agent configure : message clair.
        assert!(run_on(&ctx, Some("m"), "display-status", &json!({})).unwrap_err().contains("agent"));
        assert!(run_on(&ctx, None, "nimporte", &json!({})).is_err());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn an_unknown_client_key_and_an_impostor_agent_are_both_refused() {
        let d = tmp("keys");
        let (addr, t) = agent(2, &["@read"], &d);
        let intruder = SigningKey::from_bytes(&[1u8; 32]);
        assert!(call_agent(&addr, &intruder, &host_sk().verifying_key(), "ui", "ping", &json!({})).unwrap_err().contains("refuse"));
        // Mauvaise cle d'agent epinglee : la reponse du vrai agent n'est pas reconnue (ou un faux agent serait demasque).
        let wrong_pin = SigningKey::from_bytes(&[2u8; 32]).verifying_key();
        assert!(call_agent(&addr, &client_sk(), &wrong_pin, "ui", "ping", &json!({})).unwrap_err().contains("epingle"));
        t.join().unwrap();
        std::fs::remove_dir_all(&d).ok();
    }
}
