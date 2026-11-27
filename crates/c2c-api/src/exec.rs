//! Execution des commandes du registre : une seule implementation, appelee par la CLI, l'agent et l'UI.
//! Chaque commande rend un texte lisible (ce que la CLI affiche) ET des donnees structurees (ce que l'UI affiche).
use crate::platform::*;
use c2c_core::audit::AuditLog;
use c2c_core::display::{self, Layout};
use c2c_core::runner::SystemRunner;
use c2c_core::status::{probe, State, TcpProber};
use c2c_core::wake::{magic_packet, SshPiTransport, WakeTransport};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Ctx {
    pub config: PathBuf,
    pub audit: PathBuf,
    /// Auteur inscrit au journal d'audit : `cli`, `agent`, `ui`.
    pub actor: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Output {
    /// `false` : la commande a abouti mais le resultat est negatif (ex. controle de sante en echec).
    pub ok: bool,
    pub text: String,
    pub data: Value,
}

fn out(text: impl Into<String>, data: Value) -> Result<Output, String> {
    Ok(Output { ok: true, text: text.into(), data })
}

fn s(args: &Value, k: &str) -> Option<String> {
    args.get(k).and_then(Value::as_str).map(str::to_string).filter(|v| !v.is_empty())
}

fn flag(args: &Value, k: &str) -> bool {
    args.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn layout_of(args: &Value) -> Result<Layout, String> {
    match s(args, "layout").as_deref() {
        Some("local") => Ok(Layout::Local),
        Some("remote") => Ok(Layout::Remote),
        _ => Err("layout attendu : local|remote".into()),
    }
}

/// Lance une commande du registre en local (CLI, application sur la machine). `Err` : echec ou arguments invalides.
pub fn run(ctx: &Ctx, name: &str, args: &Value) -> Result<Output, String> {
    run_inner(ctx, name, args, false)
}

/// Variante pour l'agent : n'accede JAMAIS a 1Password (l'agent demarre et tourne seul). Les identifiants Sunshine
/// doivent etre fournis par l'appareil appelant (`_auth`), sinon la commande est refusee.
pub fn run_agent(ctx: &Ctx, name: &str, args: &Value) -> Result<Output, String> {
    run_inner(ctx, name, args, true)
}

fn run_inner(ctx: &Ctx, name: &str, args: &Value, from_agent: bool) -> Result<Output, String> {
    let audit = AuditLog::new(&ctx.audit);
    let log = |actor: &str, action: &str, target: &str, outcome: &str, detail: &str| audit.append(actor, action, target, outcome, detail).map_err(|e| e.to_string());
    match name {
        "ping" => out("pong", json!({"pong": true})),
        "status" => {
            let cfg = load(&ctx.config)?;
            let prober = TcpProber { timeout: Duration::from_secs(2) };
            let (mut text, mut data) = (vec![], vec![]);
            for m in &cfg.machines {
                let (label, key) = match probe(m, &prober) {
                    State::Online => ("en ligne", "online"),
                    State::Offline => ("hors ligne", "offline"),
                    State::Unknown => ("inconnu (pas de probe_port)", "unknown"),
                };
                text.push(format!("{:<16} {}", m.name, label));
                data.push(json!({"name": m.name, "state": key, "agent": m.agent_addr.is_some(), "wakeable": m.mac.is_some()}));
            }
            out(text.join("\n"), json!({"machines": data}))
        }
        "wake" => {
            let name = s(args, "name").ok_or("machine attendue")?;
            let cfg = load(&ctx.config)?;
            let m = cfg.machine(&name).map_err(|e| e.to_string())?;
            let Some(mac) = m.mac().map_err(|e| e.to_string())? else { return Err(format!("{name} n'a pas d'adresse MAC configuree")) };
            let runner = SystemRunner;
            let t = SshPiTransport { runner: &runner, user: cfg.wake.pi_user.clone(), host: cfg.wake.pi_host.clone() };
            if !flag(args, "execute") {
                let text = format!("[simulation] {} -> {} ({} octets). Ajouter --execute pour envoyer.", t.describe(), mac, magic_packet(&mac).len());
                return out(text, json!({"simulation": true, "via": t.describe(), "mac": mac.to_string()}));
            }
            let r = t.send(&mac);
            log(ctx.actor, "wake", &name, if r.is_ok() { "ok" } else { "echec" }, &format!("via={}", t.describe()))?;
            r.map_err(|e| e.to_string())?;
            out(format!("Reveil envoye a {name} via le Pi."), json!({"sent": true, "machine": name}))
        }
        "agent-key" => {
            let cfg = load(&ctx.config)?;
            let path = cfg.agent.host_key.clone().map(PathBuf::from).unwrap_or_else(|| c2c_core::hostkey::path_for(&ctx.config));
            match c2c_core::hostkey::load(&path)? {
                Some(k) => {
                    let pk = c2c_core::proto::pubkey_hex(&k);
                    out(format!("Cle publique de l'agent : {pk}"), json!({"pubkey": pk}))
                }
                None => Err("pas encore de cle d'identite : demarrer l'agent une fois (c2c agent-serve)".into()),
            }
        }
        "net-health" => {
            use c2c_core::nethealth::{probe_http, verdict};
            let t = Duration::from_secs(4);
            let v4 = probe_http("1.1.1.1:80".parse().map_err(|e: std::net::AddrParseError| e.to_string())?, "one.one.one.one", t);
            let v6 = probe_http("[2606:4700:4700::1111]:80".parse().map_err(|e: std::net::AddrParseError| e.to_string())?, "one.one.one.one", t);
            let v = verdict(&v4, &v6);
            log("net", "health", "1.1.1.1/2606:4700:4700::1111", v, "")?;
            out(format!("IPv4 : {v4:?}\nIPv6 : {v6:?}\nverdict : {v}"), json!({"ipv4": format!("{v4:?}"), "ipv6": format!("{v6:?}"), "verdict": v}))
        }
        "health-check" => {
            let checks = c2c_core::healthcheck::run(&SystemRunner);
            let mut text: Vec<String> = checks.iter().map(|c| format!("[{}] {}{}", if c.ok { "OK" } else { "KO" }, c.name, if c.detail.is_empty() { String::new() } else { format!(" : {}", c.detail) })).collect();
            let ko: Vec<&str> = checks.iter().filter(|c| !c.ok).map(|c| c.name.as_str()).collect();
            let healthy = c2c_core::healthcheck::all_ok(&checks);
            text.push(if healthy { "verdict : sain".to_string() } else if checks.is_empty() { "verdict : aucun controle lu (PowerShell indisponible ?)".to_string() } else { format!("verdict : {} controle(s) en echec", ko.len()) });
            log("health", "check", "local", if healthy { "ok" } else { "echec" }, &ko.join(", "))?;
            let data = json!({"healthy": healthy, "checks": checks.iter().map(|c| json!({"name": c.name, "ok": c.ok, "detail": c.detail})).collect::<Vec<_>>()});
            Ok(Output { ok: healthy, text: text.join("\n"), data })
        }
        "session-status" => {
            let st = detect_session(&stream_cfg(&ctx.config));
            let text = format!("session distante : {}", match st { Some(true) => "ACTIVE", Some(false) => "aucune", None => "inconnue (traitee comme active)" });
            out(text, json!({"session": st}))
        }
        "display-status" => {
            let cfg = display_cfg(&ctx.config, &ctx.audit);
            let screens = real_inspect()?;
            let mut text: Vec<String> = screens.iter().map(|s| format!("{:<10} actif={:<5} principal={:<5} {}x{}@{} ({},{})", s.id, s.active, s.primary, s.mode.w, s.mode.h, s.mode.hz, s.x, s.y)).collect();
            let (lo, re) = (display::check(Layout::Local, &screens, &cfg).is_empty(), display::check(Layout::Remote, &screens, &cfg).is_empty());
            text.push(format!("Local correct : {lo}"));
            text.push(format!("Remote correct : {re}"));
            out(text.join("\n"), json!({"screens": screens, "local_ok": lo, "remote_ok": re}))
        }
        "display-apply" => {
            let layout = layout_of(args)?;
            let (execute, force) = (flag(args, "execute"), flag(args, "force"));
            let cfg = display_cfg(&ctx.config, &ctx.audit);
            // Detection impossible => on suppose la session active (sur : Local exige alors force).
            let session_active = detect_session(&stream_cfg(&ctx.config)).unwrap_or(true);
            let opts = display::ApplyOptions { dry_run: !execute, force, session_active, max_attempts: 3 };
            let outcome = real_apply(layout, &cfg, &opts);
            if execute {
                let why = failure_detail(outcome.as_ref().err(), layout, &cfg);
                log(ctx.actor, "display-apply", &format!("{layout:?}"), if outcome.is_ok() { "ok" } else { "echec" }, &why)?;
            }
            let o = outcome.map_err(|e| e.to_string())?;
            out(format!("{o:?}"), json!({"outcome": format!("{o:?}"), "executed": execute}))
        }
        "display-profile" => {
            let c = load(&ctx.config)?;
            let p = profile_path(&ctx.audit);
            if let Some(n) = s(args, "name") {
                if n == "defaut" {
                    let _ = std::fs::remove_file(&p);
                } else if c.display.profiles.contains_key(&n) {
                    std::fs::write(&p, &n).map_err(|e| e.to_string())?;
                } else {
                    return Err(format!("profil inconnu : {n} (disponibles : {})", c.display.profiles.keys().cloned().collect::<Vec<_>>().join(", ")));
                }
                log(ctx.actor, "display-profile", &n, "ok", "")?;
            }
            let cur = read_profile(&ctx.audit);
            let mut text = vec![format!("Profil actif : {}", cur.as_deref().unwrap_or("defaut (remote_mode)"))];
            let mut list = vec![];
            for (n, m) in &c.display.profiles {
                let ratio = c2c_core::config::aspect_ratio(m.w, m.h);
                text.push(format!("  {}{n} : {}x{}@{} ({})", if cur.as_deref() == Some(n.as_str()) { "* " } else { "  " }, m.w, m.h, m.hz, ratio));
                list.push(json!({"name": n, "w": m.w, "h": m.h, "hz": m.hz, "ratio": ratio, "active": cur.as_deref() == Some(n.as_str())}));
            }
            out(text.join("\n"), json!({"active": cur, "profiles": list}))
        }
        "display-mode" => {
            let p = mode_path(&ctx.audit);
            if let Some(m) = s(args, "mode") {
                if !["auto", "local", "remote"].contains(&m.as_str()) {
                    return Err("mode attendu : auto|local|remote".into());
                }
                std::fs::write(&p, &m).map_err(|e| e.to_string())?;
                log(ctx.actor, "display-mode", &m, "ok", "")?;
            }
            let cur = std::fs::read_to_string(&p).unwrap_or_default();
            let cur = if cur.trim().is_empty() { "auto".to_string() } else { cur.trim().to_string() };
            out(format!("Mode d'affichage : {cur}"), json!({"mode": cur}))
        }
        "audit-verify" => {
            let n = audit.verify().map_err(|e| e.to_string())?;
            out(format!("Journal intact : {n} entrees."), json!({"intact": true, "entries": n}))
        }
        "audit-show" => {
            let mut all = audit.entries().map_err(|e| e.to_string())?;
            let limit = args.get("limit").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|t| t.parse().ok()))).unwrap_or(0) as usize;
            if limit > 0 && all.len() > limit {
                all = all.split_off(all.len() - limit);
            }
            let text: Vec<String> = all.iter().map(|e| format!("{} #{} {} {} {} {} {}", e.ts, e.seq, e.actor, e.action, e.target, e.outcome, e.detail)).collect();
            out(text.join("\n"), json!({"entries": all}))
        }
        n if n.starts_with("sunshine.") => {
            use c2c_core::sunshine_api::{run_with as sun, Action};
            let cfg = load(&ctx.config)?;
            let (action, execute, label) = match n {
                "sunshine.clients" => (Action::Clients, true, "clients"),
                "sunshine.pending" => (Action::Pending, true, "pending"),
                "sunshine.pin" => (Action::pin(&s(args, "pin").unwrap_or_default(), &s(args, "name").unwrap_or_else(|| "moonlight".into()), s(args, "pairing_id").as_deref())?, flag(args, "execute"), "pin"),
                "sunshine.unpair" => (Action::unpair(&s(args, "uuid").unwrap_or_default())?, flag(args, "execute"), "unpair"),
                _ => return Err("commande inconnue".into()),
            };
            if !execute {
                return out(format!("[simulation] appellerait Sunshine : {action:?} (ajouter --execute)"), json!({"simulation": true}));
            }
            let creds = match args.get("_auth") {
                Some(a) => match (a.get("user").and_then(Value::as_str), a.get("pass").and_then(Value::as_str)) {
                    (Some(u), Some(p)) => Some((u.to_string(), p.to_string())),
                    _ => return Err("_auth invalide (user et pass attendus)".into()),
                },
                None if from_agent => return Err("identifiants Sunshine non fournis par l'appareil appelant".into()),
                None => None,
            };
            let r = sun(&SystemRunner, &cfg.sunshine, &action, creds);
            log("sunshine", label, "api-locale", if r.is_ok() { "ok" } else { "echec" }, "")?;
            let text = r?;
            let data = serde_json::from_str::<Value>(&text).unwrap_or(Value::String(text.clone()));
            out(text, data)
        }
        _ => Err(format!("commande inconnue : {name}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(dir: &std::path::Path) -> Ctx {
        Ctx { config: dir.join("c2c.toml"), audit: dir.join("c2c-audit.jsonl"), actor: "test" }
    }

    fn tmp(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("c2c-api-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn display_mode_roundtrip_and_validation() {
        let d = tmp("mode");
        let c = ctx(&d);
        assert_eq!(run(&c, "display-mode", &json!({})).unwrap().data["mode"], "auto");
        assert_eq!(run(&c, "display-mode", &json!({"mode": "remote"})).unwrap().data["mode"], "remote");
        assert!(run(&c, "display-mode", &json!({"mode": "nimporte"})).is_err());
        assert_eq!(run(&c, "audit-verify", &json!({})).unwrap().data["entries"], 1);
        let shown = run(&c, "audit-show", &json!({"limit": 1})).unwrap();
        assert_eq!(shown.data["entries"].as_array().unwrap().len(), 1);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn display_profile_lists_sets_and_rejects() {
        let d = tmp("profile");
        std::fs::write(d.join("c2c.toml"), "[wake]\npi_user=\"u\"\npi_host=\"h\"\n[display.profiles.fhd]\nw = 1920\nh = 1080\nhz = 60\n").unwrap();
        let c = ctx(&d);
        let l = run(&c, "display-profile", &json!({})).unwrap();
        assert!(l.text.contains("fhd : 1920x1080@60 (16:9)") && l.data["active"].is_null());
        let set = run(&c, "display-profile", &json!({"name": "fhd"})).unwrap();
        assert_eq!(set.data["active"], "fhd");
        assert!(run(&c, "display-profile", &json!({"name": "x"})).is_err());
        assert!(run(&c, "display-profile", &json!({"name": "defaut"})).unwrap().data["active"].is_null());
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn wake_is_a_simulation_without_execute_and_unknown_commands_fail() {
        let d = tmp("wake");
        std::fs::write(d.join("c2c.toml"), "[wake]\npi_user=\"u\"\npi_host=\"h\"\n[[machine]]\nname=\"m\"\naddress=\"m.example\"\nmac=\"02:00:5E:00:00:01\"\n").unwrap();
        let c = ctx(&d);
        let w = run(&c, "wake", &json!({"name": "m"})).unwrap();
        assert!(w.text.contains("simulation") && w.data["simulation"] == true);
        assert!(!d.join("c2c-audit.jsonl").exists());
        assert!(run(&c, "wake", &json!({"name": "absent"})).is_err());
        assert!(run(&c, "nimporte", &json!({})).is_err());
        assert_eq!(run(&c, "ping", &json!({})).unwrap().data["pong"], true);
        std::fs::remove_dir_all(&d).ok();
    }

    #[test]
    fn sunshine_inputs_are_validated_before_any_call() {
        let d = tmp("sun");
        std::fs::write(d.join("c2c.toml"), "[wake]\npi_user=\"u\"\npi_host=\"h\"\n").unwrap();
        let c = ctx(&d);
        assert!(run(&c, "sunshine.pin", &json!({"pin": "12a4", "execute": true})).is_err());
        assert!(run(&c, "sunshine.unpair", &json!({"uuid": "x'; calc"})).is_err());
        let sim = run(&c, "sunshine.pin", &json!({"pin": "1234"})).unwrap();
        assert_eq!(sim.data["simulation"], true);
        std::fs::remove_dir_all(&d).ok();
    }
}
