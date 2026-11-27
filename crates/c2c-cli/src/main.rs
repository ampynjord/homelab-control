//! c2c : CLI du centre de controle. Tout effet reel exige --execute (sinon simulation).
//! Les commandes du registre (`c2c-api`) sont executees par la meme couche que l'agent et les applications : memes fonctionnalites.
use anyhow::{Context, Result};
use c2c_api::platform::{detect_session, display_cfg, failure_detail, load, mode_path, read_pin, real_apply, real_inspect, stream_cfg, unix_now};
use c2c_api::Ctx;
use c2c_core::audit::AuditLog;
use c2c_core::display::{self, DisplayConfig, Layout, Screen};
use c2c_core::runner::SystemRunner;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "c2c", about = "Centre de controle du homelab", version = c2c_core::update::VERSION)]
struct Cli {
    #[arg(long, default_value = "c2c.toml")]
    config: PathBuf,
    #[arg(long, default_value = "c2c-audit.jsonl")]
    audit: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum SunshineCmd {
    /// Liste les clients Moonlight appaires (lecture seule).
    Clients,
    /// Demandes d'appairage en attente de PIN (le PIN doit etre affiche sur l'appareil). Lecture seule.
    Pending,
    /// Appaire un client Moonlight avec le PIN affiche par Moonlight (4 chiffres). Sans --pairing-id : la seule demande en attente.
    Pin {
        pin: String,
        #[arg(long, default_value = "moonlight")]
        name: String,
        #[arg(long)]
        pairing_id: Option<String>,
        #[arg(long)]
        execute: bool,
    },
    /// Retire un client appaire (UUID donne par `clients`). Simulation sans --execute.
    Unpair {
        uuid: String,
        #[arg(long)]
        execute: bool,
    },
}

#[derive(Subcommand)]
enum Cmd {
    /// Etat des machines (sonde TCP).
    Status,
    /// Reveille une machine via le Pi. Simulation sans --execute.
    Wake {
        name: String,
        #[arg(long)]
        execute: bool,
    },
    /// Verifie la derniere release GitHub ; --execute l'installe a cote de cet executable.
    Update {
        #[arg(long)]
        execute: bool,
    },
    /// Plan d'ecran a partir d'un etat JSON (aucune modification de l'affichage).
    DisplayPlan {
        #[arg(value_enum)]
        layout: LayoutArg,
        /// Fichier JSON : liste de Screen (voir examples/screens-local.json).
        #[arg(long)]
        screens: PathBuf,
        #[arg(long)]
        session_active: bool,
    },
    /// Surveillance continue : applique Remote/Local selon la session (remplace la tache Watch).
    /// Simulation (journalise seulement) sans --execute.
    Watch {
        #[arg(long)]
        execute: bool,
        /// Nombre maximal de cycles (0 = illimite) ; utile pour les essais.
        #[arg(long, default_value_t = 0)]
        cycles: u64,
    },
    /// Lance l'agent (ecoute sur le tailnet, requetes signees). Cles lues dans 1Password.
    AgentServe,
    /// Affiche la cle publique de l'agent de cette machine (a epingler dans `agent_pubkey` des clients).
    AgentKey,
    /// Cree la paire de cles de CET appareil : la cle privee va dans son 1Password (jamais affichee), la cle publique est affichee.
    Keygen {
        /// Nom de l'appareil (ex. portable).
        device: String,
        #[arg(long, default_value = "Homelab")]
        vault: String,
    },
    /// Appelle l'agent d'une machine : c2c remote pc-fixe display-status
    Remote {
        name: String,
        action: String,
        /// Arguments JSON (ex. '{"layout":"remote"}').
        #[arg(long, default_value = "{}")]
        args: String,
    },
    /// Sante du reseau sortant : IPv4 et IPv6 (requete HTTP minimale). Lecture seule, journalise le verdict.
    NetHealth,
    /// API web de Sunshine (a lancer sur le PC fixe) : identifiants lus dans 1Password, certificat epingle.
    Sunshine {
        #[command(subcommand)]
        cmd: SunshineCmd,
    },
    /// Verification de sante de cette machine (services, taches, session console, Sunshine, pare-feu, reseau). Lecture seule ; code de sortie 1 si un controle echoue.
    HealthCheck,
    /// Profil de l'ecran virtuel (resolution, proportions, frequence) defini dans [display.profiles.*]. Sans argument : liste.
    DisplayProfile {
        /// Nom du profil a activer, ou "defaut". Sans argument : liste les profils.
        name: Option<String>,
    },
    /// Choix de la disposition : auto (suit la session), local (ecrans physiques), remote (ecran virtuel seul). Sans argument : affiche.
    DisplayMode {
        #[arg(value_enum)]
        mode: Option<ModeArg>,
    },
    /// Une session distante est-elle active ? (lecture seule)
    SessionStatus,
    /// Etat reel des ecrans (lecture seule, Windows).
    DisplayStatus,
    /// Applique une disposition d'ecran reelle (Windows). Simulation sans --execute.
    DisplayApply {
        #[arg(value_enum)]
        layout: LayoutArg,
        #[arg(long)]
        execute: bool,
        /// Necessaire pour passer en Local pendant une session distante (ou si la detection echoue).
        #[arg(long)]
        force: bool,
    },
    /// Verifie l'integrite du journal d'audit.
    AuditVerify,
    /// Affiche le journal d'audit.
    AuditShow {
        /// Nombre d'entrees les plus recentes (absent : toutes).
        #[arg(long)]
        limit: Option<u32>,
    },
}

#[derive(Clone, ValueEnum)]
enum ModeArg {
    Auto,
    Local,
    Remote,
}

impl ModeArg {
    fn as_str(&self) -> &'static str {
        match self {
            ModeArg::Auto => "auto",
            ModeArg::Local => "local",
            ModeArg::Remote => "remote",
        }
    }
}

#[derive(Clone, ValueEnum)]
enum LayoutArg {
    Local,
    Remote,
}

impl LayoutArg {
    fn as_str(&self) -> &'static str {
        match self {
            LayoutArg::Local => "local",
            LayoutArg::Remote => "remote",
        }
    }
    fn layout(&self) -> Layout {
        match self {
            LayoutArg::Local => Layout::Local,
            LayoutArg::Remote => Layout::Remote,
        }
    }
}

/// Lance une commande du registre et affiche son texte ; code de sortie 1 si le resultat est negatif.
fn run_api(ctx: &Ctx, name: &str, args: Value) -> Result<()> {
    let o = c2c_api::run(ctx, name, &args).map_err(anyhow::Error::msg)?;
    if !o.text.is_empty() {
        println!("{}", o.text);
    }
    if !o.ok {
        std::process::exit(1);
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.clone();
    let audit_path = cli.audit.clone();
    let audit = AuditLog::new(&cli.audit);
    let scfg = stream_cfg(&cli.config);
    let ctx = Ctx { config: cli.config.clone(), audit: cli.audit.clone(), actor: "cli" };
    match cli.cmd {
        Cmd::Status => run_api(&ctx, "status", json!({}))?,
        Cmd::Wake { name, execute } => run_api(&ctx, "wake", json!({"name": name, "execute": execute}))?,
        Cmd::Update { execute } => run_api(&ctx, "update", json!({"execute": execute}))?,
        Cmd::NetHealth => run_api(&ctx, "net-health", json!({}))?,
        Cmd::AgentKey => run_api(&ctx, "agent-key", json!({}))?,
        Cmd::Keygen { device, vault } => {
            let k = c2c_api::keygen(&SystemRunner, &device, &vault).map_err(anyhow::Error::msg)?;
            audit.append("cli", "keygen", &device, "ok", &format!("pubkey={}", k.pubkey))?;
            println!("Cle privee de {device} creee dans 1Password ({}), jamais affichee.", k.title);
            println!("Cle publique (a donner a l'agent, section [[agent.client]]) :");
            println!("  pubkey = \"{}\"", k.pubkey);
            println!("A placer dans la config de CET appareil, section [[machine]] de la machine pilotee :");
            println!("  key_ref = \"{}\"", k.key_ref);
        }
        Cmd::HealthCheck => run_api(&ctx, "health-check", json!({}))?,
        Cmd::SessionStatus => run_api(&ctx, "session-status", json!({}))?,
        Cmd::DisplayStatus => run_api(&ctx, "display-status", json!({}))?,
        Cmd::DisplayApply { layout, execute, force } => run_api(&ctx, "display-apply", json!({"layout": layout.as_str(), "execute": execute, "force": force}))?,
        Cmd::DisplayProfile { name } => run_api(&ctx, "display-profile", json!({"name": name}))?,
        Cmd::DisplayMode { mode } => run_api(&ctx, "display-mode", json!({"mode": mode.map(|m| m.as_str())}))?,
        Cmd::AuditVerify => run_api(&ctx, "audit-verify", json!({}))?,
        Cmd::AuditShow { limit } => run_api(&ctx, "audit-show", json!({"limit": limit}))?,
        Cmd::Sunshine { cmd } => match cmd {
            SunshineCmd::Clients => run_api(&ctx, "sunshine.clients", json!({}))?,
            SunshineCmd::Pending => run_api(&ctx, "sunshine.pending", json!({}))?,
            SunshineCmd::Pin { pin, name, pairing_id, execute } => run_api(&ctx, "sunshine.pin", json!({"pin": pin, "name": name, "pairing_id": pairing_id, "execute": execute}))?,
            SunshineCmd::Unpair { uuid, execute } => run_api(&ctx, "sunshine.unpair", json!({"uuid": uuid, "execute": execute}))?,
        },
        Cmd::DisplayPlan { layout, screens, session_active } => {
            let text = std::fs::read_to_string(&screens).with_context(|| format!("lecture de {}", screens.display()))?;
            let list: Vec<Screen> = serde_json::from_str(&text).context("JSON d'ecrans invalide")?;
            let layout = layout.layout();
            let cfg = display_cfg(&config_path, &audit_path);
            display::guard(layout, &display::ApplyOptions { dry_run: true, force: false, session_active, max_attempts: 1 })?;
            let problems = display::check(layout, &list, &cfg);
            if problems.is_empty() {
                println!("Topologie deja correcte.");
            } else {
                for p in &problems {
                    println!("probleme : {p:?}");
                }
                for s in display::plan(layout, &list, &cfg)? {
                    println!("etape    : {s:?}");
                }
            }
        }
        Cmd::Watch { execute, cycles } => {
            // Instance unique : un seul processus peut tenir ce port local.
            let _guard = std::net::TcpListener::bind("127.0.0.1:47631").context("une autre surveillance C2C tourne deja")?;
            // Pas de fenetre : la tache planifiee lance `conhost.exe --headless c2c.exe watch --execute`.
            let mut cfg: DisplayConfig;
            let mut w = c2c_core::watch::Watcher::new();
            let t0 = std::time::Instant::now();
            let mut n = 0u64;
            let mut last_repair = i64::MIN / 2;
            let mut console_guard = c2c_core::watch::ConsoleGuard::default();
            audit.append("watch", "start", "local", "ok", if execute { "mode=execute" } else { "mode=simulation" })?;
            loop {
                let now = t0.elapsed().as_secs() as i64;
                // Profil d'ecran virtuel : relu a chaque tour, un changement s'applique sans redemarrer Watch.
                cfg = display_cfg(&config_path, &audit_path);
                let session = detect_session(&scfg);
                let screens = real_inspect();
                let screens_ok = screens.is_ok();
                let screens = screens.unwrap_or_default();
                // Pas de lecture d'ecran fiable : on n'agit pas.
                let sess = if screens_ok { session } else { None };
                // Choix manuel : Watch maintient cette disposition quelle que soit la session (sess reste reel pour la garde).
                let eff = match read_pin(&mode_path(&cli.audit)) {
                    Some(Layout::Local) if screens_ok => Some(false),
                    Some(Layout::Remote) if screens_ok => Some(true),
                    _ => sess,
                };
                if let Some(layout) = w.tick(now, eff, |l| display::check(l, &screens, &cfg).is_empty()) {
                    if execute {
                        let opts = display::ApplyOptions { dry_run: false, force: false, session_active: layout == Layout::Local && sess == Some(true), max_attempts: 3 };
                        let r = real_apply(layout, &cfg, &opts);
                        w.report(r.is_ok());
                        { use std::io::Write; let _ = writeln!(std::io::stdout(), "[watch] {layout:?} -> {r:?}"); }
                        let why = failure_detail(r.as_ref().err(), layout, &cfg);
                        audit.append("watch", "display-apply", &format!("{layout:?}"), if r.is_ok() { "ok" } else { "echec" }, &why)?;
                    } else {
                        { use std::io::Write; let _ = writeln!(std::io::stdout(), "[watch][simulation] appliquerait {layout:?}"); }
                    }
                }
                if now - last_repair >= 60 && screens_ok {
                    last_repair = now;
                    let present = screens.iter().any(|s| s.id == cfg.remote_id);
                    let st = c2c_core::watch::driver_status(&SystemRunner);
                    if let Some(r) = c2c_core::watch::repair_needed(present, st.as_deref()) {
                        if execute {
                            let ok = c2c_core::watch::run_repair(&SystemRunner, r);
                            { use std::io::Write; let _ = writeln!(std::io::stdout(), "[watch] reparation {r:?} -> {ok}"); }
                            audit.append("watch", "repair", r.task_name(), if ok { "ok" } else { "echec" }, "")?;
                        } else {
                            { use std::io::Write; let _ = writeln!(std::io::stdout(), "[watch][simulation] lancerait {}", r.task_name()); }
                        }
                    }
                }
                // Session utilisateur laissee « deconnectee » (fin d'un RDP) : on la ramene sur la console, sinon le
                // deverrouillage la reconnecte et fait redemarrer Sunshine (flux Moonlight coupe).
                let user = std::env::var("USERNAME").unwrap_or_default();
                let disc = if user.is_empty() { None } else { c2c_core::runner::CommandRunner::run(&SystemRunner, "quser", &[]).ok().and_then(|o| c2c_core::watch::disconnected_session(&o.stdout, &user)) };
                if console_guard.tick(now, disc.is_some()) {
                    if execute {
                        let ok = c2c_core::watch::run_console_return(&SystemRunner);
                        { use std::io::Write; let _ = writeln!(std::io::stdout(), "[watch] session deconnectee -> console : {ok}"); }
                        audit.append("watch", "console-return", c2c_core::watch::CONSOLE_TASK, if ok { "ok" } else { "echec" }, "")?;
                    } else {
                        { use std::io::Write; let _ = writeln!(std::io::stdout(), "[watch][simulation] lancerait {}", c2c_core::watch::CONSOLE_TASK); }
                    }
                }
                let hb = format!("{{\"pid\":{},\"session\":\"{:?}\",\"failures\":{}}}", std::process::id(), sess, w.failures());
                let _ = std::fs::write("c2c-health.json", hb);
                n += 1;
                if cycles != 0 && n >= cycles {
                    break;
                }
                std::thread::sleep(Duration::from_secs(3));
            }
        }
        Cmd::AgentServe => {
            use c2c_core::proto::{parse_pubkey, pubkey_hex, Authenticator, ClientPolicy};
            let cfg = load(&cli.config).map_err(anyhow::Error::msg)?;
            let bind = cfg.agent.bind.clone().context("[agent] bind manquant")?;
            // Aucun acces a 1Password : l'agent n'a que des cles PUBLIQUES (clients) et sa propre cle d'identite locale.
            let key_path = cfg.agent.host_key.clone().map(PathBuf::from).unwrap_or_else(|| c2c_core::hostkey::path_for(&cli.config));
            let (host, created) = c2c_core::hostkey::load_or_create(&key_path, &SystemRunner).map_err(anyhow::Error::msg)?;
            let mut clients = std::collections::HashMap::new();
            for c in &cfg.agent.clients {
                let pubkey = parse_pubkey(&c.pubkey).map_err(|e| anyhow::anyhow!("pubkey de {} : {e}", c.name))?;
                // `allowed` accepte des noms de droits ou des groupes : @read, @common, @all.
                clients.insert(c.name.clone(), ClientPolicy { pubkey, allowed: c2c_api::expand_allowed(&c.allowed) });
            }
            let auth = Authenticator::new(host.clone(), clients).map_err(anyhow::Error::msg)?;
            let listener = c2c_core::agent::bind(&bind).map_err(anyhow::Error::msg)?;
            let apub = pubkey_hex(&host);
            audit.append("agent", "start", &bind, "ok", &format!("pubkey={apub}{}", if created { " (cle d'identite creee)" } else { "" }))?;
            println!("agent a l'ecoute sur {bind}");
            println!("cle publique de l'agent : {apub}");
            let h = c2c_api::ApiHandler { ctx: Ctx { config: cli.config.clone(), audit: cli.audit.clone(), actor: "agent" } };
            let peers: Box<dyn c2c_core::agent::PeerCheck> = match &cfg.agent.owner {
                Some(o) => Box::new(c2c_core::agent::TailscaleOwner { owner: o.clone() }),
                None => Box::new(c2c_core::agent::AnyPeer),
            };
            loop {
                c2c_core::agent::serve_one(&listener, &auth, &h, peers.as_ref(), &audit, unix_now);
            }
        }
        Cmd::Remote { name, action, args } => {
            let cfg = load(&cli.config).map_err(anyhow::Error::msg)?;
            let m = cfg.machine(&name)?;
            let addr = m.agent_addr.clone().context("agent_addr manquant pour cette machine")?;
            let kref = m.key_ref.clone().context("key_ref manquant pour cette machine (cle privee de cet appareil)")?;
            let apub = c2c_core::proto::parse_pubkey(m.agent_pubkey.as_deref().context("agent_pubkey manquant pour cette machine")?).map_err(anyhow::Error::msg)?;
            let me = cfg.client_name.clone().context("client_name manquant")?;
            let key = c2c_api::client_key(&kref).map_err(anyhow::Error::msg)?;
            let args: Value = serde_json::from_str(&args).context("--args n'est pas du JSON")?;
            let r = c2c_core::agent::call(&addr, &key, &apub, &me, unix_now(), &action, args);
            audit.append("cli", &format!("remote:{action}"), &name, if r.is_ok() { "ok" } else { "echec" }, "")?;
            let r = r.map_err(|e| anyhow::anyhow!("{e:?}"))?;
            // Les commandes du registre repondent {ok, text, data} : on affiche le texte, comme en local.
            match (r.data.get("text").and_then(Value::as_str), r.data.get("ok").and_then(Value::as_bool)) {
                (Some(t), Some(ok)) => {
                    println!("{t}");
                    if !ok {
                        std::process::exit(1);
                    }
                }
                _ => println!("{}", serde_json::to_string_pretty(&r.data)?),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use c2c_api::{find, CLI_ONLY, COMMANDS};
    use clap::CommandFactory;

    /// Parite CLI/UI : toute sous-commande de la CLI est dans le registre, ou exclue avec une raison ; et inversement.
    #[test]
    fn every_cli_command_is_in_the_api_or_explicitly_excluded() {
        let cli = Cli::command();
        for sub in cli.get_subcommands() {
            let n = sub.get_name();
            if n == "help" {
                continue;
            }
            let in_api = COMMANDS.iter().any(|c| c.cli == n);
            let excluded = CLI_ONLY.iter().any(|(e, _)| *e == n);
            assert!(in_api || excluded, "la commande CLI `{n}` n'est ni dans le registre c2c-api ni dans CLI_ONLY : l'UI n'y aurait pas acces");
            assert!(!(in_api && excluded), "`{n}` est a la fois dans le registre et exclue");
        }
        for (e, _) in CLI_ONLY {
            assert!(cli.find_subcommand(e).is_some(), "CLI_ONLY cite `{e}` qui n'existe plus dans la CLI");
        }
    }

    #[test]
    fn every_registry_command_exists_in_the_cli_with_the_same_arguments() {
        let cli = Cli::command();
        for c in COMMANDS {
            if c.cli.is_empty() {
                continue;
            }
            let top = cli.find_subcommand(c.cli).unwrap_or_else(|| panic!("le registre cite la commande CLI `{}` qui n'existe pas", c.cli));
            let sub = match c.name.strip_prefix("sunshine.") {
                Some(rest) => top.find_subcommand(rest).unwrap_or_else(|| panic!("sous-commande `sunshine {rest}` absente de la CLI")),
                None => top,
            };
            let cli_args: Vec<String> = sub.get_arguments().map(|a| a.get_id().to_string()).filter(|i| i != "help" && i != "version").collect();
            for a in c.args {
                assert!(cli_args.iter().any(|i| i == a.name), "argument `{}` de `{}` absent de la CLI", a.name, c.name);
            }
            for i in &cli_args {
                assert!(c.args.iter().any(|a| a.name == i), "argument CLI `{i}` de `{}` absent du registre : l'UI ne pourrait pas le saisir", c.name);
            }
        }
        assert!(find("sunshine.pin").is_some());
    }

    #[test]
    fn sunshine_cli_subcommands_are_all_in_the_registry() {
        let cli = Cli::command();
        let top = cli.find_subcommand("sunshine").unwrap();
        for sub in top.get_subcommands() {
            let n = sub.get_name();
            if n == "help" {
                continue;
            }
            assert!(find(&format!("sunshine.{n}")).is_some(), "`sunshine {n}` absent du registre");
        }
    }
}
