//! Registre unique des commandes de C2C : nom, risque, arguments. CLI, agent et UI en derivent leurs droits et leurs ecrans,
//! et un test impose qu'aucune commande de la CLI ne manque ici (parite CLI/UI).
use serde::Serialize;
use serde_json::Value;
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    /// Lecture ou simulation : aucun effet.
    Read,
    /// Action courante, reversible ou sans danger pour la session.
    Common,
    /// Peut couper une session, retirer un appareil ou forcer l'etat : droit separe + confirmation dans l'UI.
    Destructive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    /// S'execute la ou l'on est (sonde depuis cette machine, reveil via le Pi).
    Local,
    /// S'execute sur la machine pilotee : en local si on est dessus, sinon par l'agent.
    Machine,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "values", rename_all = "lowercase")]
pub enum ArgKind {
    Text,
    Bool,
    Choice(&'static [&'static str]),
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ArgSpec {
    pub name: &'static str,
    pub kind: ArgKind,
    pub required: bool,
    pub help: &'static str,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct CommandSpec {
    /// Nom d'API (celui de l'agent) : `sunshine.pin`.
    pub name: &'static str,
    /// Sous-commande de premier niveau de la CLI (vide : pas d'equivalent direct, atteint via `remote`).
    pub cli: &'static str,
    pub summary: &'static str,
    /// Risque du droit de base.
    pub risk: Risk,
    /// Variantes de droit selon les arguments : (suffixe, risque). Ex. (`set`, Common) donne `display-profile!set`.
    pub variants: &'static [(&'static str, Risk)],
    /// Sans `execute` la commande simule : droit `<nom>!plan`, en lecture.
    pub has_execute: bool,
    pub target: Target,
    pub args: &'static [ArgSpec],
}

const fn a(name: &'static str, kind: ArgKind, required: bool, help: &'static str) -> ArgSpec {
    ArgSpec { name, kind, required, help }
}

const LAYOUT: ArgKind = ArgKind::Choice(&["local", "remote"]);
const MODE: ArgKind = ArgKind::Choice(&["auto", "local", "remote"]);

const fn read(name: &'static str, cli: &'static str, summary: &'static str, target: Target) -> CommandSpec {
    CommandSpec { name, cli, summary, risk: Risk::Read, variants: &[], has_execute: false, target, args: &[] }
}

pub const COMMANDS: &[CommandSpec] = &[
    read("ping", "", "L'agent repond-il ?", Target::Machine),
    read("status", "status", "Etat des machines (sonde TCP depuis ici).", Target::Local),
    CommandSpec {
        name: "wake",
        cli: "wake",
        summary: "Reveille une machine via le Pi.",
        risk: Risk::Common,
        variants: &[],
        has_execute: true,
        target: Target::Local,
        args: &[a("name", ArgKind::Text, true, "Machine a reveiller"), a("execute", ArgKind::Bool, false, "Envoyer reellement (sinon simulation)")],
    },
    CommandSpec {
        name: "update",
        cli: "update",
        summary: "Verifie (et installe avec execute) la derniere release GitHub de C2C sur cette machine.",
        risk: Risk::Common,
        variants: &[],
        has_execute: true,
        target: Target::Local,
        args: &[a("execute", ArgKind::Bool, false, "Installer reellement (sinon simple verification)")],
    },
    read("agent-key", "agent-key", "Cle publique de l'agent de cette machine (a epingler dans la config des clients).", Target::Machine),
    read("net-health", "net-health", "Sante du reseau sortant (IPv4, IPv6).", Target::Machine),
    read("health-check", "health-check", "Verification de sante de la machine (services, taches, session, Sunshine, pare-feu, reseau).", Target::Machine),
    read("session-status", "session-status", "Une session distante est-elle active ?", Target::Machine),
    read("display-status", "display-status", "Etat reel des ecrans.", Target::Machine),
    CommandSpec {
        name: "display-apply",
        cli: "display-apply",
        summary: "Applique une disposition d'ecran (local ou ecran virtuel).",
        risk: Risk::Common,
        variants: &[("force", Risk::Destructive)],
        has_execute: true,
        target: Target::Machine,
        args: &[
            a("layout", LAYOUT, true, "Disposition voulue"),
            a("execute", ArgKind::Bool, false, "Appliquer reellement (sinon simulation)"),
            a("force", ArgKind::Bool, false, "Passer en Local pendant une session distante"),
        ],
    },
    CommandSpec {
        name: "display-profile",
        cli: "display-profile",
        summary: "Profil de l'ecran virtuel (liste, ou active un profil).",
        risk: Risk::Read,
        variants: &[("set", Risk::Common)],
        has_execute: false,
        target: Target::Machine,
        args: &[a("name", ArgKind::Text, false, "Profil a activer, ou defaut. Absent : liste")],
    },
    CommandSpec {
        name: "display-mode",
        cli: "display-mode",
        summary: "Disposition imposee a la surveillance : auto, local ou remote.",
        risk: Risk::Read,
        variants: &[("set", Risk::Common)],
        has_execute: false,
        target: Target::Machine,
        args: &[a("mode", MODE, false, "Mode a imposer. Absent : affiche")],
    },
    read("audit-verify", "audit-verify", "Verifie l'integrite du journal d'audit.", Target::Machine),
    CommandSpec {
        name: "audit-show",
        cli: "audit-show",
        summary: "Affiche le journal d'audit.",
        risk: Risk::Read,
        variants: &[],
        has_execute: false,
        target: Target::Machine,
        args: &[a("limit", ArgKind::Text, false, "Nombre d'entrees les plus recentes")],
    },
    read("sunshine.clients", "sunshine", "Clients Moonlight appaires.", Target::Machine),
    read("sunshine.pending", "sunshine", "Demandes d'appairage en attente de PIN.", Target::Machine),
    CommandSpec {
        name: "sunshine.pin",
        cli: "sunshine",
        summary: "Appaire un client Moonlight avec son PIN.",
        risk: Risk::Common,
        variants: &[],
        has_execute: true,
        target: Target::Machine,
        args: &[
            a("pin", ArgKind::Text, true, "PIN a 4 chiffres affiche par Moonlight"),
            a("name", ArgKind::Text, false, "Nom du client"),
            a("pairing_id", ArgKind::Text, false, "Identifiant de la demande (sinon la seule en attente)"),
            a("execute", ArgKind::Bool, false, "Appairer reellement (sinon simulation)"),
        ],
    },
    CommandSpec {
        name: "sunshine.unpair",
        cli: "sunshine",
        summary: "Retire un client appaire.",
        risk: Risk::Destructive,
        variants: &[],
        has_execute: true,
        target: Target::Machine,
        args: &[a("uuid", ArgKind::Text, true, "UUID du client"), a("execute", ArgKind::Bool, false, "Retirer reellement (sinon simulation)")],
    },
];

/// Sous-commandes de la CLI sans equivalent d'ecran, avec la raison.
pub const CLI_ONLY: &[(&str, &str)] = &[
    ("watch", "service d'arriere-plan (tache planifiee)"),
    ("agent-serve", "service d'arriere-plan (tache planifiee)"),
    ("remote", "l'UI l'integre : toute commande se lance sur la machine choisie"),
    ("display-plan", "outil de mise au point hors ligne (fichier d'ecrans)"),
    ("keygen", "configuration d'un appareil : sa cle privee est creee dans le 1Password de CET appareil"),
];

pub fn find(name: &str) -> Option<&'static CommandSpec> {
    COMMANDS.iter().find(|c| c.name == name)
}

fn truthy(args: &Value, key: &str) -> bool {
    args.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn present(args: &Value, key: &str) -> bool {
    args.get(key).map_or(false, |v| !v.is_null() && v.as_str().map_or(true, |s| !s.is_empty()))
}

/// Droit exige pour appeler `name` avec ces arguments. Inconnu : le nom tel quel (l'agent refusera).
pub fn right_for(name: &str, args: &Value) -> String {
    let Some(c) = find(name) else { return name.to_string() };
    if c.has_execute && !truthy(args, "execute") {
        return format!("{name}!plan");
    }
    match name {
        "display-apply" if truthy(args, "force") => "display-apply!force".into(),
        "display-profile" if present(args, "name") => "display-profile!set".into(),
        "display-mode" if present(args, "mode") => "display-mode!set".into(),
        _ => name.to_string(),
    }
}

/// Niveau de risque de cet appel precis (ex. `display-apply` avec `force` : destructif). Inconnu : destructif, par prudence.
pub fn risk_of(name: &str, args: &Value) -> Risk {
    let right = right_for(name, args);
    all_rights().into_iter().find(|(n, _)| *n == right).map(|(_, r)| r).unwrap_or(Risk::Destructive)
}

/// Garde de confirmation : un appel destructif exige `confirmed`. A appliquer cote application (ecran ET backend).
pub fn confirmation_error(name: &str, args: &Value, confirmed: bool) -> Option<String> {
    (risk_of(name, args) == Risk::Destructive && !confirmed).then(|| "action destructive : confirmation explicite requise".to_string())
}

/// Tous les droits possibles avec leur niveau de risque.
pub fn all_rights() -> Vec<(String, Risk)> {
    let mut v = vec![];
    for c in COMMANDS {
        v.push((c.name.to_string(), c.risk));
        if c.has_execute {
            v.push((format!("{}!plan", c.name), Risk::Read));
        }
        for (s, r) in c.variants {
            v.push((format!("{}!{s}", c.name), *r));
        }
    }
    v
}

/// Developpe la liste `allowed` d'un client : `@read`, `@common` (lecture + courant), `@all`, ou noms de droits tels quels.
pub fn expand_allowed(list: &[String]) -> HashSet<String> {
    let mut out = HashSet::new();
    for item in list {
        let upto = match item.as_str() {
            "@read" => Some(0),
            "@common" => Some(1),
            "@all" => Some(2),
            _ => None,
        };
        match upto {
            Some(max) => {
                for (n, r) in all_rights() {
                    let level = match r {
                        Risk::Read => 0,
                        Risk::Common => 1,
                        Risk::Destructive => 2,
                    };
                    if level <= max {
                        out.insert(n);
                    }
                }
            }
            None => {
                out.insert(item.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rights_depend_on_arguments() {
        assert_eq!(right_for("display-apply", &json!({"layout": "remote"})), "display-apply!plan");
        assert_eq!(right_for("display-apply", &json!({"layout": "remote", "execute": true})), "display-apply");
        assert_eq!(right_for("display-apply", &json!({"layout": "local", "execute": true, "force": true})), "display-apply!force");
        assert_eq!(right_for("display-profile", &json!({})), "display-profile");
        assert_eq!(right_for("display-profile", &json!({"name": "fhd"})), "display-profile!set");
        assert_eq!(right_for("display-mode", &json!({"mode": "remote"})), "display-mode!set");
        assert_eq!(right_for("sunshine.unpair", &json!({"uuid": "x"})), "sunshine.unpair!plan");
        assert_eq!(right_for("sunshine.unpair", &json!({"uuid": "x", "execute": true})), "sunshine.unpair");
        assert_eq!(right_for("inconnu", &json!({})), "inconnu");
    }

    #[test]
    fn risk_follows_the_arguments_and_unknown_is_destructive() {
        assert_eq!(risk_of("display-apply", &json!({"layout": "local"})), Risk::Read);
        assert_eq!(risk_of("display-apply", &json!({"layout": "remote", "execute": true})), Risk::Common);
        assert_eq!(risk_of("display-apply", &json!({"layout": "local", "execute": true, "force": true})), Risk::Destructive);
        assert_eq!(risk_of("sunshine.unpair", &json!({"uuid": "x", "execute": true})), Risk::Destructive);
        assert_eq!(risk_of("sunshine.unpair", &json!({"uuid": "x"})), Risk::Read);
        assert_eq!(risk_of("display-profile", &json!({"name": "fhd"})), Risk::Common);
        assert_eq!(risk_of("inconnu", &json!({})), Risk::Destructive);
    }

    #[test]
    fn destructive_calls_need_confirmation() {
        let force = json!({"layout": "local", "execute": true, "force": true});
        assert!(confirmation_error("display-apply", &force, false).is_some());
        assert!(confirmation_error("display-apply", &force, true).is_none());
        assert!(confirmation_error("display-apply", &json!({"layout": "remote", "execute": true}), false).is_none());
        assert!(confirmation_error("inconnu", &json!({}), false).is_some());
    }

    #[test]
    fn groups_expand_by_risk_and_never_leak_upwards() {
        let read = expand_allowed(&["@read".into()]);
        assert!(read.contains("display-status") && read.contains("display-apply!plan") && read.contains("display-profile"));
        assert!(!read.contains("display-apply") && !read.contains("wake") && !read.contains("sunshine.unpair"));
        let common = expand_allowed(&["@common".into()]);
        assert!(common.contains("wake") && common.contains("display-apply") && common.contains("sunshine.pin") && common.contains("display-profile!set"));
        assert!(!common.contains("display-apply!force") && !common.contains("sunshine.unpair"));
        let all = expand_allowed(&["@all".into()]);
        assert!(all.contains("display-apply!force") && all.contains("sunshine.unpair"));
        let plain = expand_allowed(&["ping".into(), "status".into()]);
        assert_eq!(plain.len(), 2);
    }

    #[test]
    fn names_and_rights_are_unique_and_destructive_exists() {
        let mut names: Vec<&str> = COMMANDS.iter().map(|c| c.name).collect();
        names.sort();
        let n = names.len();
        names.dedup();
        assert_eq!(n, names.len());
        let rights = all_rights();
        assert!(rights.iter().any(|(n, r)| n == "display-apply!force" && *r == Risk::Destructive));
        let mut ids: Vec<&String> = rights.iter().map(|(n, _)| n).collect();
        ids.sort();
        let m = ids.len();
        ids.dedup();
        assert_eq!(m, ids.len());
    }
}
