//! Application bureau C2C (Tauri 2). Aucune logique metier ici : tout passe par `c2c-api`, la meme couche que la CLI et l'agent.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use c2c_api::{Ctx, Output};
use serde_json::{json, Value};
use std::path::PathBuf;

/// Configuration : `C2C_CONFIG`, sinon `c2c.toml` a cote de l'executable, sinon dans le dossier courant.
fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("C2C_CONFIG") {
        return PathBuf::from(p);
    }
    let beside = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("c2c.toml")));
    match beside {
        Some(p) if p.exists() => p,
        _ => PathBuf::from("c2c.toml"),
    }
}

fn ctx() -> Ctx {
    let config = config_path();
    let audit = config.with_file_name("c2c-audit.jsonl");
    Ctx { config, audit, actor: "ui" }
}

/// Les commandes et leurs arguments : l'interface se construit a partir de ce registre (parite avec la CLI).
#[tauri::command]
fn registry() -> Value {
    json!({ "commands": c2c_api::COMMANDS, "cli_only": c2c_api::CLI_ONLY })
}

#[tauri::command]
fn app_info() -> Value {
    let c = ctx();
    let cfg = c2c_api::platform::load(&c.config);
    json!({
        "config": c.config.display().to_string(),
        "config_ok": cfg.is_ok(),
        "config_error": cfg.as_ref().err(),
        "client_name": cfg.as_ref().ok().and_then(|c| c.client_name.clone()),
    })
}

#[tauri::command]
fn machines() -> Result<Value, String> {
    let cfg = c2c_api::platform::load(&ctx().config)?;
    let list: Vec<Value> = cfg
        .machines
        .iter()
        .map(|m| json!({ "name": m.name, "address": m.address, "agent": m.agent_addr.is_some(), "wakeable": m.mac.is_some() }))
        .collect();
    Ok(json!(list))
}

/// Niveau de risque de CET appel (read, common, destructive) : l'ecran decide de demander confirmation sans dupliquer la regle.
#[tauri::command]
fn risk(name: String, args: Value) -> Value {
    json!(c2c_api::risk_of(&name, &args))
}

/// Lance une commande du registre : en local (`machine` absent) ou par l'agent de la machine choisie.
/// Une action destructive exige `confirmed` : verifie ici aussi, pas seulement a l'ecran.
#[tauri::command]
async fn run_command(machine: Option<String>, name: String, args: Value, confirmed: bool) -> Result<Output, String> {
    if let Some(e) = c2c_api::confirmation_error(&name, &args, confirmed) {
        return Err(e);
    }
    tauri::async_runtime::spawn_blocking(move || c2c_api::run_on(&ctx(), machine.as_deref(), &name, &args))
        .await
        .map_err(|e| e.to_string())?
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![registry, app_info, machines, risk, run_command])
        .run(tauri::generate_context!())
        .expect("erreur au lancement de l'application C2C");
}
