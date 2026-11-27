//! Couche commune de C2C : registre des commandes (noms, risques, arguments), execution et acces systeme.
//! La CLI, l'agent et les applications (bureau, mobile) appellent tous `run` : memes fonctionnalites, un seul code.
pub mod exec;
pub mod platform;
pub mod keygen;
pub mod remote;
pub mod registry;

pub use exec::{run, run_agent, Ctx, Output};
pub use keygen::{keygen, Keygen};
pub use remote::{call_agent, client_key, run_on};
pub use registry::{all_rights, expand_allowed, find, right_for, risk_of, confirmation_error, ArgKind, ArgSpec, CommandSpec, Risk, Target, CLI_ONLY, COMMANDS};

use c2c_core::agent::Handler;
use serde_json::{json, Value};

/// Commandes historiques de l'agent, conservees telles quelles pour les clients existants.
const LEGACY: &[&str] = &["ping", "status", "display.apply"];

/// Handler de l'agent : execute n'importe quelle commande du registre, apres controle du droit par argument.
pub struct ApiHandler {
    pub ctx: Ctx,
}

impl Handler for ApiHandler {
    fn handle(&self, action: &str, args: &Value) -> Result<Value, String> {
        match action {
            "ping" => Ok(json!({"pong": true})),
            // Historique : etat des ecrans et de la session (forme inchangee).
            "status" => {
                let screens = platform::real_inspect()?;
                let session = platform::detect_session(&platform::stream_cfg(&self.ctx.config));
                Ok(json!({"screens": screens, "session": session}))
            }
            // Historique : applique toujours reellement.
            "display.apply" => {
                let mut a = args.clone();
                a["execute"] = json!(true);
                run_agent(&self.ctx, "display-apply", &a).map(|o| json!(o.text))
            }
            name => {
                let spec = find(name).ok_or("action inconnue")?;
                if spec.target == Target::Local {
                    return Err("cette commande s'execute ici, pas par l'agent".into());
                }
                let o = run_agent(&self.ctx, name, args)?;
                Ok(json!({"ok": o.ok, "text": o.text, "data": o.data}))
            }
        }
    }

    fn required_right(&self, action: &str, args: &Value) -> String {
        if LEGACY.contains(&action) {
            action.to_string()
        } else {
            right_for(action, args)
        }
    }
}
