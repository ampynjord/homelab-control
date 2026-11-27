//! Verification de sante apres redemarrage (lecture seule) : services, taches, session console, Sunshine, pare-feu, reseau.
//! Un seul PowerShell produit des lignes `nom|OK|detail` ; l'analyse est pure et testee.
use crate::runner::CommandRunner;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// Script lecture seule. Chaque controle imprime `nom|OK|detail` ou `nom|KO|detail`.
pub const SCRIPT: &str = r#"[Console]::OutputEncoding=[Text.Encoding]::UTF8
$ErrorActionPreference='SilentlyContinue'
function chk($n,$ok,$d){ "$n|$(if($ok){'OK'}else{'KO'})|$d" }
foreach($s in 'SunshineService','Tailscale','sshd','TermService'){ $v=Get-Service $s; chk "service $s" ($v.Status -eq 'Running') "$($v.Status)" }
$t=Get-ScheduledTask -TaskName 'C2C Watch'; chk 'tache C2C Watch' ($t.State -eq 'Running') "$($t.State)"
$t=Get-ScheduledTask -TaskName 'C2C ramener console'; chk 'tache C2C ramener console' ($null -ne $t) "$($t.State)"
$q=(quser 2>$null) -join "`n"; chk 'session sur la console' ($q -match "(?m)^\s*>?\s*$($env:USERNAME)\s+console\s") 'session utilisateur active sur la console'
chk 'processus sunshine' ($null -ne (Get-Process sunshine)) ''
chk 'port Sunshine 47989' ($null -ne (Get-NetTCPConnection -State Listen -LocalPort 47989)) ''
$f=Get-NetFirewallRule -DisplayName 'C2C Sunshine (tailnet)'; chk 'pare-feu Sunshine (tailnet)' ($f.Enabled -eq 'True') ''
$j=& 'C:\Program Files\Tailscale\tailscale.exe' status --json | ConvertFrom-Json; chk 'tailscale connecte' ($j.BackendState -eq 'Running') "$($j.BackendState)"
$c=& curl.exe -4 -s -m 5 -o NUL -w '%{http_code}' http://1.1.1.1; chk 'IPv4 sortant' ($c -match '^[23]') "code $c"
"#;

pub fn parse(stdout: &str) -> Vec<Check> {
    stdout
        .lines()
        .filter_map(|l| {
            let mut p = l.trim().splitn(3, '|');
            let name = p.next()?.trim();
            let state = p.next()?.trim();
            let detail = p.next().unwrap_or("").trim();
            match state {
                "OK" | "KO" if !name.is_empty() => Some(Check { name: name.to_string(), ok: state == "OK", detail: detail.to_string() }),
                _ => None,
            }
        })
        .collect()
}

pub fn run(runner: &dyn CommandRunner) -> Vec<Check> {
    match runner.run("powershell", &["-NoProfile".into(), "-NonInteractive".into(), "-Command".into(), SCRIPT.into()]) {
        Ok(o) => parse(&o.stdout),
        Err(_) => vec![],
    }
}

/// Aucun controle lu = echec (on ne declare jamais « sain » sans rien avoir verifie).
pub fn all_ok(checks: &[Check]) -> bool {
    !checks.is_empty() && checks.iter().all(|c| c.ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    #[test]
    fn parses_ok_ko_and_ignores_noise() {
        let c = parse("service Tailscale|OK|Running\nbruit sans separateur\nport Sunshine 47989|KO|\nx|PEUT-ETRE|y\n|OK|vide\n");
        assert_eq!(c.len(), 2);
        assert_eq!(c[0], Check { name: "service Tailscale".into(), ok: true, detail: "Running".into() });
        assert!(!c[1].ok);
        assert_eq!(c[1].detail, "");
    }

    #[test]
    fn detail_may_contain_pipes() {
        let c = parse("a|KO|x|y");
        assert_eq!(c[0].detail, "x|y");
    }

    #[test]
    fn healthy_only_when_every_check_is_ok_and_there_is_at_least_one() {
        assert!(!all_ok(&[]));
        assert!(all_ok(&parse("a|OK|\nb|OK|")));
        assert!(!all_ok(&parse("a|OK|\nb|KO|")));
    }

    #[test]
    fn run_uses_one_powershell_call_and_handles_failure() {
        let r = RecordingRunner::ok("a|OK|d\n");
        assert!(all_ok(&run(&r)));
        let calls = r.calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "powershell");
        assert!(!all_ok(&run(&RecordingRunner::failing(1))));
    }
}
