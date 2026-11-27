//! Detection de session distante Parsec (port de SessionState.ps1). Logique pure : le contenu du journal,
//! l'heure et les processus sont fournis par l'appelant. Heures locales naives, en secondes.
use crate::runner::CommandRunner;
use std::collections::{HashMap, HashSet};

/// "2026-11-24 13:31:32" -> secondes (calendrier civil, sans fuseau).
pub fn parse_ts(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || (b[10] != b' ' && b[10] != b'T') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, m, d, hh, mm, ss) = (n(0..4)?, n(5..7)?, n(8..10)?, n(11..13)?, n(14..16)?, n(17..19)?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || hh > 23 || mm > 59 || ss > 60 {
        return None;
    }
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + hh * 3600 + mm * 60 + ss)
}

#[derive(Debug, Default)]
struct Owner {
    start: i64,
    guests: HashSet<String>,
    last_activity: Option<i64>,
    last_record: i64,
}

#[derive(Debug)]
pub struct SessionState {
    boot: i64,
    owners: HashMap<u32, Owner>,
}

impl SessionState {
    pub fn new(boot: i64) -> Self {
        Self { boot, owners: HashMap::new() }
    }

    /// Processus parsecd.exe vivants : pid -> heure de demarrage.
    pub fn sync_processes(&mut self, procs: &HashMap<u32, i64>) {
        self.owners.retain(|pid, o| procs.get(pid) == Some(&o.start));
        for (pid, start) in procs {
            self.owners.entry(*pid).or_insert(Owner { start: *start, last_record: i64::MIN, ..Default::default() });
        }
    }

    pub fn update(&mut self, content: &str, now: i64) {
        for line in content.lines() {
            let Some(rest) = line.strip_prefix('[') else { continue };
            let Some((stamp, rest)) = rest.split_once("] [") else { continue };
            let Some(ts) = parse_ts(stamp) else { continue };
            let Some((head, body)) = rest.split_once("] ") else { continue };
            let Some(pid) = head.split(',').next().and_then(|p| p.parse::<u32>().ok()) else { continue };
            let Some(o) = self.owners.get_mut(&pid) else { continue };
            if ts < self.boot || ts < o.start - 1 || ts < o.last_record || ts > now + 60 {
                continue;
            }
            let mut words = body.splitn(2, ' ');
            let (first, tail) = (words.next().unwrap_or(""), words.next().unwrap_or(""));
            if tail.starts_with("connected.") {
                o.last_record = ts;
                o.guests.insert(first.to_string());
                o.last_activity = Some(ts);
            } else if tail.starts_with("disconnected.") {
                o.last_record = ts;
                o.guests.remove(first);
                if o.guests.is_empty() {
                    o.last_activity = None;
                }
            } else if body.starts_with('[') && body.contains("] FPS:") {
                // Meme 0 FPS = flux vivant en attente de reprise de capture.
                o.last_record = ts;
                o.last_activity = Some(ts);
            }
        }
    }

    /// Une activite perdue ne peut pas garder l'ecran virtuel actif indefiniment (fenetre 120 s).
    pub fn is_remote(&self, now: i64) -> bool {
        self.owners.values().any(|o| matches!(o.last_activity, Some(a) if (-60..120).contains(&(now - a))))
    }
}

/// Commande PowerShell fixe : heure locale puis processus parsecd (`pid iso-date`).
const PS_SCRIPT: &str = "Write-Output ('NOW ' + (Get-Date).ToString('s')); \
Get-CimInstance Win32_Process -Filter \"Name='parsecd.exe'\" | ForEach-Object { 'PROC ' + $_.ProcessId + ' ' + $_.CreationDate.ToString('s') }; \
'BOOT ' + (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToString('s')";

pub fn parse_probe(out: &str) -> Option<(i64, i64, HashMap<u32, i64>)> {
    let (mut now, mut boot, mut procs) = (None, None, HashMap::new());
    for l in out.lines() {
        let l = l.trim();
        if let Some(v) = l.strip_prefix("NOW ") {
            now = parse_ts(v);
        } else if let Some(v) = l.strip_prefix("BOOT ") {
            boot = parse_ts(v);
        } else if let Some(v) = l.strip_prefix("PROC ") {
            let (pid, d) = v.split_once(' ')?;
            procs.insert(pid.parse().ok()?, parse_ts(d)?);
        }
    }
    Some((now?, boot?, procs))
}

/// Vrai si une session Parsec est active. En cas de doute (erreur), `None` : l'appelant suppose active.
pub fn parsec_session_active(runner: &dyn CommandRunner, log_text: &str) -> Option<bool> {
    let args = ["-NoProfile".to_string(), "-Command".to_string(), PS_SCRIPT.to_string()];
    let out = runner.run("powershell", &args).ok().filter(|o| o.status == 0)?;
    let (now, boot, procs) = parse_probe(&out.stdout)?;
    let mut st = SessionState::new(boot);
    st.sync_processes(&procs);
    st.update(log_text, now);
    Some(st.is_remote(now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runner::RecordingRunner;

    const BOOT: &str = "2026-11-24 08:00:00";

    fn state(pid: u32, start: &str) -> SessionState {
        let mut s = SessionState::new(parse_ts(BOOT).unwrap());
        s.sync_processes(&HashMap::from([(pid, parse_ts(start).unwrap())]));
        s
    }
    fn t(s: &str) -> i64 {
        parse_ts(s).unwrap()
    }

    #[test]
    fn timestamps() {
        assert_eq!(t("1970-01-01 00:00:00"), 0);
        assert_eq!(t("2026-11-24 13:31:33") - t("2026-11-24 13:31:32"), 1);
        assert_eq!(t("2026-03-01 00:00:00") - t("2026-02-28 00:00:00"), 86400);
        assert!(parse_ts("n'importe quoi").is_none());
    }

    #[test]
    fn connect_then_disconnect() {
        let mut s = state(100, "2026-11-24 09:00:00");
        let now = t("2026-11-24 10:00:10");
        s.update("[2026-11-24 10:00:00] [100,D] guest#1 connected.\n", now);
        assert!(s.is_remote(now));
        s.update("[2026-11-24 10:00:05] [100,D] guest#1 disconnected.\n", now);
        assert!(!s.is_remote(now));
    }

    #[test]
    fn fps_keeps_session_alive_and_staleness_expires() {
        let mut s = state(100, "2026-11-24 09:00:00");
        s.update("[2026-11-24 10:00:00] [100,D] g connected.\n[2026-11-24 10:05:00] [100,D] [1] FPS:0.0/60\n", t("2026-11-24 10:05:01"));
        assert!(s.is_remote(t("2026-11-24 10:05:30")));
        assert!(!s.is_remote(t("2026-11-24 10:07:30")), "perdu apres 120 s sans activite");
    }

    #[test]
    fn ignores_other_pids_old_lines_and_future_lines() {
        let mut s = state(100, "2026-11-24 09:00:00");
        let now = t("2026-11-24 10:00:10");
        s.update("[2026-11-24 10:00:00] [999,D] g connected.\n", now);
        s.update("[2026-11-24 07:00:00] [100,D] g connected.\n", now); // avant le demarrage
        s.update("[2026-11-24 11:00:00] [100,D] g connected.\n", now); // futur
        assert!(!s.is_remote(now));
    }

    #[test]
    fn dead_process_drops_session() {
        let mut s = state(100, "2026-11-24 09:00:00");
        let now = t("2026-11-24 10:00:10");
        s.update("[2026-11-24 10:00:00] [100,D] g connected.\n", now);
        s.sync_processes(&HashMap::new());
        assert!(!s.is_remote(now));
    }

    #[test]
    fn probe_parsing_and_end_to_end() {
        let out = "NOW 2026-11-24T10:00:10\nPROC 100 2026-11-24T09:00:00\nBOOT 2026-11-24T08:00:00\n";
        let r = RecordingRunner::ok(out);
        let log = "[2026-11-24 10:00:00] [100,D] g connected.\n";
        assert_eq!(parsec_session_active(&r, log), Some(true));
        assert_eq!(parsec_session_active(&RecordingRunner::ok(out), ""), Some(false));
    }

    #[test]
    fn probe_failure_is_unknown_not_false() {
        assert_eq!(parsec_session_active(&RecordingRunner::failing(1), ""), None);
        assert_eq!(parsec_session_active(&RecordingRunner::ok("garbage"), ""), None);
    }
}
