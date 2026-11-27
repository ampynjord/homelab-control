//! Decision de la surveillance (remplace la boucle de `display.ps1 -Mode Watch`) : logique pure, horloge injectee.
//! Regles reprises : connexion immediate, deconnexion seulement apres 3 s stables, nouvelle tentative
//! avec temporisation exponentielle (5 s x 2^n, plafonnee a 60 s), jamais d'action si la session est inconnue.
use crate::display::Layout;
use crate::runner::CommandRunner;

const DISCONNECT_STABLE_SECS: i64 = 3;

/// Nombre d'echecs consecutifs apres lequel la surveillance cesse de reappliquer.
pub const MAX_FAILURES: u32 = 8;

#[derive(Debug, Default)]
pub struct Watcher {
    adopted: Option<bool>,
    candidate: Option<bool>,
    candidate_since: i64,
    last_attempt: Option<i64>,
    failures: u32,
}

impl Watcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn failures(&self) -> u32 {
        self.failures
    }

    pub fn desired(&self) -> Option<Layout> {
        self.adopted.map(|r| if r { Layout::Remote } else { Layout::Local })
    }

    fn delay(&self) -> i64 {
        (5i64 * (1i64 << self.failures.min(4))).min(60)
    }

    /// `session` : Some(actif?) ou None si la detection a echoue (on ne touche a rien).
    /// `correct` : la topologie courante correspond-elle deja a la disposition voulue ?
    /// Retourne la disposition a appliquer maintenant, le cas echeant.
    pub fn tick(&mut self, now: i64, session: Option<bool>, correct: impl Fn(Layout) -> bool) -> Option<Layout> {
        let want = session?;
        if self.candidate != Some(want) {
            self.candidate = Some(want);
            self.candidate_since = now;
        }
        if self.adopted != Some(want) && (want || now - self.candidate_since >= DISCONNECT_STABLE_SECS) {
            self.adopted = Some(want);
            self.last_attempt = None;
            self.failures = 0;
        }
        let layout = self.desired()?;
        if correct(layout) {
            return None;
        }
        // Trop d'echecs : on arrete de toucher a l'affichage (evite le clignotement) jusqu'au prochain changement de session.
        if self.failures >= MAX_FAILURES {
            return None;
        }
        if self.last_attempt.map_or(true, |t| now - t >= self.delay()) {
            self.last_attempt = Some(now);
            return Some(layout);
        }
        None
    }

    pub fn report(&mut self, ok: bool) {
        self.failures = if ok { 0 } else { self.failures + 1 };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Repair {
    /// Tache existante `ParsecVDD Repair` (redemarre le pilote).
    RestartDriver,
    /// Tache existante `ParsecVDisplay Autostart` (recree l'ecran virtuel).
    CreateVirtualDisplay,
}

impl Repair {
    pub fn task_name(self) -> &'static str {
        match self {
            Repair::RestartDriver => "ParsecVDD Repair",
            Repair::CreateVirtualDisplay => "ParsecVDisplay Autostart",
        }
    }
}

/// `driver_status` : etat PnP de ROOT-DISPLAY-0000 (None = pilote introuvable/inconnu).
pub fn repair_needed(virtual_present: bool, driver_status: Option<&str>) -> Option<Repair> {
    match driver_status {
        Some(st) if st != "OK" => Some(Repair::RestartDriver),
        _ if !virtual_present => Some(Repair::CreateVirtualDisplay),
        _ => None,
    }
}

pub fn driver_status(runner: &dyn CommandRunner) -> Option<String> {
    let cmd = r"(Get-PnpDevice -InstanceId 'ROOT\DISPLAY\0000' -ErrorAction SilentlyContinue).Status";
    let out = runner.run("powershell", &["-NoProfile".into(), "-Command".into(), cmd.into()]).ok()?;
    let t = out.stdout.trim().to_string();
    (out.status == 0 && !t.is_empty()).then_some(t)
}

/// Lance une tache planifiee existante (aucune creation, aucune modification).
pub fn run_repair(runner: &dyn CommandRunner, r: Repair) -> bool {
    runner.run("schtasks", &["/run".into(), "/tn".into(), r.task_name().into()]).map(|o| o.status == 0).unwrap_or(false)
}

/// Tache planifiee SYSTEM (creee par `scripts/console-task.ps1`) qui lance `tscon 1 /dest:console`.
pub const CONSOLE_TASK: &str = "C2C ramener console";

/// ID de la session de `user` si `quser` la montre en etat deconnecte (FR « Deco », EN « Disc »).
/// Une session RDP active ou la console active ne comptent pas : on ne coupe jamais un RDP en cours.
pub fn disconnected_session(quser: &str, user: &str) -> Option<u32> {
    for line in quser.lines() {
        let mut toks = line.trim_start_matches(|c: char| c == '>' || c.is_whitespace()).split_whitespace();
        if !toks.next().map_or(false, |t| t.eq_ignore_ascii_case(user)) {
            continue;
        }
        let rest: Vec<&str> = toks.collect();
        let pos = rest.iter().position(|t| t.parse::<u32>().is_ok())?;
        let id: u32 = rest[pos].parse().ok()?;
        let state = rest.get(pos + 1)?.to_lowercase();
        // « Deco » peut arriver avec un accent mal decode (codepage OEM) : on ne compare que debut et fin.
        let disc = state.starts_with("disc") || (state.starts_with('d') && state.ends_with("co"));
        return disc.then_some(id);
    }
    None
}

pub fn run_console_return(runner: &dyn CommandRunner) -> bool {
    runner.run("schtasks", &["/run".into(), "/tn".into(), CONSOLE_TASK.into()]).map(|o| o.status == 0).unwrap_or(false)
}

/// Garde : agit seulement si la session reste deconnectee `STABLE` secondes, puis au plus une fois par `COOLDOWN` (30 s).
#[derive(Debug, Default)]
pub struct ConsoleGuard {
    since: Option<i64>,
    last: Option<i64>,
}

impl ConsoleGuard {
    const STABLE: i64 = 6;
    const COOLDOWN: i64 = 30;

    pub fn tick(&mut self, now: i64, disconnected: bool) -> bool {
        if !disconnected {
            self.since = None;
            return false;
        }
        let since = *self.since.get_or_insert(now);
        if now - since >= Self::STABLE && self.last.map_or(true, |t| now - t >= Self::COOLDOWN) {
            self.last = Some(now);
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FR_ACTIVE: &str = " UTILISATEUR           SESSION            ID  ETAT   TEMPS INACT TEMPS SESSION\n>user                 console             1  Actif           1  25/11/2026 10:30";
    const FR_DISC: &str = " UTILISATEUR           SESSION            ID  ETAT   TEMPS INACT TEMPS SESSION\n user                                     1  Déco           5  25/11/2026 10:30";
    const EN_DISC: &str = " USERNAME   SESSIONNAME   ID  STATE   IDLE TIME  LOGON TIME\n user                  1  Disc          3  11/25/2026 10:30 AM";
    const RDP_ACTIVE: &str = " USERNAME   SESSIONNAME   ID  STATE\n>user     rdp-tcp#3      1  Active";

    #[test]
    fn detects_only_a_disconnected_session_of_the_user() {
        assert_eq!(disconnected_session(FR_ACTIVE, "user"), None);
        assert_eq!(disconnected_session(FR_DISC, "user"), Some(1));
        assert_eq!(disconnected_session(&FR_DISC.replace("Déco", "D\u{fffd}co"), "user"), Some(1));
        assert_eq!(disconnected_session(EN_DISC, "USER"), Some(1));
        assert_eq!(disconnected_session(RDP_ACTIVE, "user"), None);
        assert_eq!(disconnected_session(FR_DISC, "autre"), None);
        assert_eq!(disconnected_session("", "user"), None);
    }

    #[test]
    fn console_guard_waits_and_rate_limits() {
        let mut g = ConsoleGuard::default();
        assert!(!g.tick(0, true));
        assert!(!g.tick(5, true));
        assert!(g.tick(6, true));
        assert!(!g.tick(9, true), "pas de relance avant le delai");
        assert!(!g.tick(20, true), "delai de 30 s depuis la derniere action");
        assert!(g.tick(40, true));
        assert!(!g.tick(50, false));
        assert!(!g.tick(51, true));
        assert!(!g.tick(60, true), "stable depuis 9 s mais delai de 30 s non ecoule");
        assert!(g.tick(71, true));
    }

    #[test]
    fn console_return_runs_only_the_named_task() {
        let r = crate::runner::RecordingRunner::ok("");
        assert!(run_console_return(&r));
        assert_eq!(r.calls()[0], ("schtasks".to_string(), vec!["/run".to_string(), "/tn".to_string(), "C2C ramener console".to_string()]));
    }

    fn never(_: Layout) -> bool {
        false
    }

    #[test]
    fn connect_is_immediate() {
        let mut w = Watcher::new();
        assert_eq!(w.tick(100, Some(true), never), Some(Layout::Remote));
    }

    #[test]
    fn disconnect_waits_three_stable_seconds() {
        let mut w = Watcher::new();
        w.tick(100, Some(true), |_| true);
        let remote_ok = |l: Layout| l == Layout::Remote;
        assert_eq!(w.tick(101, Some(false), remote_ok), None);
        assert_eq!(w.tick(103, Some(false), remote_ok), None);
        assert_eq!(w.tick(104, Some(false), remote_ok), Some(Layout::Local));
    }

    #[test]
    fn flapping_never_triggers_local() {
        let mut w = Watcher::new();
        w.tick(100, Some(true), |_| true);
        for t in 101..120 {
            let s = t % 2 == 0;
            let r = w.tick(t, Some(s), |_| true);
            assert_eq!(r, None);
        }
        assert_eq!(w.desired(), Some(Layout::Remote));
    }

    #[test]
    fn unknown_session_does_nothing() {
        let mut w = Watcher::new();
        assert_eq!(w.tick(100, None, never), None);
        w.tick(101, Some(true), |_| true);
        assert_eq!(w.tick(500, None, never), None);
        assert_eq!(w.desired(), Some(Layout::Remote));
    }

    #[test]
    fn no_action_when_already_correct() {
        let mut w = Watcher::new();
        assert_eq!(w.tick(100, Some(true), |l| l == Layout::Remote), None);
    }

    #[test]
    fn exponential_backoff_capped_at_60s() {
        let mut w = Watcher::new();
        let mut t = 100;
        assert!(w.tick(t, Some(true), never).is_some());
        let mut gaps = vec![];
        for _ in 0..6 {
            w.report(false);
            let start = t;
            loop {
                t += 1;
                if w.tick(t, Some(true), never).is_some() {
                    break;
                }
            }
            gaps.push(t - start);
        }
        assert_eq!(gaps, vec![10, 20, 40, 60, 60, 60]);
    }

    #[test]
    fn success_resets_backoff() {
        let mut w = Watcher::new();
        w.tick(100, Some(true), never);
        w.report(false);
        w.report(true);
        assert_eq!(w.failures(), 0);
        assert_eq!(w.tick(105, Some(true), never), Some(Layout::Remote));
    }

    #[test]
    fn repair_decisions() {
        assert_eq!(repair_needed(true, Some("OK")), None);
        assert_eq!(repair_needed(false, Some("OK")), Some(Repair::CreateVirtualDisplay));
        assert_eq!(repair_needed(true, Some("Error")), Some(Repair::RestartDriver));
        assert_eq!(repair_needed(false, Some("Error")), Some(Repair::RestartDriver));
        assert_eq!(repair_needed(false, None), Some(Repair::CreateVirtualDisplay));
        assert_eq!(repair_needed(true, None), None);
    }

    #[test]
    fn repair_runs_only_the_named_existing_task() {
        let r = crate::runner::RecordingRunner::ok("");
        assert!(run_repair(&r, Repair::RestartDriver));
        assert_eq!(r.calls()[0], ("schtasks".to_string(), vec!["/run".to_string(), "/tn".to_string(), "ParsecVDD Repair".to_string()]));
        assert_eq!(driver_status(&crate::runner::RecordingRunner::ok("OK ")).as_deref(), Some("OK"));
        assert_eq!(driver_status(&crate::runner::RecordingRunner::ok("")), None);
    }
}
