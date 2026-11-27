//! Plan d'ecran Local/Remote : logique pure reprise des regles de display.ps1 v5.
//!
//! Regles conservees (pieges deja rencontres) :
//! - verifier la topologie COMPLETE (ecrans actifs exacts, principal, position, mode), pas seulement le mode ;
//! - ne jamais laisser zero ecran actif : on active la cible AVANT de desactiver le reste ;
//! - retour de secours aux ecrans physiques si plus aucun ecran actif ;
//! - ne pas couper une session distante active sans `force`.
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mode {
    pub w: u32,
    pub h: u32,
    pub hz: u32,
}

impl Mode {
    /// Meme resolution et frequence a 1 Hz pres (Windows rapporte 59 pour 59,94 Hz).
    pub fn matches(&self, other: &Mode) -> bool {
        self.w == other.w && self.h == other.h && self.hz.abs_diff(other.hz) <= 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Screen {
    /// Identifiant materiel (ex. PSCCDD0, MSI4CE3, AOC2401).
    pub id: String,
    pub active: bool,
    pub primary: bool,
    pub mode: Mode,
    pub x: i32,
    pub y: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    Local,
    Remote,
}

#[derive(Debug, Clone)]
pub struct DisplayConfig {
    pub remote_id: String,
    pub remote_mode: Mode,
    /// Ecrans physiques ; le premier est l'ecran principal en local.
    pub local: Vec<(String, Mode, (i32, i32))>,
}

impl Default for DisplayConfig {
    /// Valeurs du PC fixe (display.ps1 v5) : distant 1920x1200@60 en 16:10.
    fn default() -> Self {
        Self {
            remote_id: "PSCCDD0".into(),
            remote_mode: Mode { w: 1920, h: 1200, hz: 60 },
            local: vec![
                ("MSI4CE3".into(), Mode { w: 2560, h: 1440, hz: 60 }, (0, 0)),
                ("AOC2401".into(), Mode { w: 1920, h: 1080, hz: 60 }, (2560, 104)),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    ScreenMissing(String),
    UnexpectedActive(String),
    NotActive(String),
    NotPrimary(String),
    WrongPosition(String),
    WrongMode(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Activate(String),
    SetMode { id: String, mode: Mode },
    Place { id: String, x: i32, y: i32 },
    SetPrimary(String),
    Deactivate(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DisplayError {
    #[error("ecran introuvable : {0}")]
    ScreenMissing(String),
    #[error("une session distante est active : refus de couper l'affichage sans --force")]
    RemoteSessionActive,
    #[error("backend d'affichage : {0}")]
    Backend(String),
    #[error("topologie toujours incorrecte apres {0} tentatives")]
    NotConverged(u32),
    #[error("topologie toujours incorrecte apres {0} tentatives (derniere erreur du pilote : {1})")]
    NotConvergedWith(u32, String),
}

fn targets(layout: Layout, cfg: &DisplayConfig) -> Vec<(String, Mode, (i32, i32))> {
    match layout {
        Layout::Remote => vec![(cfg.remote_id.clone(), cfg.remote_mode, (0, 0))],
        Layout::Local => cfg.local.clone(),
    }
}

/// Diagnostic complet ; liste vide = topologie correcte.
pub fn check(layout: Layout, screens: &[Screen], cfg: &DisplayConfig) -> Vec<Problem> {
    let want = targets(layout, cfg);
    let mut problems = vec![];
    for s in screens.iter().filter(|s| s.active) {
        if !want.iter().any(|(id, _, _)| *id == s.id) {
            problems.push(Problem::UnexpectedActive(s.id.clone()));
        }
    }
    for (i, (id, mode, pos)) in want.iter().enumerate() {
        match screens.iter().find(|s| &s.id == id) {
            None => problems.push(Problem::ScreenMissing(id.clone())),
            Some(s) if !s.active => problems.push(Problem::NotActive(id.clone())),
            Some(s) => {
                if (i == 0) != s.primary {
                    problems.push(Problem::NotPrimary(id.clone()));
                }
                if (s.x, s.y) != *pos {
                    problems.push(Problem::WrongPosition(id.clone()));
                }
                if !s.mode.matches(mode) {
                    problems.push(Problem::WrongMode(id.clone()));
                }
            }
        }
    }
    problems
}

/// Etapes pour atteindre la cible. Les ecrans cibles sont actives AVANT toute desactivation.
pub fn plan(layout: Layout, screens: &[Screen], cfg: &DisplayConfig) -> Result<Vec<Step>, DisplayError> {
    let want = targets(layout, cfg);
    for (id, _, _) in &want {
        if !screens.iter().any(|s| &s.id == id) {
            return Err(DisplayError::ScreenMissing(id.clone()));
        }
    }
    let mut steps = vec![];
    for (id, mode, (x, y)) in &want {
        let s = screens.iter().find(|s| &s.id == id).unwrap();
        if !s.active {
            steps.push(Step::Activate(id.clone()));
        }
        if !s.active || !s.mode.matches(mode) {
            steps.push(Step::SetMode { id: id.clone(), mode: *mode });
        }
        if !s.active || (s.x, s.y) != (*x, *y) {
            steps.push(Step::Place { id: id.clone(), x: *x, y: *y });
        }
    }
    let primary = &want[0].0;
    let cur = screens.iter().find(|s| &s.id == primary).unwrap();
    if !cur.active || !cur.primary {
        steps.push(Step::SetPrimary(primary.clone()));
    }
    for s in screens.iter().filter(|s| s.active) {
        if !want.iter().any(|(id, _, _)| *id == s.id) {
            steps.push(Step::Deactivate(s.id.clone()));
        }
    }
    Ok(steps)
}

pub trait DisplayBackend {
    fn inspect(&mut self) -> Result<Vec<Screen>, DisplayError>;
    fn execute(&mut self, step: &Step) -> Result<(), DisplayError>;
    /// Valide les etapes en attente (backends qui regroupent les changements, ex. CCD Windows).
    fn commit(&mut self) -> Result<(), DisplayError> {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ApplyOptions {
    pub dry_run: bool,
    pub force: bool,
    pub session_active: bool,
    pub max_attempts: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    AlreadyCorrect,
    /// Simulation : etapes qui seraient executees.
    Planned(Vec<Step>),
    Applied { attempts: u32 },
}

pub fn guard(layout: Layout, opts: &ApplyOptions) -> Result<(), DisplayError> {
    if layout == Layout::Local && opts.session_active && !opts.force {
        return Err(DisplayError::RemoteSessionActive);
    }
    Ok(())
}

pub fn apply(
    backend: &mut dyn DisplayBackend,
    layout: Layout,
    cfg: &DisplayConfig,
    opts: &ApplyOptions,
) -> Result<Outcome, DisplayError> {
    guard(layout, opts)?;
    let mut screens = backend.inspect()?;
    if check(layout, &screens, cfg).is_empty() {
        return Ok(Outcome::AlreadyCorrect);
    }
    if opts.dry_run {
        return Ok(Outcome::Planned(plan(layout, &screens, cfg)?));
    }
    let mut last_err: Option<String> = None;
    for attempt in 1..=opts.max_attempts {
        let steps = plan(layout, &screens, cfg)?;
        let mut failed = false;
        for s in &steps {
            if let Err(e) = backend.execute(s) {
                last_err = Some(format!("{s:?} : {e}"));
                failed = true;
                break;
            }
        }
        if let Err(e) = backend.commit() {
            last_err = Some(format!("commit : {e}"));
            failed = true;
        }
        screens = backend.inspect()?;
        if !failed && check(layout, &screens, cfg).is_empty() {
            return Ok(Outcome::Applied { attempts: attempt });
        }
    }
    // Secours : plus aucun ecran actif => retour aux ecrans physiques.
    if !screens.iter().any(|s| s.active) && layout == Layout::Remote {
        for s in plan(Layout::Local, &screens, cfg)? {
            let _ = backend.execute(&s);
        }
        let _ = backend.commit();
    }
    Err(match last_err {
        Some(m) => DisplayError::NotConvergedWith(opts.max_attempts, m),
        None => DisplayError::NotConverged(opts.max_attempts),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scr(id: &str, active: bool, primary: bool, mode: Mode, x: i32, y: i32) -> Screen {
        Screen { id: id.into(), active, primary, mode, x, y }
    }
    const M2560: Mode = Mode { w: 2560, h: 1440, hz: 60 };
    const M1080: Mode = Mode { w: 1920, h: 1080, hz: 60 };
    const V2560: Mode = Mode { w: 2560, h: 1600, hz: 60 };
    const V1200: Mode = Mode { w: 1920, h: 1200, hz: 60 };

    fn local() -> Vec<Screen> {
        vec![
            scr("MSI4CE3", true, true, M2560, 0, 0),
            scr("AOC2401", true, false, M1080, 2560, 104),
            scr("PSCCDD0", false, false, V2560, 4480, 0),
        ]
    }
    fn remote() -> Vec<Screen> {
        vec![
            scr("MSI4CE3", false, false, M2560, 0, 0),
            scr("AOC2401", false, false, M1080, 2560, 104),
            scr("PSCCDD0", true, true, V1200, 0, 0),
        ]
    }

    #[test]
    fn correct_layouts_have_no_problem() {
        let c = DisplayConfig::default();
        assert!(check(Layout::Local, &local(), &c).is_empty());
        assert!(check(Layout::Remote, &remote(), &c).is_empty());
    }

    /// Incident 2026-11-16 : virtuel en (4480,0) et physiques encore actifs, mode virtuel correct.
    #[test]
    fn incident_partial_remote_is_not_correct() {
        let c = DisplayConfig::default();
        let s = vec![
            scr("MSI4CE3", true, true, M2560, 0, 0),
            scr("AOC2401", true, false, M1080, 2560, 104),
            scr("PSCCDD0", true, false, V1200, 4480, 0),
        ];
        let p = check(Layout::Remote, &s, &c);
        assert!(p.contains(&Problem::UnexpectedActive("MSI4CE3".into())));
        assert!(p.contains(&Problem::UnexpectedActive("AOC2401".into())));
        assert!(p.contains(&Problem::NotPrimary("PSCCDD0".into())));
        assert!(p.contains(&Problem::WrongPosition("PSCCDD0".into())));
    }

    /// Essai reel 2026-11-24 : le MSI est rapporte en 2560x1440@59 pour la consigne @60.
    #[test]
    fn refresh_within_one_hz_is_accepted() {
        let c = DisplayConfig::default();
        let mut s = local();
        s[0].mode.hz = 59;
        assert!(check(Layout::Local, &s, &c).is_empty());
        s[0].mode.hz = 57;
        assert_eq!(check(Layout::Local, &s, &c), vec![Problem::WrongMode("MSI4CE3".into())]);
    }

    #[test]
    fn wrong_resolution_detected() {
        let c = DisplayConfig::default();
        let mut s = remote();
        s[2].mode = V2560;
        assert_eq!(check(Layout::Remote, &s, &c), vec![Problem::WrongMode("PSCCDD0".into())]);
    }

    #[test]
    fn plan_activates_target_before_deactivating_others() {
        let steps = plan(Layout::Remote, &local(), &DisplayConfig::default()).unwrap();
        let act = steps.iter().position(|s| *s == Step::Activate("PSCCDD0".into())).unwrap();
        let first_off = steps.iter().position(|s| matches!(s, Step::Deactivate(_))).unwrap();
        assert!(act < first_off);
        assert!(steps.contains(&Step::SetMode { id: "PSCCDD0".into(), mode: V1200 }));
        assert!(steps.contains(&Step::SetPrimary("PSCCDD0".into())));
    }

    #[test]
    fn plan_fails_when_target_screen_absent() {
        let s = vec![scr("MSI4CE3", true, true, M2560, 0, 0)];
        assert_eq!(
            plan(Layout::Remote, &s, &DisplayConfig::default()),
            Err(DisplayError::ScreenMissing("PSCCDD0".into()))
        );
    }

    #[test]
    fn remote_resolution_is_configurable() {
        let mut c = DisplayConfig::default();
        c.remote_mode = Mode { w: 1680, h: 1050, hz: 60 };
        let steps = plan(Layout::Remote, &remote(), &c).unwrap();
        assert!(steps.contains(&Step::SetMode { id: "PSCCDD0".into(), mode: c.remote_mode }));
    }

    /// Backend simule qui applique reellement les etapes sur un etat en memoire.
    struct Sim {
        screens: Vec<Screen>,
        log: Vec<Step>,
        fail_first_n: u32,
    }
    impl DisplayBackend for Sim {
        fn inspect(&mut self) -> Result<Vec<Screen>, DisplayError> {
            Ok(self.screens.clone())
        }
        fn execute(&mut self, step: &Step) -> Result<(), DisplayError> {
            self.log.push(step.clone());
            if self.fail_first_n > 0 {
                self.fail_first_n -= 1;
                return Err(DisplayError::Backend("refuse".into()));
            }
            match step {
                Step::Activate(id) => self.screens.iter_mut().find(|s| &s.id == id).unwrap().active = true,
                Step::Deactivate(id) => {
                    let s = self.screens.iter_mut().find(|s| &s.id == id).unwrap();
                    s.active = false;
                    s.primary = false;
                }
                Step::SetMode { id, mode } => self.screens.iter_mut().find(|s| &s.id == id).unwrap().mode = *mode,
                Step::Place { id, x, y } => {
                    let s = self.screens.iter_mut().find(|s| &s.id == id).unwrap();
                    s.x = *x;
                    s.y = *y;
                }
                Step::SetPrimary(id) => {
                    for s in self.screens.iter_mut() {
                        s.primary = &s.id == id;
                    }
                }
            }
            Ok(())
        }
    }

    fn opts() -> ApplyOptions {
        ApplyOptions { dry_run: false, force: false, session_active: false, max_attempts: 3 }
    }

    #[test]
    fn apply_converges_both_ways() {
        let c = DisplayConfig::default();
        let mut b = Sim { screens: local(), log: vec![], fail_first_n: 0 };
        assert_eq!(apply(&mut b, Layout::Remote, &c, &opts()).unwrap(), Outcome::Applied { attempts: 1 });
        assert!(check(Layout::Remote, &b.screens, &c).is_empty());
        let o = ApplyOptions { force: true, session_active: true, ..opts() };
        apply(&mut b, Layout::Local, &c, &o).unwrap();
        assert!(check(Layout::Local, &b.screens, &c).is_empty());
    }

    #[test]
    fn apply_is_idempotent() {
        let mut b = Sim { screens: remote(), log: vec![], fail_first_n: 0 };
        assert_eq!(apply(&mut b, Layout::Remote, &DisplayConfig::default(), &opts()).unwrap(), Outcome::AlreadyCorrect);
        assert!(b.log.is_empty());
    }

    #[test]
    fn dry_run_changes_nothing() {
        let mut b = Sim { screens: local(), log: vec![], fail_first_n: 0 };
        let o = ApplyOptions { dry_run: true, ..opts() };
        assert!(matches!(apply(&mut b, Layout::Remote, &DisplayConfig::default(), &o).unwrap(), Outcome::Planned(_)));
        assert!(b.log.is_empty());
    }

    #[test]
    fn refuses_to_cut_active_remote_session() {
        let mut b = Sim { screens: remote(), log: vec![], fail_first_n: 0 };
        let o = ApplyOptions { session_active: true, ..opts() };
        assert_eq!(apply(&mut b, Layout::Local, &DisplayConfig::default(), &o), Err(DisplayError::RemoteSessionActive));
        assert!(b.log.is_empty());
    }

    #[test]
    fn retries_after_transient_failure() {
        let mut b = Sim { screens: local(), log: vec![], fail_first_n: 1 };
        assert_eq!(
            apply(&mut b, Layout::Remote, &DisplayConfig::default(), &opts()).unwrap(),
            Outcome::Applied { attempts: 2 }
        );
    }

    #[test]
    fn gives_up_after_max_attempts() {
        let mut b = Sim { screens: local(), log: vec![], fail_first_n: 100 };
        assert_eq!(
            apply(&mut b, Layout::Remote, &DisplayConfig::default(), &opts()),
            Err(DisplayError::NotConvergedWith(3, "Activate(\"PSCCDD0\") : backend d'affichage : refuse".into()))
        );
    }

    #[test]
    fn falls_back_to_physical_when_no_screen_active() {
        let mut all_off = remote();
        all_off[2].active = false;
        all_off[2].primary = false;
        let mut b = Sim { screens: all_off, log: vec![], fail_first_n: 0 };
        // Le pilote virtuel refuse toute operation (cas du code 43) ; les ecrans physiques repondent.
        struct Stubborn(Sim);
        impl DisplayBackend for Stubborn {
            fn inspect(&mut self) -> Result<Vec<Screen>, DisplayError> {
                self.0.inspect()
            }
            fn execute(&mut self, s: &Step) -> Result<(), DisplayError> {
                let virt = match s {
                    Step::Activate(i) | Step::SetPrimary(i) | Step::Deactivate(i) => i == "PSCCDD0",
                    Step::SetMode { id, .. } | Step::Place { id, .. } => id == "PSCCDD0",
                };
                if virt {
                    return Err(DisplayError::Backend("pilote en erreur".into()));
                }
                self.0.execute(s)
            }
        }
        let mut st = Stubborn(Sim { screens: std::mem::take(&mut b.screens), log: vec![], fail_first_n: 0 });
        let c = DisplayConfig::default();
        let r = apply(&mut st, Layout::Remote, &c, &ApplyOptions { max_attempts: 1, ..opts() });
        assert!(r.is_err());
        // Le secours a reactive les ecrans physiques.
        assert!(check(Layout::Local, &st.0.screens, &c).is_empty());
    }
}
