//! Backend d'affichage Windows (CCD + DEVMODE). Seul endroit du projet qui contient du `unsafe`.
//! Port des regles de DisplayTopology.cs / DisplayModes.cs (display.ps1 v5).
#![cfg(windows)]

use c2c_core::display::{DisplayBackend, DisplayError, Mode, Screen, Step};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Devices::Display::*;
use windows::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, POINTL, WIN32_ERROR};
use windows::Win32::Graphics::Gdi::*;

const PATH_ACTIVE: u32 = 1;
const INVALID_IDX: u32 = 0xFFFF_FFFF;

fn err(msg: impl Into<String>) -> DisplayError {
    DisplayError::Backend(msg.into())
}

#[derive(Default)]
struct Wish {
    mode: Option<Mode>,
    pos: Option<(i32, i32)>,
    primary: bool,
}

fn entry(wishes: &mut Vec<(String, Wish)>, id: &str) -> usize {
    match wishes.iter().position(|(i, _)| i == id) {
        Some(n) => n,
        None => {
            wishes.push((id.to_string(), Wish::default()));
            wishes.len() - 1
        }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn from_wide(buf: &[u16]) -> String {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..n])
}

/// `\\?\DISPLAY#PSCCDD0#5&...` -> `PSCCDD0`
fn hardware_id(device_path: &str) -> Option<String> {
    device_path.split('#').nth(1).map(str::to_string)
}

struct PathInfo {
    path: DISPLAYCONFIG_PATH_INFO,
    id: String,
    gdi: String,
}

fn query_paths() -> Result<Vec<PathInfo>, DisplayError> {
    for _ in 0..5 {
        let (mut np, mut nm) = (0u32, 0u32);
        let rc = unsafe { GetDisplayConfigBufferSizes(QDC_ALL_PATHS, &mut np, &mut nm) };
        if rc != WIN32_ERROR(0) {
            return Err(err(format!("GetDisplayConfigBufferSizes={}", rc.0)));
        }
        let mut paths = vec![DISPLAYCONFIG_PATH_INFO::default(); np as usize];
        let mut modes = vec![DISPLAYCONFIG_MODE_INFO::default(); nm as usize];
        let rc = unsafe { QueryDisplayConfig(QDC_ALL_PATHS, &mut np, paths.as_mut_ptr(), &mut nm, modes.as_mut_ptr(), None) };
        if rc == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if rc != WIN32_ERROR(0) {
            return Err(err(format!("QueryDisplayConfig={}", rc.0)));
        }
        paths.truncate(np as usize);
        let mut out = vec![];
        for p in paths {
            if !p.targetInfo.targetAvailable.as_bool() {
                continue;
            }
            let mut t = DISPLAYCONFIG_TARGET_DEVICE_NAME::default();
            t.header.r#type = DISPLAYCONFIG_DEVICE_INFO_GET_TARGET_NAME;
            t.header.size = std::mem::size_of::<DISPLAYCONFIG_TARGET_DEVICE_NAME>() as u32;
            t.header.adapterId = p.targetInfo.adapterId;
            t.header.id = p.targetInfo.id;
            if unsafe { DisplayConfigGetDeviceInfo(&mut t.header) } != 0 {
                continue;
            }
            let Some(id) = hardware_id(&from_wide(&t.monitorDevicePath)) else { continue };
            let mut s = DISPLAYCONFIG_SOURCE_DEVICE_NAME::default();
            s.header.r#type = DISPLAYCONFIG_DEVICE_INFO_GET_SOURCE_NAME;
            s.header.size = std::mem::size_of::<DISPLAYCONFIG_SOURCE_DEVICE_NAME>() as u32;
            s.header.adapterId = p.sourceInfo.adapterId;
            s.header.id = p.sourceInfo.id;
            let gdi = if unsafe { DisplayConfigGetDeviceInfo(&mut s.header) } == 0 { from_wide(&s.viewGdiDeviceName) } else { String::new() };
            out.push(PathInfo { path: p, id, gdi });
        }
        return Ok(out);
    }
    Err(err("topologie instable"))
}

fn is_active(p: &DISPLAYCONFIG_PATH_INFO) -> bool {
    p.flags & PATH_ACTIVE != 0
}

fn current_devmode(gdi: &str) -> Option<DEVMODEW> {
    let mut dm = DEVMODEW { dmSize: std::mem::size_of::<DEVMODEW>() as u16, ..Default::default() };
    let name = wide(gdi);
    unsafe { EnumDisplaySettingsW(PCWSTR(name.as_ptr()), ENUM_CURRENT_SETTINGS, &mut dm) }.as_bool().then_some(dm)
}

fn is_primary(gdi: &str) -> bool {
    let mut i = 0;
    loop {
        let mut d = DISPLAY_DEVICEW { cb: std::mem::size_of::<DISPLAY_DEVICEW>() as u32, ..Default::default() };
        if !unsafe { EnumDisplayDevicesW(PCWSTR::null(), i, &mut d, 0) }.as_bool() {
            return false;
        }
        if from_wide(&d.DeviceName).eq_ignore_ascii_case(gdi) {
            return d.StateFlags & DISPLAY_DEVICE_PRIMARY_DEVICE != 0;
        }
        i += 1;
    }
}

/// Un ecran par identifiant materiel, en preferant le chemin actif.
fn unique_by_id(infos: &[PathInfo]) -> BTreeMap<String, &PathInfo> {
    let mut m: BTreeMap<String, &PathInfo> = BTreeMap::new();
    for i in infos {
        match m.get(&i.id) {
            Some(prev) if is_active(&prev.path) || !is_active(&i.path) => {}
            _ => {
                m.insert(i.id.clone(), i);
            }
        }
    }
    m
}

/// Detache la console du processus : la fenetre disparait et ne peut plus etre fermee par erreur
/// (fermer la console tuait la surveillance, code 0xC000013A).
pub fn detach_console() {
    // SAFETY : appel sans argument, sans pointeur ; sans effet si aucune console n'est attachee.
    let _ = unsafe { windows::Win32::System::Console::FreeConsole() };
}

pub fn inspect_screens() -> Result<Vec<Screen>, DisplayError> {
    let infos = query_paths()?;
    let mut out = vec![];
    for (id, i) in unique_by_id(&infos) {
        let active = is_active(&i.path);
        let dm = if active { current_devmode(&i.gdi) } else { None };
        let (mode, x, y) = match &dm {
            Some(d) => {
                let pos = unsafe { d.Anonymous1.Anonymous2.dmPosition };
                (Mode { w: d.dmPelsWidth, h: d.dmPelsHeight, hz: d.dmDisplayFrequency }, pos.x, pos.y)
            }
            None => (Mode { w: 0, h: 0, hz: 0 }, 0, 0),
        };
        out.push(Screen { id, active, primary: active && is_primary(&i.gdi), mode, x, y });
    }
    Ok(out)
}

/// Backend reel. Les etapes sont mises en file ; `commit` applique la topologie (CCD) puis les modes.
pub struct WindowsBackend {
    /// Identifiants des ecrans virtuels : la topologie n'est persistee que si aucun n'en fait partie.
    pub virtual_ids: Vec<String>,
    pub settle_timeout: Duration,
    queue: Vec<Step>,
}

impl WindowsBackend {
    pub fn new(virtual_ids: Vec<String>) -> Self {
        Self { virtual_ids, settle_timeout: Duration::from_secs(20), queue: vec![] }
    }

    fn apply_topology(&self, want: &BTreeSet<String>) -> Result<(), DisplayError> {
        let infos = query_paths()?;
        let uniq = unique_by_id(&infos);
        let mut chosen = vec![];
        for id in want {
            let i = uniq.get(id).ok_or_else(|| err(format!("ecran indisponible : {id}")))?;
            let mut p = i.path;
            p.sourceInfo.Anonymous.modeInfoIdx = INVALID_IDX;
            p.targetInfo.Anonymous.modeInfoIdx = INVALID_IDX;
            p.flags = PATH_ACTIVE;
            p.targetInfo.refreshRate = DISPLAYCONFIG_RATIONAL::default();
            p.targetInfo.scanLineOrdering = DISPLAYCONFIG_SCANLINE_ORDERING(0);
            chosen.push(p);
        }
        let persist = !want.iter().any(|id| self.virtual_ids.contains(id));
        let base = SDC_USE_SUPPLIED_DISPLAY_CONFIG | SDC_ALLOW_CHANGES;
        let rc = unsafe { SetDisplayConfig(Some(&chosen), None, base | SDC_VALIDATE) };
        if rc != 0 {
            return Err(err(format!("validation topologie refusee={rc}")));
        }
        let mut flags = base | SDC_APPLY;
        if persist {
            flags |= SDC_SAVE_TO_DATABASE;
        }
        let rc = unsafe { SetDisplayConfig(Some(&chosen), None, flags) };
        if rc != 0 {
            return Err(err(format!("SetDisplayConfig={rc}")));
        }
        Ok(())
    }

    fn wait_active(&self, want: &BTreeSet<String>) -> Result<(), DisplayError> {
        let deadline = Instant::now() + self.settle_timeout;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let now: BTreeSet<String> = inspect_screens()?.into_iter().filter(|s| s.active).map(|s| s.id).collect();
            if &now == want {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(err("topologie active incorrecte apres application"));
            }
        }
    }

    /// Dernier recours pour un ecran deja actif dont le mode n'a pas ete retenu (cas du virtuel seul, qui retombe en 1080p) :
    /// changement « en direct » (sans CDS_NORESET ni registre), largeur/hauteur/frequence uniquement, comme l'ancien script.
    fn apply_modes_live(&self) -> Result<(), DisplayError> {
        let current = inspect_screens()?;
        let infos = query_paths()?;
        let uniq = unique_by_id(&infos);
        for s in &self.queue {
            let Step::SetMode { id, mode } = s else { continue };
            if current.iter().any(|c| &c.id == id && c.active && c.mode == *mode) {
                continue;
            }
            let i = uniq.get(id).ok_or_else(|| err(format!("ecran introuvable : {id}")))?;
            let mut dm = current_devmode(&i.gdi).ok_or_else(|| err(format!("mode courant illisible : {id}")))?;
            dm.dmPelsWidth = mode.w;
            dm.dmPelsHeight = mode.h;
            dm.dmDisplayFrequency = mode.hz;
            dm.dmFields = DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY;
            let name = wide(&i.gdi);
            // SAFETY : `name` et `dm` restent valides pendant l'appel ; flags 0 = application immediate.
            let rc = unsafe { ChangeDisplaySettingsExW(PCWSTR(name.as_ptr()), Some(&dm), None, CDS_TYPE(0), None) };
            if rc != DISP_CHANGE_SUCCESSFUL {
                return Err(err(format!("mode en direct {id} {}x{}@{}={}", mode.w, mode.h, mode.hz, rc.0)));
            }
        }
        Ok(())
    }

    fn apply_modes(&self) -> Result<(), DisplayError> {
        let mut wishes: Vec<(String, Wish)> = vec![];
        for s in &self.queue {
            match s {
                Step::SetMode { id, mode } => {
                    let n = entry(&mut wishes, id);
                    wishes[n].1.mode = Some(*mode);
                }
                Step::Place { id, x, y } => {
                    let n = entry(&mut wishes, id);
                    wishes[n].1.pos = Some((*x, *y));
                }
                Step::SetPrimary(id) => {
                    let n = entry(&mut wishes, id);
                    wishes[n].1.primary = true;
                }
                _ => {}
            }
        }
        if wishes.is_empty() {
            return Ok(());
        }
        let infos = query_paths()?;
        let uniq = unique_by_id(&infos);
        // Le principal d'abord (Windows exige qu'il soit en 0,0).
        wishes.sort_by_key(|(_, w)| !w.primary);
        for (id, w) in &wishes {
            let i = uniq.get(id).ok_or_else(|| err(format!("ecran introuvable : {id}")))?;
            let mut dm = current_devmode(&i.gdi).ok_or_else(|| err(format!("mode courant illisible : {id}")))?;
            let mut fields = DEVMODE_FIELD_FLAGS(0);
            if let Some(m) = w.mode {
                dm.dmPelsWidth = m.w;
                dm.dmPelsHeight = m.h;
                dm.dmDisplayFrequency = m.hz;
                dm.dmBitsPerPel = 32;
                fields |= DM_PELSWIDTH | DM_PELSHEIGHT | DM_DISPLAYFREQUENCY | DM_BITSPERPEL;
            }
            if let Some((x, y)) = w.pos {
                dm.Anonymous1.Anonymous2.dmPosition = POINTL { x, y };
                fields |= DM_POSITION;
            }
            dm.dmFields = fields;
            let name = wide(&i.gdi);
            let mut flags = CDS_UPDATEREGISTRY | CDS_NORESET;
            if w.primary {
                flags |= CDS_SET_PRIMARY;
            }
            let rc = unsafe { ChangeDisplaySettingsExW(PCWSTR(name.as_ptr()), Some(&dm), None, flags, None) };
            if rc != DISP_CHANGE_SUCCESSFUL {
                return Err(err(format!("ChangeDisplaySettingsEx({id})={}", rc.0)));
            }
        }
        let rc = unsafe { ChangeDisplaySettingsExW(PCWSTR::null(), None, None, CDS_TYPE(0), None) };
        if rc != DISP_CHANGE_SUCCESSFUL {
            return Err(err(format!("validation des modes={}", rc.0)));
        }
        Ok(())
    }
}

impl DisplayBackend for WindowsBackend {
    fn inspect(&mut self) -> Result<Vec<Screen>, DisplayError> {
        inspect_screens()
    }

    fn execute(&mut self, step: &Step) -> Result<(), DisplayError> {
        self.queue.push(step.clone());
        Ok(())
    }

    fn commit(&mut self) -> Result<(), DisplayError> {
        let queue = std::mem::take(&mut self.queue);
        let mut want: BTreeSet<String> = inspect_screens()?.into_iter().filter(|s| s.active).map(|s| s.id).collect();
        let before = want.clone();
        for s in &queue {
            match s {
                Step::Activate(id) => {
                    want.insert(id.clone());
                }
                Step::Deactivate(id) => {
                    want.remove(id);
                }
                _ => {}
            }
        }
        if want.is_empty() {
            return Err(err("refus : aucun ecran ne resterait actif"));
        }
        self.queue = queue;
        let result = (|| {
            if want != before {
                self.apply_topology(&want)?;
                self.wait_active(&want)?;
            }
            self.apply_modes()?;
            // ChangeDisplaySettingsEx (registre) peut rallumer des ecrans : on reverifie et on rapplique la topologie.
            let now: BTreeSet<String> = inspect_screens()?.into_iter().filter(|s| s.active).map(|s| s.id).collect();
            if now != want {
                self.apply_topology(&want)?;
                self.wait_active(&want)?;
            }
            self.apply_modes_live()
        })();
        self.queue.clear();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_id_from_device_path() {
        assert_eq!(hardware_id(r"\\?\DISPLAY#PSCCDD0#5&2a1b#{e6f07b5f}").as_deref(), Some("PSCCDD0"));
        assert_eq!(hardware_id("nope"), None);
    }

    #[test]
    fn wide_roundtrip() {
        assert_eq!(from_wide(&wide(r"\\.\DISPLAY1")), r"\\.\DISPLAY1");
    }
}
