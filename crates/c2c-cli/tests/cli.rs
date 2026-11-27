use std::path::PathBuf;
use std::process::Command;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn c2c(dir: &tempdir::T, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_c2c"))
        .current_dir(&dir.0)
        .args(args)
        .output()
        .unwrap()
}

mod tempdir {
    pub struct T(pub std::path::PathBuf);
    impl T {
        pub fn new(tag: &str) -> T {
            let p = std::env::temp_dir().join(format!("c2c-test-{}-{}", tag, std::process::id()));
            std::fs::create_dir_all(&p).unwrap();
            T(p)
        }
    }
    impl Drop for T {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

#[test]
fn wake_without_execute_is_simulation_and_writes_no_audit() {
    let d = tempdir::T::new("wake");
    let cfg = root().join("examples/c2c.example.toml");
    let o = c2c(&d, &["--config", cfg.to_str().unwrap(), "wake", "pc-fixe"]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{out}");
    assert!(out.contains("simulation") && out.contains("02:00:5E:00:00:01"));
    assert!(!d.0.join("c2c-audit.jsonl").exists());
}

#[test]
fn wake_unknown_machine_fails() {
    let d = tempdir::T::new("unk");
    let cfg = root().join("examples/c2c.example.toml");
    let o = c2c(&d, &["--config", cfg.to_str().unwrap(), "wake", "nope"]);
    assert!(!o.status.success());
}

#[test]
fn display_plan_remote_from_local_state() {
    let d = tempdir::T::new("plan");
    let sc = root().join("examples/screens-local.json");
    let o = c2c(&d, &["display-plan", "remote", "--screens", sc.to_str().unwrap()]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(o.status.success(), "{out}");
    assert!(out.contains("Activate(\"PSCCDD0\")") && out.contains("Deactivate(\"MSI4CE3\")"));
}

#[test]
fn display_plan_local_refused_during_active_session() {
    let d = tempdir::T::new("guard");
    let sc = root().join("examples/screens-local.json");
    let o = c2c(&d, &["display-plan", "local", "--screens", sc.to_str().unwrap(), "--session-active"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("session distante"));
}

#[test]
fn audit_verify_on_empty_log() {
    let d = tempdir::T::new("audit");
    let o = c2c(&d, &["audit-verify"]);
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stdout).contains("0 entrees"));
}

#[test]
fn display_mode_is_stored_and_defaults_to_auto() {
    let d = tempdir::T::new("mode");
    let o = c2c(&d, &["display-mode"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("auto"));
    let o = c2c(&d, &["display-mode", "remote"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("remote"));
    let o = c2c(&d, &["display-mode"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("remote"));
    let o = c2c(&d, &["display-mode", "auto"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("auto"));
}

#[test]
fn display_profile_lists_selects_and_rejects_unknown() {
    let d = tempdir::T::new("profile");
    std::fs::write(
        d.0.join("c2c.toml"),
        "[wake]\npi_user=\"u\"\npi_host=\"h\"\n[display.profiles.portable]\nw = 2560\nh = 1600\nhz = 60\n[display.profiles.fhd]\nw = 1920\nh = 1080\nhz = 60\n",
    )
    .unwrap();
    let o = c2c(&d, &["display-profile"]);
    let s = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(s.contains("portable : 2560x1600@60 (16:10)") && s.contains("fhd : 1920x1080@60 (16:9)"), "{s}");
    let o = c2c(&d, &["display-profile", "portable"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("Profil actif : portable"));
    let o = c2c(&d, &["display-profile", "nimporte"]);
    assert!(!o.status.success());
    let o = c2c(&d, &["display-profile", "defaut"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("defaut"));
}
