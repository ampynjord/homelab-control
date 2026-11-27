//! Execution de commandes sans shell (arguments separes), injectable pour les tests.
use std::io;
use std::process::Command;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[String]) -> io::Result<Output>;

    /// Comme `run`, avec des donnees sur l'entree standard (pour transmettre un secret sans le mettre dans la ligne de commande).
    fn run_stdin(&self, _program: &str, _args: &[String], _stdin: &str) -> io::Result<Output> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "entree standard non prise en charge"))
    }
}

/// Sous Windows, empeche l'ouverture d'une fenetre console pour la commande lancee (CREATE_NO_WINDOW).
pub fn quiet(c: &mut Command) -> &mut Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    c
}

pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run_stdin(&self, program: &str, args: &[String], stdin: &str) -> io::Result<Output> {
        use std::io::Write;
        use std::process::Stdio;
        let mut c = Command::new(program);
        c.args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = quiet(&mut c).spawn()?;
        if let Some(mut i) = child.stdin.take() {
            i.write_all(stdin.as_bytes())?;
        }
        let o = child.wait_with_output()?;
        Ok(Output { status: o.status.code().unwrap_or(-1), stdout: String::from_utf8_lossy(&o.stdout).into_owned(), stderr: String::from_utf8_lossy(&o.stderr).into_owned() })
    }

    fn run(&self, program: &str, args: &[String]) -> io::Result<Output> {
        let mut c = Command::new(program);
        c.args(args);
        let o = quiet(&mut c).output()?;
        Ok(Output {
            status: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        })
    }
}

/// Enregistre les appels sans rien executer (tests et mode simulation).
pub struct RecordingRunner {
    pub calls: Mutex<Vec<(String, Vec<String>)>>,
    /// Donnees recues sur l'entree standard, dans l'ordre des appels `run_stdin`.
    pub stdins: Mutex<Vec<String>>,
    pub reply: Output,
}

impl RecordingRunner {
    pub fn ok(stdout: &str) -> Self {
        Self { calls: Mutex::new(vec![]), stdins: Mutex::new(vec![]), reply: Output { status: 0, stdout: stdout.into(), stderr: String::new() } }
    }
    pub fn failing(status: i32) -> Self {
        Self { calls: Mutex::new(vec![]), stdins: Mutex::new(vec![]), reply: Output { status, stdout: String::new(), stderr: "boom".into() } }
    }
    pub fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.calls.lock().unwrap().clone()
    }
}

impl CommandRunner for RecordingRunner {
    fn run_stdin(&self, program: &str, args: &[String], stdin: &str) -> io::Result<Output> {
        self.calls.lock().unwrap().push((program.to_string(), args.to_vec()));
        self.stdins.lock().unwrap().push(stdin.to_string());
        Ok(self.reply.clone())
    }

    fn run(&self, program: &str, args: &[String]) -> io::Result<Output> {
        self.calls.lock().unwrap().push((program.to_string(), args.to_vec()));
        Ok(self.reply.clone())
    }
}
