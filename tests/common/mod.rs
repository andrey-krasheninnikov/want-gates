#![allow(dead_code)]
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{Builder, TempDir};

pub fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(args)
        .output()
        .unwrap()
}

pub fn status(socket: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wgates"))
        .args(["status", "--socket"])
        .arg(socket)
        .output()
        .unwrap()
}

pub struct Service {
    pub child: Child,
    pub directory: TempDir,
    pub socket: PathBuf,
    pub state: PathBuf,
}

impl Service {
    pub fn start() -> Self {
        let directory = Builder::new().prefix("wgates-").tempdir_in("/tmp").unwrap();
        let socket = directory.path().join("runtime/control.sock");
        let state = directory.path().join("state");
        let child = Command::new(env!("CARGO_BIN_EXE_wgates"))
            .args(["serve", "--socket"])
            .arg(&socket)
            .arg("--state-dir")
            .arg(&state)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut service = Self {
            child,
            directory,
            socket,
            state,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            assert!(
                service.child.try_wait().unwrap().is_none(),
                "service exited"
            );
            if status(&service.socket).status.success() {
                return service;
            }
            assert!(Instant::now() < deadline, "service did not become ready");
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn stop(&mut self) -> ExitStatus {
        // SAFETY: the PID belongs to this fixture's live child process.
        assert_eq!(
            unsafe { libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) },
            0
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "service did not stop");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        if self.child.try_wait().unwrap().is_none() {
            self.child.kill().unwrap();
        }
        self.child.wait().unwrap();
    }
}
