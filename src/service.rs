//! Windows Service integration.
//!
//! Only the lifecycle lives here: report start pending until the listener is bound and running
//! after, translate the Service Control Manager's stop event into the same shutdown future the
//! console path uses, report stop pending while it drains, and Stopped when it has. The proxy
//! itself knows nothing about any of it.
//!
//! The service runs with its working directory set to the system directory, not the install
//! directory, so the configuration path is resolved to an absolute one BEFORE the dispatcher
//! starts. A relative path here silently becomes `C:\Windows\System32\config.toml`.

use crate::server;

use std::ffi::OsString;
use std::time::Duration;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

pub const SERVICE_NAME: &str = "WebAccessProxy";

/// What the Service Control Manager is told to allow for starting: a schema migration on a large
/// database runs before the listener binds.
const START_WAIT: Duration = Duration::from_secs(120);

/// What it is told to allow for stopping: blocking work, a migration job among it, finishes first.
const STOP_WAIT: Duration = Duration::from_secs(60);

windows_service::define_windows_service!(ffi_service_main, service_main);

/// Called from `main` when started by the SCM. Blocks until the service stops.
pub fn start() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run() {
        // There is no console to print to. The event log is the only place this could go, and
        // wiring that up is not worth a dependency: the proxy's own tracing output is the record.
        tracing::error!(error = %e, "service failed");
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let mut stop_tx = Some(stop_tx);

    let handler = move |control| -> ServiceControlHandlerResult {
        match control {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                if let Some(tx) = stop_tx.take() {
                    let _ = tx.send(());
                }
                ServiceControlHandlerResult::NoError
            }
            // Interrogate must be answered or the SCM considers the service unresponsive.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, handler)?;
    let report = move |state: ServiceState, accept: ServiceControlAccept, wait_hint: Duration| {
        let status = ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: accept,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint,
            process_id: None,
        };
        if let Err(e) = status_handle.set_service_status(status) {
            tracing::warn!(error = %e, "could not report the service state");
        }
    };

    // Start pending until the config is read, the database opened and the port bound, so a start
    // that cannot serve fails where the administrator started it instead of a second later.
    report(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
        START_WAIT,
    );
    let config_path = crate::config_path_from_args();
    let outcome = server::serve_blocking(
        &config_path,
        async move {
            let _ = stop_rx.await;
            // Draining waits for blocking work, a migration job among it.
            report(
                ServiceState::StopPending,
                ServiceControlAccept::empty(),
                STOP_WAIT,
            );
        },
        move || {
            report(
                ServiceState::Running,
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                Duration::default(),
            );
        },
    );

    // Report Stopped whatever happened, or the SCM leaves the service wedged in Running.
    let exit_code = if outcome.is_ok() {
        ServiceExitCode::Win32(0)
    } else {
        ServiceExitCode::ServiceSpecific(1)
    };
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    outcome
}

#[cfg(all(test, target_env = "msvc"))]
mod tests {
    /// A server without the Visual C++ Redistributable cannot load a binary that imports its
    /// runtime: the service times out at start and `--version` exits 0xC0000135. The test binary
    /// is built with the same flags as the proxy, so its imports stand for the proxy's.
    #[test]
    fn the_c_runtime_is_linked_statically() {
        let exe = std::fs::read(std::env::current_exe().expect("the test binary's path"))
            .expect("the test binary");
        let dlls = imported_dlls(&exe);
        assert!(
            dlls.iter().any(|d| d == "kernel32.dll"),
            "the import table was not read: {dlls:?}"
        );
        for dll in &dlls {
            let runtime = dll.starts_with("vcruntime")
                || dll.starts_with("msvcp")
                || dll.starts_with("api-ms-win-crt-");
            assert!(!runtime, "the binary imports {dll}");
        }
    }

    /// The DLL names in a PE32+ image's import directory, lowercased. The runtime linked in
    /// carries the string "vcruntime140.dll" as data, so only the import table answers this.
    fn imported_dlls(pe: &[u8]) -> Vec<String> {
        let u16_at = |o: usize| u16::from_le_bytes([pe[o], pe[o + 1]]) as usize;
        let u32_at = |o: usize| u32::from_le_bytes(pe[o..o + 4].try_into().unwrap()) as usize;
        let header = u32_at(0x3c);
        let sections = u16_at(header + 6);
        let optional = header + 24;
        assert_eq!(u16_at(optional), 0x20b, "not a PE32+ image");
        let imports = u32_at(optional + 120);
        let table = optional + u16_at(header + 20);
        let offset = |rva: usize| {
            (0..sections)
                .map(|i| table + i * 40)
                .find(|&s| (u32_at(s + 12)..u32_at(s + 12) + u32_at(s + 16)).contains(&rva))
                .map(|s| rva - u32_at(s + 12) + u32_at(s + 20))
                .expect("an RVA inside a section")
        };
        let mut dlls = Vec::new();
        let mut descriptor = offset(imports);
        while u32_at(descriptor + 12) != 0 {
            let name = &pe[offset(u32_at(descriptor + 12))..];
            let end = name
                .iter()
                .position(|&b| b == 0)
                .expect("a terminated name");
            dlls.push(String::from_utf8_lossy(&name[..end]).to_ascii_lowercase());
            descriptor += 20;
        }
        dlls
    }
}
