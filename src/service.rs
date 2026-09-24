//! Windows Service integration.
//!
//! Only the lifecycle lives here: tell the Service Control Manager we are running, translate its
//! stop event into the same shutdown future the console path uses, and report Stopped when the
//! accept loop returns. The proxy itself knows nothing about any of it.
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

    let running = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    status_handle.set_service_status(running)?;

    let config_path = crate::config_path_from_args();
    let outcome = server::serve_blocking(&config_path, async move {
        let _ = stop_rx.await;
    });

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
