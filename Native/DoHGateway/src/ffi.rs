use std::ffi::{c_char, CStr, CString};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::runtime::Runtime;
use tokio::sync::watch;

use crate::doh::DohResolver;
use crate::gateway::Gateway;
use crate::tls::GatewayTls;

struct RunningGateway {
    port: u16,
    shutdown: watch::Sender<bool>,
}

/// Whole start + linux.do probe must finish inside this budget so a blocked
/// built-in resolver cannot hang the caller (or the next cold launch).
pub(crate) const START_BUDGET: Duration = Duration::from_secs(4);

static RUNTIME: OnceLock<Runtime> = OnceLock::new();
static STATE: Mutex<Option<RunningGateway>> = Mutex::new(None);
static LAST_ERROR: Mutex<Option<CString>> = Mutex::new(None);

fn runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("dexo-doh-gateway")
            .build()
            .expect("tokio runtime")
    })
}

fn stop_locked(state: &mut Option<RunningGateway>) {
    if let Some(running) = state.take() {
        let _ = running.shutdown.send(true);
    }
}

fn set_last_error(message: impl AsRef<str>) {
    let message = message.as_ref().replace('\0', "");
    if !message.is_empty() {
        eprintln!("[DoHGateway] {message}");
    }
    if let Ok(mut slot) = LAST_ERROR.lock() {
        *slot = CString::new(message).ok();
    }
}

fn empty_cstr() -> *const c_char {
    static EMPTY: &[u8] = b"\0";
    EMPTY.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn dexo_doh_gateway_start(doh_url: *const c_char, preferred_port: u16) -> i32 {
    set_last_error("");
    if doh_url.is_null() {
        set_last_error("DoH URL is missing");
        return -1;
    }
    let url = unsafe { CStr::from_ptr(doh_url) }
        .to_str()
        .map(str::trim)
        .unwrap_or("");
    if url.is_empty() {
        set_last_error("DoH URL is empty");
        return -1;
    }

    // Never hold STATE across resolver/probe I/O. A blocked Cloudflare
    // probe previously froze the iOS main thread while this mutex was held.
    if let Ok(mut state) = STATE.lock() {
        stop_locked(&mut state);
    } else {
        set_last_error("DoH gateway lock poisoned");
        return -3;
    }

    let bind_addr = format!("127.0.0.1:{preferred_port}");
    let url_owned = url.to_string();
    let started = runtime().block_on(async {
        tokio::time::timeout(START_BUDGET, async {
            let tls = std::sync::Arc::new(GatewayTls::new());
            let resolver = DohResolver::new(&url_owned, tls.clone()).await?;
            let listener = TcpListener::bind(&bind_addr)
                .await
                .map_err(|error| format!("bind {bind_addr}: {error}"))?;
            let port = listener
                .local_addr()
                .map_err(|error| format!("listener address: {error}"))?
                .port();
            resolver
                .probe()
                .await
                .map_err(|error| format!("{error}"))?;
            Ok::<_, String>((port, listener, resolver, tls))
        })
        .await
        .map_err(|_| "DoH start timed out".to_string())?
    });

    let (port, listener, resolver, tls) = match started {
        Ok(value) => value,
        Err(message) => {
            set_last_error(message);
            return -1;
        }
    };

    let (shutdown, rx) = watch::channel(false);
    let gateway = Gateway::new(resolver, tls);
    runtime().spawn(async move {
        gateway.serve(listener, rx).await;
    });
    eprintln!("[DoHGateway] listening on 127.0.0.1:{port} doh={url}");
    match STATE.lock() {
        Ok(mut state) => {
            stop_locked(&mut state);
            *state = Some(RunningGateway { port, shutdown });
        }
        Err(_) => {
            let _ = shutdown.send(true);
            set_last_error("DoH gateway lock poisoned");
            return -3;
        }
    }
    port as i32
}

#[no_mangle]
pub extern "C" fn dexo_doh_gateway_stop() {
    if let Ok(mut state) = STATE.lock() {
        stop_locked(&mut state);
        eprintln!("[DoHGateway] stopped");
    }
}

#[no_mangle]
pub extern "C" fn dexo_doh_gateway_port() -> i32 {
    STATE
        .lock()
        .ok()
        .and_then(|state| state.as_ref().map(|running| running.port as i32))
        .unwrap_or(0)
}

#[no_mangle]
pub extern "C" fn dexo_doh_gateway_is_running() -> i32 {
    if dexo_doh_gateway_port() > 0 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn dexo_doh_gateway_ech_compiled() -> i32 {
    i32::from(cfg!(feature = "ech"))
}

#[no_mangle]
pub extern "C" fn dexo_doh_gateway_last_error() -> *const c_char {
    match LAST_ERROR.lock() {
        Ok(slot) => slot.as_ref().map(|value| value.as_ptr()).unwrap_or_else(empty_cstr),
        Err(_) => empty_cstr(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_budget_is_a_few_seconds() {
        assert!(
            START_BUDGET.as_secs() >= 3 && START_BUDGET.as_secs() <= 4,
            "start/probe budget must be 3–4s, got {:?}",
            START_BUDGET
        );
    }

    #[test]
    fn ech_compiled_matches_crate_feature() {
        assert_eq!(
            dexo_doh_gateway_ech_compiled(),
            i32::from(cfg!(feature = "ech"))
        );
        assert_eq!(
            dexo_doh_gateway_ech_compiled(),
            1,
            "default cargo test must build with ECH"
        );
    }
}
