use std::ffi::{c_char, CStr, CString};
use std::sync::{Mutex, OnceLock};

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

    let mut state = match STATE.lock() {
        Ok(guard) => guard,
        Err(_) => {
            set_last_error("DoH gateway lock poisoned");
            return -3;
        }
    };
    stop_locked(&mut state);

    let bind_addr = format!("127.0.0.1:{preferred_port}");
    let started = runtime().block_on(async {
        let tls = std::sync::Arc::new(GatewayTls::new());
        let resolver = DohResolver::new(url, tls.clone()).await?;
        resolver.probe().await?;
        let listener = TcpListener::bind(&bind_addr)
            .await
            .map_err(|error| format!("bind {bind_addr}: {error}"))?;
        let port = listener
            .local_addr()
            .map_err(|error| format!("listener address: {error}"))?
            .port();
        Ok::<_, String>((port, listener, resolver, tls))
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
    *state = Some(RunningGateway { port, shutdown });
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
