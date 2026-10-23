//! C ABI around the engine so the Swift helper can host it in-process.

use mailcore::{Engine, api};
use parking_lot::Mutex;
use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::OnceLock;

pub type EventCallback = extern "C" fn(ctx: *mut c_void, json: *const c_char);

struct Running {
    engine: Engine,
    token: String,
}

struct Ctx(*mut c_void);
// The context pointer is owned by the Swift side, which guarantees it outlives the engine.
unsafe impl Send for Ctx {}
unsafe impl Sync for Ctx {}

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static RUNNING: Mutex<Option<Running>> = Mutex::new(None);
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mailcore")
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

fn set_error(e: impl ToString) {
    *LAST_ERROR.lock() = Some(e.to_string());
}

fn init_logging(dir: &std::path::Path) {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        let _ = std::fs::create_dir_all(dir.join("logs"));
        if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("logs/mailcore.log")) {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("MAILBOX_LOG").unwrap_or_else(|_| "info".into()))
                .with_ansi(false)
                .with_writer(std::sync::Mutex::new(file))
                .try_init();
        }
    });
}

/// # Safety
/// `data_dir` must be a valid NUL-terminated UTF-8 string; `ctx` must stay valid until `mailcore_stop`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mailcore_start(data_dir: *const c_char, port: u16, cb: Option<EventCallback>, ctx: *mut c_void) -> i32 {
    if data_dir.is_null() {
        set_error("data_dir is NULL");
        return -1;
    }
    let dir = match unsafe { CStr::from_ptr(data_dir) }.to_str() {
        Ok(s) => std::path::PathBuf::from(s),
        Err(e) => {
            set_error(e);
            return -1;
        }
    };
    if let Some(r) = RUNNING.lock().as_ref() {
        return r.engine.api_port.load(std::sync::atomic::Ordering::Relaxed) as i32;
    }
    init_logging(&dir);
    let rt = runtime();
    let ctx = Ctx(ctx);
    let result = rt.block_on(async move {
        let engine = Engine::open(&dir)?;
        let handle = api::serve(engine.clone(), if port == 0 { None } else { Some(port) }).await?;
        if let Some(cb) = cb {
            let mut rx = engine.events.subscribe();
            tokio::spawn(async move {
                let ctx = ctx;
                loop {
                    match rx.recv().await {
                        Ok(ev) => {
                            if let Ok(json) = serde_json::to_string(&ev) {
                                if let Ok(c) = CString::new(json) {
                                    cb(ctx.0, c.as_ptr());
                                }
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
            });
        }
        engine.start();
        Ok::<_, mailcore::Error>((engine, handle))
    });
    match result {
        Ok((engine, handle)) => {
            let port = handle.port as i32;
            *RUNNING.lock() = Some(Running { engine, token: handle.token });
            port
        }
        Err(e) => {
            set_error(e);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mailcore_stop() {
    if let Some(r) = RUNNING.lock().take() {
        runtime().block_on(r.engine.shutdown());
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mailcore_token() -> *mut c_char {
    match RUNNING.lock().as_ref() {
        Some(r) => CString::new(r.token.clone()).map(CString::into_raw).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mailcore_last_error() -> *mut c_char {
    match LAST_ERROR.lock().as_ref() {
        Some(e) => CString::new(e.clone()).map(CString::into_raw).unwrap_or(std::ptr::null_mut()),
        None => std::ptr::null_mut(),
    }
}

/// # Safety
/// `s` must come from one of the functions above and not be freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mailcore_free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(unsafe { CString::from_raw(s) });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn mailcore_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
