//! NGINX dynamic module exposing ALTCHA proof-of-work challenges as request
//! variables.
//!
//! Two variables are exposed:
//!   - `$altcha_challenge` — fresh challenge JSON (one per request, cached in
//!     module ctx)
//!   - `$altcha_verified`  — `"1"` if the configured input variable holds a
//!     valid solved payload, `"0"` otherwise
//!
//! Configuration directives are accepted in `http`, `server`, and `location`
//! contexts and merge top-down (parent values fill in unset child values). See
//! the README for the full list of directives.

use core::ffi::{c_char, c_void};
use core::time::Duration;
use core::{mem, ptr};

use altcha::{
    Challenge, CreateChallengeOptions, HmacAlgorithm, Payload, VerifySolutionOptions,
    create_challenge, verify_solution,
};
use base64::Engine;
use ngx::core::Status;
use ngx::ffi::{
    NGX_CONF_TAKE1, NGX_HTTP_LOC_CONF, NGX_HTTP_LOC_CONF_OFFSET, NGX_HTTP_MAIN_CONF,
    NGX_HTTP_MODULE, NGX_HTTP_SRV_CONF, NGX_LOG_EMERG, ngx_command_t, ngx_conf_t,
    ngx_http_add_variable, ngx_http_compile_complex_value_t, ngx_http_complex_value,
    ngx_http_complex_value_t, ngx_http_module_t, ngx_http_variable_t, ngx_int_t, ngx_module_t,
    ngx_str_t, ngx_uint_t, ngx_variable_value_t,
};
use ngx::http::{self, HttpModule, HttpModuleLocationConf, Merge, MergeConfigError};
use ngx::{http_variable_get, ngx_conf_log_error, ngx_log_debug_http, ngx_string};

/// Per-location module configuration. `Option`s let `Merge` distinguish "unset"
/// from "explicitly set", so parent contexts can fill in missing leaves.
#[derive(Debug, Default)]
struct ModuleConfig {
    hmac_signature_secret: Option<String>,
    hmac_key_signature_secret: Option<String>,
    algorithm: Option<String>,
    cost: Option<u32>,
    hmac_algorithm: Option<HmacAlgorithm>,
    key_length: Option<usize>,
    key_prefix: Option<String>,
    expires: Option<Duration>,
    /// Compiled `ngx_http_complex_value_t` for the configured input variable
    /// expression (e.g. `$arg_altcha`). Allocated in nginx's config pool.
    verify_input: *mut ngx_http_complex_value_t,
}

// SAFETY: nginx workers are single-threaded; the raw pointer lives in the
// nginx config pool which is never freed during a worker's lifetime.
unsafe impl Send for ModuleConfig {}
unsafe impl Sync for ModuleConfig {}

impl ModuleConfig {
    fn algorithm(&self) -> &str {
        self.algorithm.as_deref().unwrap_or("PBKDF2/SHA-256")
    }
    fn cost(&self) -> u32 {
        self.cost.unwrap_or(100_000)
    }
    fn hmac_algorithm(&self) -> HmacAlgorithm {
        self.hmac_algorithm.clone().unwrap_or_default()
    }
    fn key_length(&self) -> usize {
        self.key_length.unwrap_or(32)
    }
    fn key_prefix(&self) -> &str {
        self.key_prefix.as_deref().unwrap_or("00")
    }
    fn expires(&self) -> Duration {
        self.expires.unwrap_or(Duration::from_secs(300))
    }
}

impl Merge for ModuleConfig {
    fn merge(&mut self, prev: &ModuleConfig) -> Result<(), MergeConfigError> {
        if self.hmac_signature_secret.is_none() {
            self.hmac_signature_secret = prev.hmac_signature_secret.clone();
        }
        if self.hmac_key_signature_secret.is_none() {
            self.hmac_key_signature_secret = prev.hmac_key_signature_secret.clone();
        }
        if self.algorithm.is_none() {
            self.algorithm = prev.algorithm.clone();
        }
        if self.cost.is_none() {
            self.cost = prev.cost;
        }
        if self.hmac_algorithm.is_none() {
            self.hmac_algorithm = prev.hmac_algorithm.clone();
        }
        if self.key_length.is_none() {
            self.key_length = prev.key_length;
        }
        if self.key_prefix.is_none() {
            self.key_prefix = prev.key_prefix.clone();
        }
        if self.expires.is_none() {
            self.expires = prev.expires;
        }
        if self.verify_input.is_null() {
            self.verify_input = prev.verify_input;
        }
        Ok(())
    }
}

struct AltchaModule;

unsafe impl HttpModuleLocationConf for AltchaModule {
    type LocationConf = ModuleConfig;
}

impl HttpModule for AltchaModule {
    fn module() -> &'static ngx_module_t {
        unsafe { &*ptr::addr_of!(ngx_http_altcha_module) }
    }

    unsafe extern "C" fn preconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        for mut v in unsafe { NGX_HTTP_ALTCHA_VARS } {
            let var = unsafe { ngx_http_add_variable(cf, &raw mut v.name, v.flags) };
            if var.is_null() {
                return ngx_int_t::from(Status::NGX_ERROR);
            }
            unsafe {
                (*var).get_handler = v.get_handler;
                (*var).data = v.data;
            }
        }
        ngx_int_t::from(Status::NGX_OK)
    }
}

const ALL_CONTEXTS: ngx_uint_t =
    (NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1) as ngx_uint_t;

static mut NGX_HTTP_ALTCHA_COMMANDS: [ngx_command_t; 10] = [
    ngx_command_t {
        name: ngx_string!("altcha_hmac_signature_secret"),
        type_: ALL_CONTEXTS,
        set: Some(set_hmac_signature_secret),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("altcha_hmac_key_signature_secret"),
        type_: ALL_CONTEXTS,
        set: Some(set_hmac_key_signature_secret),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("altcha_algorithm"),
        type_: ALL_CONTEXTS,
        set: Some(set_algorithm),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("altcha_cost"),
        type_: ALL_CONTEXTS,
        set: Some(set_cost),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("altcha_hmac_algorithm"),
        type_: ALL_CONTEXTS,
        set: Some(set_hmac_algorithm),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("altcha_key_length"),
        type_: ALL_CONTEXTS,
        set: Some(set_key_length),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("altcha_key_prefix"),
        type_: ALL_CONTEXTS,
        set: Some(set_key_prefix),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("altcha_expires"),
        type_: ALL_CONTEXTS,
        set: Some(set_expires),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t {
        name: ngx_string!("altcha_verify_input"),
        type_: ALL_CONTEXTS,
        set: Some(set_verify_input),
        conf: NGX_HTTP_LOC_CONF_OFFSET,
        offset: 0,
        post: ptr::null_mut(),
    },
    ngx_command_t::empty(),
];

static NGX_HTTP_ALTCHA_MODULE_CTX: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(AltchaModule::preconfiguration),
    postconfiguration: None,
    create_main_conf: None,
    init_main_conf: None,
    create_srv_conf: None,
    merge_srv_conf: None,
    create_loc_conf: Some(AltchaModule::create_loc_conf),
    merge_loc_conf: Some(AltchaModule::merge_loc_conf),
};

#[cfg(feature = "export-modules")]
ngx::ngx_modules!(ngx_http_altcha_module);

#[used]
#[allow(non_upper_case_globals)]
#[cfg_attr(not(feature = "export-modules"), unsafe(no_mangle))]
pub static mut ngx_http_altcha_module: ngx_module_t = ngx_module_t {
    ctx: &raw const NGX_HTTP_ALTCHA_MODULE_CTX as _,
    commands: unsafe { &raw mut NGX_HTTP_ALTCHA_COMMANDS[0] },
    type_: NGX_HTTP_MODULE as _,
    ..ngx_module_t::default()
};

static mut NGX_HTTP_ALTCHA_VARS: [ngx_http_variable_t; 2] = [
    ngx_http_variable_t {
        name: ngx_string!("altcha_challenge"),
        set_handler: None,
        get_handler: Some(ngx_http_altcha_challenge_variable),
        data: 0,
        flags: 0,
        index: 0,
    },
    ngx_http_variable_t {
        name: ngx_string!("altcha_verified"),
        set_handler: None,
        get_handler: Some(ngx_http_altcha_verified_variable),
        data: 0,
        flags: 0,
        index: 0,
    },
];

#[derive(Debug, Default)]
struct AltchaCtx {
    challenge_json: Option<ngx_str_t>,
    verified: Option<bool>,
}

http_variable_get!(
    ngx_http_altcha_challenge_variable,
    |request: &mut http::Request, v: *mut ngx_variable_value_t, _: usize| {
        let ctx_ptr = ensure_ctx(request);
        if ctx_ptr.is_null() {
            return Status::NGX_ERROR;
        }

        if let Some(s) = unsafe { (*ctx_ptr).challenge_json } {
            unsafe { bind_str(v, s) };
            return Status::NGX_OK;
        }

        let conf = match AltchaModule::location_conf(request) {
            Some(c) => c,
            None => {
                ngx_log_debug_http!(request, "altcha: no location config");
                return Status::NGX_ERROR;
            }
        };

        let Some(secret) = conf.hmac_signature_secret.clone() else {
            ngx_log_debug_http!(
                request,
                "altcha: altcha_hmac_signature_secret is not configured"
            );
            unsafe { (*v).set_not_found(1) };
            return Status::NGX_OK;
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let opts = CreateChallengeOptions {
            algorithm: conf.algorithm().to_string(),
            cost: conf.cost(),
            hmac_algorithm: conf.hmac_algorithm(),
            hmac_signature_secret: Some(secret),
            hmac_key_signature_secret: conf.hmac_key_signature_secret.clone(),
            key_length: conf.key_length(),
            key_prefix: conf.key_prefix().to_string(),
            expires_at: Some(now + conf.expires().as_secs()),
            ..Default::default()
        };

        let challenge: Challenge = match create_challenge(opts) {
            Ok(c) => c,
            Err(e) => {
                ngx_log_debug_http!(request, "altcha: create_challenge failed: {:?}", e);
                return Status::NGX_ERROR;
            }
        };

        let json = match serde_json::to_string(&challenge) {
            Ok(s) => s,
            Err(e) => {
                ngx_log_debug_http!(request, "altcha: serialize challenge failed: {:?}", e);
                return Status::NGX_ERROR;
            }
        };

        let pool_ptr = request.pool().as_ptr();
        let ngx_s = match unsafe { ngx_str_t::from_bytes(pool_ptr, json.as_bytes()) } {
            Some(s) => s,
            None => return Status::NGX_ERROR,
        };

        unsafe {
            (*ctx_ptr).challenge_json = Some(ngx_s);
            bind_str(v, ngx_s);
        }
        Status::NGX_OK
    }
);

http_variable_get!(
    ngx_http_altcha_verified_variable,
    |request: &mut http::Request, v: *mut ngx_variable_value_t, _: usize| {
        let ctx_ptr = ensure_ctx(request);
        if ctx_ptr.is_null() {
            return Status::NGX_ERROR;
        }

        if let Some(verified) = unsafe { (*ctx_ptr).verified } {
            unsafe { bind_static_bool(v, verified) };
            return Status::NGX_OK;
        }

        let verified = run_verify(request);
        unsafe {
            (*ctx_ptr).verified = Some(verified);
            bind_static_bool(v, verified);
        }
        Status::NGX_OK
    }
);

/// Returns `true` only when the configured input variable holds a solved,
/// signed, unexpired ALTCHA payload. Any error along the way collapses to
/// `false`.
fn run_verify(request: &mut http::Request) -> bool {
    let conf = match AltchaModule::location_conf(request) {
        Some(c) => c,
        None => return false,
    };
    let Some(secret) = conf.hmac_signature_secret.clone() else {
        ngx_log_debug_http!(
            request,
            "altcha: verify failed — altcha_hmac_signature_secret not configured"
        );
        return false;
    };
    if conf.verify_input.is_null() {
        ngx_log_debug_http!(
            request,
            "altcha: verify failed — altcha_verify_input not configured"
        );
        return false;
    }

    // Evaluate the configured input variable expression against this request.
    let mut value = ngx_str_t::empty();
    let r_ptr: *mut ngx::ffi::ngx_http_request_t = request.into();
    let rc = unsafe { ngx_http_complex_value(r_ptr, conf.verify_input, &raw mut value) };
    if rc != ngx_int_t::from(Status::NGX_OK) || value.is_empty() {
        ngx_log_debug_http!(request, "altcha: verify failed — input value missing");
        return false;
    }

    let raw_bytes = value.as_bytes();
    let payload_json = match base64::engine::general_purpose::STANDARD.decode(raw_bytes) {
        Ok(b) => b,
        Err(_) => {
            // Some altcha clients use URL-safe base64 — try that as a fallback.
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(raw_bytes) {
                Ok(b) => b,
                Err(e) => {
                    ngx_log_debug_http!(request, "altcha: verify failed — base64 decode: {:?}", e);
                    return false;
                }
            }
        }
    };

    let payload: Payload = match serde_json::from_slice(&payload_json) {
        Ok(p) => p,
        Err(e) => {
            ngx_log_debug_http!(request, "altcha: verify failed — json parse: {:?}", e);
            return false;
        }
    };

    let opts = VerifySolutionOptions {
        challenge: &payload.challenge,
        solution: &payload.solution,
        hmac_algorithm: conf.hmac_algorithm(),
        hmac_key_signature_secret: conf.hmac_key_signature_secret.clone(),
        hmac_signature_secret: secret,
    };

    match verify_solution(opts) {
        Ok(r) => r.verified,
        Err(e) => {
            ngx_log_debug_http!(request, "altcha: verify_solution error: {:?}", e);
            false
        }
    }
}

/// Lazily allocates an `AltchaCtx` in the request pool and stores it as the
/// module ctx so subsequent variable reads share state. Returns null on
/// allocation failure.
fn ensure_ctx(request: &mut http::Request) -> *mut AltchaCtx {
    if let Some(existing) = request.get_module_ctx::<AltchaCtx>(AltchaModule::module()) {
        // SAFETY: the ctx was allocated and is owned by this module, so
        // upgrading the borrow to a mutable raw pointer is sound — the only
        // access path is through this getter, which runs sequentially.
        return (existing as *const AltchaCtx) as *mut AltchaCtx;
    }
    let new_ctx = request.pool().allocate::<AltchaCtx>(Default::default());
    if new_ctx.is_null() {
        return ptr::null_mut();
    }
    request.set_module_ctx(new_ctx as *mut c_void, AltchaModule::module());
    new_ctx
}

unsafe fn bind_str(v: *mut ngx_variable_value_t, s: ngx_str_t) {
    unsafe {
        (*v).set_valid(1);
        (*v).set_no_cacheable(0);
        (*v).set_not_found(0);
        (*v).set_len(s.len as u32);
        (*v).data = s.data;
    }
}

unsafe fn bind_static_bool(v: *mut ngx_variable_value_t, value: bool) {
    static TRUE_S: &[u8] = b"1";
    static FALSE_S: &[u8] = b"0";
    let bytes = if value { TRUE_S } else { FALSE_S };
    unsafe {
        (*v).set_valid(1);
        (*v).set_no_cacheable(0);
        (*v).set_not_found(0);
        (*v).set_len(bytes.len() as u32);
        (*v).data = bytes.as_ptr() as *mut u8;
    }
}

// ---------------------------------------------------------------------------
// Directive setters
// ---------------------------------------------------------------------------

unsafe fn arg_str<'a>(cf: *mut ngx_conf_t) -> Option<&'a ngx_str_t> {
    let args = unsafe { (*(*cf).args).as_slice() };
    args.get(1)
}

extern "C" fn set_hmac_signature_secret(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let Some(arg) = arg_str(cf) else {
            return ngx::core::NGX_CONF_ERROR;
        };
        conf.hmac_signature_secret = Some(arg.to_string());
    }
    ngx::core::NGX_CONF_OK
}

extern "C" fn set_hmac_key_signature_secret(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let Some(arg) = arg_str(cf) else {
            return ngx::core::NGX_CONF_ERROR;
        };
        conf.hmac_key_signature_secret = Some(arg.to_string());
    }
    ngx::core::NGX_CONF_OK
}

extern "C" fn set_algorithm(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let Some(arg) = arg_str(cf) else {
            return ngx::core::NGX_CONF_ERROR;
        };
        conf.algorithm = Some(arg.to_string());
    }
    ngx::core::NGX_CONF_OK
}

extern "C" fn set_cost(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let Some(arg) = arg_str(cf) else {
            return ngx::core::NGX_CONF_ERROR;
        };
        let s = match arg.to_str() {
            Ok(s) => s,
            Err(_) => {
                ngx_conf_log_error!(NGX_LOG_EMERG, cf, "altcha_cost is not utf-8");
                return ngx::core::NGX_CONF_ERROR;
            }
        };
        match s.parse::<u32>() {
            Ok(n) if n > 0 => conf.cost = Some(n),
            _ => {
                ngx_conf_log_error!(NGX_LOG_EMERG, cf, "altcha_cost must be a positive integer");
                return ngx::core::NGX_CONF_ERROR;
            }
        }
    }
    ngx::core::NGX_CONF_OK
}

extern "C" fn set_hmac_algorithm(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let Some(arg) = arg_str(cf) else {
            return ngx::core::NGX_CONF_ERROR;
        };
        let s = arg.to_str().unwrap_or("");
        let algo = match s.to_ascii_lowercase().as_str() {
            "sha256" | "sha-256" => HmacAlgorithm::Sha256,
            "sha384" | "sha-384" => HmacAlgorithm::Sha384,
            "sha512" | "sha-512" => HmacAlgorithm::Sha512,
            _ => {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    cf,
                    "altcha_hmac_algorithm must be one of sha256, sha384, sha512"
                );
                return ngx::core::NGX_CONF_ERROR;
            }
        };
        conf.hmac_algorithm = Some(algo);
    }
    ngx::core::NGX_CONF_OK
}

extern "C" fn set_key_length(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let Some(arg) = arg_str(cf) else {
            return ngx::core::NGX_CONF_ERROR;
        };
        let s = arg.to_str().unwrap_or("");
        match s.parse::<usize>() {
            Ok(n) if n > 0 && n <= 64 => conf.key_length = Some(n),
            _ => {
                ngx_conf_log_error!(NGX_LOG_EMERG, cf, "altcha_key_length must be in 1..=64");
                return ngx::core::NGX_CONF_ERROR;
            }
        }
    }
    ngx::core::NGX_CONF_OK
}

extern "C" fn set_key_prefix(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let Some(arg) = arg_str(cf) else {
            return ngx::core::NGX_CONF_ERROR;
        };
        let s = arg.to_str().unwrap_or("");
        if s.is_empty() || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            ngx_conf_log_error!(NGX_LOG_EMERG, cf, "altcha_key_prefix must be hex");
            return ngx::core::NGX_CONF_ERROR;
        }
        conf.key_prefix = Some(s.to_string());
    }
    ngx::core::NGX_CONF_OK
}

extern "C" fn set_expires(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let Some(arg) = arg_str(cf) else {
            return ngx::core::NGX_CONF_ERROR;
        };
        let s = arg.to_str().unwrap_or("");
        match duration_str::parse(s) {
            Ok(d) if !d.is_zero() => conf.expires = Some(d),
            _ => {
                ngx_conf_log_error!(
                    NGX_LOG_EMERG,
                    cf,
                    "altcha_expires must be a positive duration like \"5m\" or \"300s\""
                );
                return ngx::core::NGX_CONF_ERROR;
            }
        }
    }
    ngx::core::NGX_CONF_OK
}

extern "C" fn set_verify_input(
    cf: *mut ngx_conf_t,
    _cmd: *mut ngx_command_t,
    conf: *mut c_void,
) -> *mut c_char {
    unsafe {
        let conf = &mut *(conf as *mut ModuleConfig);
        let cf_ref = &mut *cf;
        let pool = ngx::core::Pool::from_ngx_pool(cf_ref.pool);

        let cv = pool.calloc_type::<ngx_http_complex_value_t>();
        if cv.is_null() {
            return ngx::core::NGX_CONF_ERROR;
        }

        let args = (*cf_ref.args).as_slice_mut();
        let mut ccv: ngx_http_compile_complex_value_t = mem::zeroed();
        ccv.cf = cf;
        ccv.value = &raw mut args[1];
        ccv.complex_value = cv;

        if nginx_sys::ngx_http_compile_complex_value(&raw mut ccv)
            != ngx_int_t::from(Status::NGX_OK)
        {
            return ngx::core::NGX_CONF_ERROR;
        }

        conf.verify_input = cv;
    }
    ngx::core::NGX_CONF_OK
}
