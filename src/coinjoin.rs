//! Bridge between the Slint `Cj` global and the real `wallet_rpc_core` engine.
//!
//! Nothing here is simulated on the key side: the seed comes from `os/security`
//! (the app-scoped seed, one consent prompt at authorization), the session derives and
//! caches the account keys, and every round produces a real SLIP-0019 ownership
//! proof from those keys. The policy the user approves is the exact struct the
//! engine then enforces.
//!
//! Requests come from the host over `crate::transport` when KeyOS lets the app
//! own a USB interface, and from the demo button otherwise. Both fill the same
//! pending slot; a host authorization is answered only once the user has slid.

use core::cell::RefCell;
use std::io::Write;

use slint_keyos_platform::slint::{Color, ComponentHandle};
use wallet_rpc_core::coinjoin::{Policy, TOKEN_LEN};
use wallet_rpc_core::protocol::{
    Backend, CoreError, Engine, CMD_AUTHORIZE_COINJOIN, CMD_GET_INFO, CMD_GET_OWNERSHIP_PROOF, CMD_GET_XPUB,
    CMD_REVOKE_SESSION, CMD_SIGN_COINJOIN, STATUS_ERR_DENIED, STATUS_ERR_INTERNAL, STATUS_ERR_MALFORMED,
    STATUS_ERR_NO_SESSION, STATUS_ERR_POLICY, STATUS_OK,
};

use wallet_rpc_core::ngwallet::bdk_wallet::bitcoin::{
    secp256k1::{All, Secp256k1},
    Network,
};
use wallet_rpc_core::zeroize::Zeroizing;

security::use_api!();
fs::use_api!();

/// Device-backed implementation of the engine's backend.
struct PrimeBackend {
    security: Security,
    secp: Secp256k1<All>,
    /// Set when the user has completed the slide gesture for the pending policy.
    /// `approve_policy` consumes it, so an engine call can never open a session
    /// the user did not physically confirm.
    slide_confirmed: bool,
}

impl Backend for PrimeBackend {
    fn firmware_version(&self) -> String {
        env!("CARGO_PKG_VERSION").to_string()
    }

    /// The 64-byte BIP-39 seed of the coinjoin wallet, derived from the
    /// app-scoped seed `os/security` hands third-party apps (KeyOS asks the user
    /// once, on the trusted display). Called exactly once per session, at
    /// authorization, from the UI callback so the consent prompt can be drawn.
    ///
    /// This is a separate wallet from the main Passport bitcoin wallet: the
    /// master seed is Foundation-signed-only. It is still covered by the
    /// ordinary seed backup (app seed = hmac(app_id, master seed)).
    fn seed(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        let app_seed = match self.security.app_seed() {
            Ok(seed) => seed,
            Err(e) => {
                log::warn!("app seed access denied: {e:?}");
                return None;
            }
        };
        // Empty passphrase: passphrase wallets are out of scope for v1, and the
        // host verifies the master fingerprint before trusting a session.
        let master = wallet_rpc_core::ngwallet::bip39::MasterKey::from_entropy(
            &self.secp,
            Network::Bitcoin,
            app_seed.as_bytes(),
            "",
            None,
        )
        .inspect_err(|e| log::error!("master key derivation failed: {e:?}"))
        .ok()?;
        Some(Zeroizing::new(master.key.0.to_vec()))
    }

    /// The slide gesture on the authorize page is the approval. It is taken
    /// before the engine call and consumed here, so a repeated or background
    /// authorize attempt finds no confirmation waiting.
    fn approve_policy(&mut self, policy: &Policy) -> bool {
        let confirmed = core::mem::take(&mut self.slide_confirmed);
        log::info!(
            "authorize coinjoin: coordinator {}, account {}, budget {} sat, {} rounds -> {}",
            String::from_utf8_lossy(&policy.coordinator_id),
            policy.account,
            policy.fee_budget_sats,
            policy.max_rounds,
            if confirmed { "confirmed" } else { "no confirmation" },
        );
        confirmed
    }

    /// Session tokens come from the secure element's RNG. No software fallback:
    /// a predictable token is worse than a refused session.
    fn random_bytes(&mut self, out: &mut [u8]) -> bool {
        match self.security.get_random() {
            Ok(random) if random.len() >= out.len() => {
                out.copy_from_slice(&random[..out.len()]);
                true
            }
            Ok(_) => {
                log::error!("secure random too short for a session token");
                false
            }
            Err(e) => {
                log::error!("secure random unavailable: {e:?}");
                false
            }
        }
    }
}

/// Everything the UI callbacks share.
struct App {
    engine: Engine<PrimeBackend>,
    /// Policy awaiting approval — set by a request, cleared once used.
    pending: Option<Policy>,
    /// The host's authorization frame behind `pending`, with where its reply goes.
    /// None when the pending policy is the local demo request.
    host: Option<crate::transport::HostFrame>,
    token: Option<[u8; TOKEN_LEN]>,
    /// Address index the next demo round asks a proof for.
    next_index: u32,
}

/// The request the demo button stands in for. Values match what Wasabi's Passport
/// client sends today (see Hwi/Passport/CoinjoinPolicy.cs).
fn demo_policy() -> Policy {
    Policy {
        network: Network::Bitcoin,
        account: 0,
        coordinator_id: b"coinjoin.nl".to_vec(),
        fee_budget_sats: 3_000,
        max_rounds: 10,
        valid_for_secs: 12 * 60 * 60,
    }
}

/// Commitment data as Wasabi sends it: length-prefixed coordinator id, then the
/// round's 32-byte commitment.
fn commitment(coordinator_id: &[u8], round: u32) -> Vec<u8> {
    let mut data = vec![coordinator_id.len() as u8];
    data.extend_from_slice(coordinator_id);
    let mut round_id = [0u8; 32];
    round_id[..4].copy_from_slice(&round.to_le_bytes());
    data.extend_from_slice(&round_id);
    data
}

const H: u32 = 0x8000_0000;
/// Wasabi coinjoins are taproot-first, so demo rounds exercise the BIP-86 path.
const DEMO_PURPOSE: u32 = 86 | H;
/// `[version][command][payload_len u32]` precedes every request payload.
const REQUEST_HEADER_LEN: usize = 6;
/// `[version][command][status][payload_len u32]` precedes every response payload.
const RESPONSE_HEADER_LEN: usize = 7;

fn error_text(error: CoreError) -> &'static str {
    match error {
        CoreError::Denied => {
            "Seed access denied. Allow this app's app-seed permission (Settings > Apps > Coinjoin Signer), unlock the device, and try again."
        }
        CoreError::Internal => "Device error: no secure random or key derivation failed.",
        CoreError::NoSession => "No active session.",
        CoreError::Policy => "Request is outside the authorized policy.",
        CoreError::Malformed => "Malformed request.",
    }
}

fn status_text(status: u8) -> &'static str {
    match status {
        STATUS_ERR_DENIED => error_text(CoreError::Denied),
        STATUS_ERR_INTERNAL => error_text(CoreError::Internal),
        STATUS_ERR_NO_SESSION => error_text(CoreError::NoSession),
        STATUS_ERR_POLICY => error_text(CoreError::Policy),
        STATUS_ERR_MALFORMED => error_text(CoreError::Malformed),
        _ => "Request refused.",
    }
}

fn show_policy(cj: &crate::Cj, policy: &Policy) {
    cj.set_coordinator(String::from_utf8_lossy(&policy.coordinator_id).to_string().into());
    cj.set_network(
        match policy.network {
            Network::Bitcoin => "mainnet",
            _ => "testnet",
        }
        .into(),
    );
    cj.set_account(policy.account as i32);
    cj.set_fee_budget(policy.fee_budget_sats as i32);
    cj.set_max_rounds(policy.max_rounds as i32);
    let minutes = policy.valid_for_secs / 60;
    cj.set_valid_for(
        if minutes % 60 == 0 { format!("{} h", minutes / 60) } else { format!("{minutes} min") }
            .into(),
    );
}

fn clear_session(cj: &crate::Cj) {
    cj.set_session_active(false);
    cj.set_rounds(0);
    cj.set_fee_spent(0);
    cj.set_fingerprint("".into());
    cj.set_last_result("".into());
}

/// The session page follows what the engine holds after a host round.
fn show_session(cj: &crate::Cj, app: &App) {
    if let Some(session) = app.engine.active_session() {
        cj.set_rounds(session.rounds_used as i32);
        cj.set_fee_spent(session.fee_spent as i32);
    }
}

fn navigate(ui: &crate::AppWindow, to: crate::RouteOption) {
    let options = crate::NavigateOptions { replace: false, animate: crate::Animate::Forward };
    let nav = ui.global::<crate::Navigate>();
    match to {
        crate::RouteOption::Authorize => nav.invoke_authorize(options),
        crate::RouteOption::Session => nav.invoke_session(options),
        _ => nav.invoke_return_home(),
    }
}

/// Opens the session the pending request asks for, once the user has slid. A host request is
/// answered with the engine's own response frame; the demo request goes through the typed call.
fn authorize(ui: &crate::AppWindow, app: &mut App) -> bool {
    let cj = ui.global::<crate::Cj>();
    let outcome = if let Some((frame, reply)) = app.host.take() {
        app.pending = None;
        app.engine.backend.slide_confirmed = true;
        let response = app.engine.process_frame(&frame);
        let outcome = match response.get(2) {
            Some(&STATUS_OK) => response
                .get(RESPONSE_HEADER_LEN..RESPONSE_HEADER_LEN + TOKEN_LEN)
                .and_then(|t| t.try_into().ok())
                .ok_or(STATUS_ERR_INTERNAL),
            Some(&status) => Err(status),
            None => Err(STATUS_ERR_INTERNAL),
        };
        let _ = reply.send(response);
        outcome
    } else if let Some(policy) = app.pending.take() {
        app.engine.backend.slide_confirmed = true;
        app.engine.authorize(policy).map_err(CoreError::status)
    } else {
        cj.set_status("No pending request.".into());
        return false;
    };

    match outcome {
        Ok(token) => {
            app.token = Some(token);
            app.next_index = 0;
            let fingerprint =
                app.engine.active_session().map(|s| s.keys.fingerprint.to_string()).unwrap_or_default();
            clear_session(&cj);
            cj.set_session_active(true);
            cj.set_fingerprint(fingerprint.into());
            cj.set_status("".into());
            log::info!("coinjoin session opened");
            true
        }
        Err(status) => {
            app.engine.backend.slide_confirmed = false;
            cj.set_status(status_text(status).into());
            log::warn!("authorize failed: status {status}");
            false
        }
    }
}

/// Refuses whatever authorization is on screen; a host is told so.
fn deny(app: &mut App) {
    app.pending = None;
    if let Some((frame, reply)) = app.host.take() {
        app.engine.backend.slide_confirmed = false;
        let _ = reply.send(app.engine.process_frame(&frame));
        log::info!("coinjoin authorization denied");
    }
}

/// One frame from the host. An authorization waits for the user; everything else is answered now.
fn handle_host_frame(ui: &crate::AppWindow, app: &mut App, (frame, reply): crate::transport::HostFrame) {
    let cj = ui.global::<crate::Cj>();

    if frame.is_empty() {
        // The host gave up waiting for the user.
        if app.host.is_some() {
            deny(app);
            cj.set_status("Wasabi stopped waiting for this authorization.".into());
            if ui.global::<crate::RouteState>().get_active() == crate::RouteOption::Authorize {
                navigate(ui, crate::RouteOption::MainPage);
            }
        }
        return;
    }

    let command = frame.get(1).copied().unwrap_or(0);
    if command == CMD_AUTHORIZE_COINJOIN {
        if let Some((policy, _)) = frame.get(REQUEST_HEADER_LEN..).and_then(Policy::parse) {
            // A newer request replaces one still on screen; the older host gets a denial.
            deny(app);
            show_policy(&cj, &policy);
            cj.set_status("".into());
            app.pending = Some(policy);
            app.host = Some((frame, reply));
            navigate(ui, crate::RouteOption::Authorize);
            return;
        }
    }

    let response = app.engine.process_frame(&frame);
    let status = response.get(2).copied().unwrap_or(STATUS_ERR_INTERNAL);
    show_session(&cj, app);
    if status == STATUS_OK {
        match command {
            CMD_GET_OWNERSHIP_PROOF => cj.set_last_result("Ownership proof sent to Wasabi".into()),
            CMD_SIGN_COINJOIN => cj.set_last_result(
                format!("Round {} signed · fees used {} sat", cj.get_rounds(), cj.get_fee_spent()).into(),
            ),
            CMD_REVOKE_SESSION => {
                app.token = None;
                clear_session(&cj);
                cj.set_status("Wasabi ended the session.".into());
                navigate(ui, crate::RouteOption::MainPage);
            }
            CMD_GET_INFO | CMD_GET_XPUB => {}
            _ => {}
        }
    } else if command != CMD_GET_INFO {
        cj.set_last_result(format!("Request refused: {}", status_text(status)).into());
    }
    let _ = reply.send(response);
}

const EXPORT_DIR: &str = "wallets";
const EXPORT_FILENAME: &str = "coinjoin-signer-wasabi.json";

/// Write the wallet file to the Airlock. Returns the path on the volume.
fn save_to_airlock(json: &str) -> Result<String, String> {
    let fs = FileSystem::default();
    let location = fs::Location::Airlock;
    fs.create_dir(EXPORT_DIR, location)
        .map_err(|e| format!("Airlock not writable ({e:?}). Turn Airlock off / unplug USB, then retry."))?;
    // One fixed file, overwritten in place: a repeated tap rewrites the same
    // bytes instead of littering the Airlock with numbered copies.
    let path = format!("{EXPORT_DIR}/{EXPORT_FILENAME}");
    let mut file = fs
        .open_file(&path, location, fs::OpenFlags { read: false, write: true, create: true })
        .map_err(|e| format!("Could not create {path} ({e:?})."))?;
    file.overwrite(json.as_bytes()).map_err(|e| format!("Write failed ({e:?})."))?;
    file.flush().map_err(|e| format!("Flush failed ({e})."))?;
    Ok(path)
}

pub fn init(ui: &crate::AppWindow) {
    let backend = PrimeBackend {
        security: Security::default(),
        secp: Secp256k1::new(),
        slide_confirmed: false,
    };
    let app: &'static RefCell<App> = Box::leak(Box::new(RefCell::new(App {
        engine: Engine::new(backend),
        pending: None,
        host: None,
        token: None,
        next_index: 0,
    })));

    let cj = ui.global::<crate::Cj>();

    let ui_weak = ui.as_weak();
    cj.on_request_demo(move || {
        let ui = ui_weak.unwrap();
        let policy = demo_policy();
        show_policy(&ui.global::<crate::Cj>(), &policy);
        ui.global::<crate::Cj>().set_status("".into());
        let mut app = app.borrow_mut();
        deny(&mut app);
        app.pending = Some(policy);
    });

    let ui_weak = ui.as_weak();
    cj.on_authorize(move || authorize(&ui_weak.unwrap(), &mut app.borrow_mut()));

    cj.on_deny(move || deny(&mut app.borrow_mut()));

    let ui_weak = ui.as_weak();
    cj.on_simulate_round(move || {
        let ui = ui_weak.unwrap();
        let cj = ui.global::<crate::Cj>();
        let mut app = app.borrow_mut();
        let Some(token) = app.token else {
            cj.set_status("No active session.".into());
            return;
        };
        let index = app.next_index;
        let Some(policy) = app.engine.active_session().map(|s| s.policy.clone()) else {
            cj.set_status("No active session.".into());
            return;
        };
        // A real SLIP-0019 proof over the round commitment, signed with the
        // session's cached taproot key — the same call a host round makes.
        let path = [DEMO_PURPOSE, H, H, 1, index];
        match app.engine.ownership_proof(&token, &path, &commitment(&policy.coordinator_id, index)) {
            Ok(proof) => {
                app.next_index += 1;
                let fee_spent =
                    app.engine.active_session().map(|s| s.fee_spent as i32).unwrap_or(0);
                // A round costs budget only when a PSBT is actually signed, so
                // fee-spent stays 0 until a host sends one; the UI counts the
                // proofs it asked for.
                cj.set_rounds(cj.get_rounds() + 1);
                cj.set_fee_spent(fee_spent);
                cj.set_last_result(
                    format!(
                        "Taproot proof for m/86'/0'/0'/1/{index} · {} bytes · fee within budget",
                        proof.len()
                    )
                    .into(),
                );
            }
            Err(e) => {
                cj.set_last_result(format!("round rejected: {}", error_text(e)).into());
            }
        }
    });

    let ui_weak = ui.as_weak();
    cj.on_revoke(move || {
        let ui = ui_weak.unwrap();
        let cj = ui.global::<crate::Cj>();
        let mut app = app.borrow_mut();
        if let Some(token) = app.token.take() {
            let _ = app.engine.revoke(&token); // drops the session: keys zeroize
            log::info!("coinjoin session revoked");
        }
        app.next_index = 0;
        deny(&mut app);
        clear_session(&cj);
    });

    let ui_weak = ui.as_weak();
    cj.on_prepare_export(move || {
        let ui = ui_weak.unwrap();
        let cj = ui.global::<crate::Cj>();
        let mut app = app.borrow_mut();
        cj.set_export_path("".into());
        // Two derivations, one consent (KeyOS remembers the app-seed grant).
        let (fingerprint, xpub84) = match app.engine.xpub(Network::Bitcoin, &[84 | H, H, H]) {
            Ok(v) => v,
            Err(e) => {
                cj.set_status(error_text(e).into());
                return false;
            }
        };
        let xpub86 = match app.engine.xpub(Network::Bitcoin, &[86 | H, H, H]) {
            Ok((_, x)) => x,
            Err(e) => {
                cj.set_status(error_text(e).into());
                return false;
            }
        };
        let json = wallet_rpc_core::wasabi::wallet_json(&fingerprint.to_string(), &xpub84, &xpub86);
        cj.set_wallet_qr(slint_keyos_platform::qrcode::render(
            json.as_bytes(),
            Color::from_rgb_u8(0, 0, 0),
            Color::from_rgb_u8(255, 255, 255),
        ));
        cj.set_wallet_json(json.into());
        cj.set_fingerprint(fingerprint.to_string().into());
        cj.set_status("".into());
        true
    });

    let ui_weak = ui.as_weak();
    cj.on_save_export(move || {
        let ui = ui_weak.unwrap();
        let cj = ui.global::<crate::Cj>();
        let json = cj.get_wallet_json();
        match save_to_airlock(&json) {
            Ok(path) => {
                log::info!("wasabi wallet file saved to airlock: {path}");
                cj.set_export_path(path.into());
                cj.set_status("".into());
            }
            Err(msg) => {
                log::warn!("wasabi export failed: {msg}");
                cj.set_status(msg.into());
            }
        }
    });

    // Host frames arrive on the transport thread and are answered here, on the thread that owns the engine.
    let ui_weak = ui.as_weak();
    crate::transport::on_host_frame(Box::new(move |host_frame| {
        handle_host_frame(&ui_weak.unwrap(), &mut app.borrow_mut(), host_frame)
    }));
    let status = crate::transport::start();
    log::info!("transport: {}", status.line());
    cj.set_serving(status.is_serving());
    cj.set_transport(status.line().into());
}
