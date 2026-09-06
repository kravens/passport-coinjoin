//! Bridge between the Slint `Cj` global and the real `wallet_rpc_core` engine.
//!
//! Nothing here is simulated on the key side: the seed comes from `os/security`
//! (the app-scoped seed, one consent prompt at authorization), the session derives and
//! caches the account keys, and every round produces a real SLIP-0019 ownership
//! proof from those keys. The policy the user approves is the exact struct the
//! engine then enforces.
//!
//! What is still local is the *request*: KeyOS gives third-party apps no USB or
//! QuantumLink channel yet, so the demo request stands in for the host message
//! until Foundation ships the vendor interface. It fills the same pending-policy
//! slot a wire request will, so binding the transport changes only where the
//! policy bytes come from.

use core::cell::RefCell;

use slint_keyos_platform::slint::ComponentHandle;
use wallet_rpc_core::coinjoin::{Policy, TOKEN_LEN};
use wallet_rpc_core::protocol::{Backend, CoreError, Engine};

use wallet_rpc_core::ngwallet::bdk_wallet::bitcoin::{
    secp256k1::{All, Secp256k1},
    Network,
};
use wallet_rpc_core::zeroize::Zeroizing;

security::use_api!();

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
    token: Option<[u8; TOKEN_LEN]>,
    /// Address index the next demo round asks a proof for.
    next_index: u32,
}

/// The request the app stands in for until a host transport exists. Values match
/// what Wasabi's Passport client sends today (see Hwi/Passport/CoinjoinPolicy.cs).
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

pub fn init(ui: &crate::AppWindow) {
    let backend = PrimeBackend {
        security: Security::default(),
        secp: Secp256k1::new(),
        slide_confirmed: false,
    };
    let app: &'static RefCell<App> = Box::leak(Box::new(RefCell::new(App {
        engine: Engine::new(backend),
        pending: None,
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
        app.borrow_mut().pending = Some(policy);
    });

    let ui_weak = ui.as_weak();
    cj.on_authorize(move || {
        let ui = ui_weak.unwrap();
        let cj = ui.global::<crate::Cj>();
        let mut app = app.borrow_mut();
        let Some(policy) = app.pending.take() else {
            cj.set_status("No pending request.".into());
            return false;
        };
        // The gesture that got us here is the user's approval; the engine still
        // asks the backend for it, and the seed prompt follows.
        app.engine.backend.slide_confirmed = true;
        match app.engine.authorize(policy) {
            Ok(token) => {
                app.token = Some(token);
                app.next_index = 0;
                let fingerprint = app
                    .engine
                    .active_session()
                    .map(|s| s.keys.fingerprint.to_string())
                    .unwrap_or_default();
                clear_session(&cj);
                cj.set_session_active(true);
                cj.set_fingerprint(fingerprint.into());
                cj.set_status("".into());
                log::info!("coinjoin session opened");
                true
            }
            Err(e) => {
                app.engine.backend.slide_confirmed = false;
                cj.set_status(error_text(e).into());
                log::warn!("authorize failed: {e:?}");
                false
            }
        }
    });

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
        app.pending = None;
        clear_session(&cj);
    });
}
